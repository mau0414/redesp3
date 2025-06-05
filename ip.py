from iputils import read_ipv4_header
import ipaddress
import struct
from socket import IPPROTO_ICMP, IPPROTO_TCP

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela_encaminhamento = []

    def __raw_recv(self, datagrama):
        """
        Processa o datagrama recebido da camada de enlace.
        Se o datagrama é destinado a este host, processa-o como um host.
        Caso contrário, encaminha-o como um roteador.
        """
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        
        if dst_addr == self.meu_endereco:
            # Atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # Atua como roteador
            ttl -= 1  # Decrementa o TTL
            if ttl <= 0:
                # Gera e envia mensagem ICMP Time Exceeded
                icmp_message = self.time_exceeded(datagrama)
                destine_addr = src_addr
                datagrama_icmp = self._enviar_icmp(icmp_message, destine_addr)
                next_hop = self._next_hop(destine_addr)
                self.enlace.enviar(datagrama_icmp, next_hop)
                return
            
            else:
                # Atualiza o cabeçalho IPv4 com o novo TTL e recalcula o checksum
                ver_ihl = (4 << 4) | 5
                total_length = len(datagrama)
                flags_frag = (flags << 13) | frag_offset
                src_addr_packed = ipaddress.IPv4Address(src_addr).packed
                dst_addr_packed = ipaddress.IPv4Address(dst_addr).packed

                header_without_checksum = struct.pack('!BBHHHBBH4s4s', ver_ihl, (dscp << 2) | ecn, total_length, 
                                                  identification, flags_frag, ttl, proto, 0, 
                                                  src_addr_packed, dst_addr_packed)
                checksum = self.calc_checksum(header_without_checksum)

                header = struct.pack('!BBHHHBBH4s4s', ver_ihl, (dscp << 2) | ecn, total_length, 
                                 identification, flags_frag, ttl, proto, checksum, 
                                 src_addr_packed, dst_addr_packed)

                datagrama = header + payload
                next_hop = self._next_hop(dst_addr)
                self.enlace.enviar(datagrama, next_hop)

    def time_exceeded(self, datagrama):
        #"Time exceeded messages are used by the traceroute utility to identify gateways on the path between two hosts."
        #Header time exceeded message
        typ = 11  
        code = 0  
        checksum = 0  
        unused = 0  
        
        #conteudo icmp = IP header and first 8 bytes of original datagram's data    
        ip_header = datagrama[:20]  
        payload = datagrama[20:28] 
        icmp_payload = ip_header + payload

        #Definindo icmp header
        icmp_header = struct.pack('!BBHI', typ, code, checksum, unused)
        checksum = self.calc_checksum(icmp_header + icmp_payload)
        icmp_header = struct.pack('!BBHI', typ, code, checksum, unused)

        # Retorna mensagem icmp
        return icmp_header + icmp_payload

    def _enviar_icmp(self, icmp_message, dest_addr):

       # Envia mensagem imcp
       # Padão de envio de mensagem (muda apenas o protocolo)
        ver_ihl = (4 << 4) | 5
        dscp = 0
        ecn = 0
        total_length = 20 + len(icmp_message)
        identification = 0
        flags = 0
        frag_offset = 0
        ttl = 64
        proto = IPPROTO_ICMP
        checksum = 0
        src_addr_packed = ipaddress.IPv4Address(self.meu_endereco).packed
        dst_addr_packed = ipaddress.IPv4Address(dest_addr).packed

        header = struct.pack('!BBHHHBBH4s4s', ver_ihl, (dscp << 2) | ecn, total_length, 
                                              identification, (flags << 13) | frag_offset, ttl, proto, 
                                              checksum, src_addr_packed, dst_addr_packed)
        checksum = self.calc_checksum(header)
        header = struct.pack('!BBHHHBBH4s4s', ver_ihl, (dscp << 2) | ecn, total_length, 
                             identification, (flags << 13) | frag_offset, ttl, proto, 
                             checksum, src_addr_packed, dst_addr_packed)

        icmp_datagrama = header + icmp_message
        return icmp_datagrama
        

    def _next_hop(self, dest_addr):

        dest_IP = ipaddress.IPv4Address(dest_addr)
        matchEntry = None
        for cidr,next_hop in self.tabela_encaminhamento:
            network = ipaddress.IPv4Network(cidr)
            if dest_IP in network: #Encontrou possivel match
                #Escolhe o de maior prefixo 
                if(matchEntry is None or (network.prefixlen> ipaddress.IPv4Network(matchEntry[0]).prefixlen)):
                    matchEntry = (cidr,next_hop)

        if matchEntry:
            return matchEntry[1]
        else:
            return None
       

    def definir_endereco_host(self, meu_endereco):
        """
        Define o endereço IP deste host. Atua como host ao receber datagramas
        destinados a este endereço.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato [(cidr0, next_hop0), (cidr1, next_hop1), ...].
        """
        self.tabela_encaminhamento = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede.
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia um segmento TCP para o endereço de destino, encapsulando-o em um datagrama IPv4.
        """
        next_hop = self._next_hop(dest_addr)
        if not next_hop:
            return

        # parâmetros header padrão IPV4
        ver_ihl = (4 << 4) | 5
        dscp = 0
        ecn = 0
        total_length = 20 + len(segmento)
        identification = 0
        flags = 0
        frag_offset = 0
        ttl = 64
        proto = IPPROTO_TCP
        checksum = 0 #Definição inicial
        src_addr_packed = ipaddress.IPv4Address(self.meu_endereco).packed
        dst_addr_packed = ipaddress.IPv4Address(dest_addr).packed

        header = struct.pack('!BBHHHBBH4s4s', ver_ihl, (dscp << 2) | ecn, total_length, 
                                              identification, (flags << 13) | frag_offset, ttl, proto, 
                                              checksum, src_addr_packed, dst_addr_packed)
        #Cálculo checksum
        checksum = self.calc_checksum(header)
    	#Header com checksum atualizado
        header = struct.pack('!BBHHHBBH4s4s', ver_ihl, (dscp << 2) | ecn, total_length, identification, 
                             (flags << 13) | frag_offset, ttl, proto, checksum, src_addr_packed, dst_addr_packed)

        # montagem do datagrama, formado por header e segmento
        datagrama = header + segmento
        self.enlace.enviar(datagrama, next_hop)

    def calc_checksum(self, header):
    
    # Calcula o checksum para o cabeçalho IPv4.
        
        if len(header) % 2 == 1:
            header += b'\0'
        s = sum(struct.unpack("!%dH" % (len(header) // 2), header))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff
