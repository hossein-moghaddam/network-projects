import sys
import socket
import datetime
from struct import *
import binascii
closed = 0
open = []
filter = 0
filterlist = []


# Get Host Inet
def get_host_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


#create a TCP packet
class generate_Packet:
    def __init__(self, src_ip, dest_ip, dest_port,ack,syn,fin):
        ############
        # IP segment
        self.version = 0x4
        self.ihl = 0x5
        self.type_of_service = 0x0
        self.total_length = 0
        self.identification = 0xabcd
        self.flags = 0x0
        self.fragment_offset = 0x0
        self.ttl = 255
        self.protocol = 0x6
        self.header_checksum = 0x0
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_addr = socket.inet_aton(src_ip)
        self.dest_addr = socket.inet_aton(dest_ip)
        self.v_ihl = (self.version << 4) + self.ihl
        self.flag_fragoff = (self.flags << 13) + self.fragment_offset

        #############
        # TCP segment
        self.src_port = 0x3039  # source port 12345
        self.dest_port = dest_port
        self.seq_no = 0x0
        self.ack_no = 0x0
        self.data_offset = 0x5
        self.reserved = 0x0
        self.ns, self.cwr, self.ece, self.urg, self.ack, self.psh, self.rst, self.syn, self.fin = 0x0, 0x0, 0x0, 0x0, ack, 0x0, 0x0, syn, fin
        self.window_size = socket.htons(5840)
        self.checksum = 0x0
        self.urg_pointer = 0x0
        self.data_offset_res_flags = (self.data_offset << 12) + (self.reserved << 9) + (self.ns << 8) + (
                    self.cwr << 7) + (self.ece << 6) + (self.urg << 5) + (self.ack << 4) + (self.psh << 3) + (
                                              self.rst << 2) + (self.syn << 1) + self.fin
        ########
        # packet
        self.tcp_header = b""
        self.ip_header = b""
        self.packet = b""

    def calc_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i + 1]
            s = s + w
        # s = 0x119cc
        s = (s >> 16) + (s & 0xffff)
        # s = 0x19cd
        s = ~s & 0xffff
        # s = 0xe632
        return s

    def generate_tmp_ip_header(self):
        tmp_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                             self.identification, self.flag_fragoff,
                             self.ttl, self.protocol, self.header_checksum,
                             self.src_addr,
                             self.dest_addr)
        return tmp_ip_header

    def generate_tmp_tcp_header(self):
        tmp_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                              self.seq_no,
                              self.ack_no,
                              self.data_offset_res_flags, self.window_size,
                              self.checksum, self.urg_pointer)
        return tmp_tcp_header

    def generate_packet(self):
        # IP header + checksum
        final_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                               self.identification, self.flag_fragoff,
                               self.ttl, self.protocol, self.calc_checksum(self.generate_tmp_ip_header()),
                               self.src_addr,
                               self.dest_addr)
        # TCP header + checksum
        tmp_tcp_header = self.generate_tmp_tcp_header()
        pseudo_header = pack("!4s4sBBH", self.src_addr, self.dest_addr, self.checksum, self.protocol,
                             len(tmp_tcp_header))
        psh = pseudo_header + tmp_tcp_header
        final_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                                self.seq_no,
                                self.ack_no,
                                self.data_offset_res_flags, self.window_size,
                                self.calc_checksum(psh), self.urg_pointer)

        self.ip_header = final_ip_header
        self.tcp_header = final_tcp_header
        self.packet = final_ip_header + final_tcp_header


# Get input  format--> -t IP or FQDN -p port ranges -d delay -s MODE(CS,AS,SS,WS,FS)
def _input_():
    a = sys.argv[1:9]
    if '-p' not in a or '-t' not in a or '-d' not in a or '-s' not in a:
        print("Wrong input format!Please check Your input format")
    else:
        domain_name = a[a.index("-t")+1]
        ports = a[a.index("-p")+1]
        mode = a[a.index("-s")+1]
        timeout = a[a.index("-d")+1]
        try:
            address_ip = socket.gethostbyname_ex(domain_name)[2]
        except:
            print("Wrong FQDN!")
            exit(0)

        if mode not in ['CS', 'SS', 'AS', 'FS', 'WS']:
            print("Wrong Scan Mode!")
            exit(0)

        if '-' not in ports:
            print("Wrong Port Format!")
            exit(0)
        ports = ports.split('-')
        for i in range(2):
            ports[i] = int(ports[i])
        if ports[0] > ports[1]:
            print("Wrong Port Format!")
            exit(0)
        if ports[1] > 65535:
            print("Wrong Port Format!")
        if ports[0] == 0:
            ports[0] = 1
        return [address_ip,ports,mode,timeout]


# Connect Scan(CS)
def connect_scan(ipaddress, ports,delay):
    global closed, open
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(delay)
        s.connect((ipaddress,ports))
        open.append(ports)
        s.close()
    except:
        closed = closed + 1
        s.close()


# Syn Scan(SS)
def Syn_scan (mysocket,ipaddress,port):
    mainpacket = generate_Packet(get_host_ip_address(),ipaddress,port,0,1,0)
    mainpacket.generate_packet()
    mysocket.sendto(mainpacket.packet, (ipaddress, 0))
    global open, closed, filter
    while 1:
        try:
            data = mysocket.recv(1024)
            maindata = data
            src, = unpack("!H",maindata[20:22])
            des, = unpack("!H",maindata[22:24])
            if des != 12345 or src != port:
                continue
            data, = unpack("!H", data[32:34])
            ack = (data & 16) >> 4
            syn = (data & 2) >> 1
            rst = (data & 4) >> 2
            if ack == 1 and syn == 1:
                open.append(port)
            elif rst == 1:
                closed = closed + 1
        except:
            filter = filter + 1
        break


# Ack Scan
def Ack_scan(mysocket,ipaddress,port):
    mainpacket = generate_Packet(get_host_ip_address(), ipaddress, port, 1, 0, 0)
    mainpacket.generate_packet()
    mysocket.sendto(mainpacket.packet, (ipaddress, 0))
    global open, closed, filter
    while 1:
        try:
            data = mysocket.recv(1024)
            maindata = data
            src, = unpack("!H", maindata[20:22])
            des, = unpack("!H", maindata[22:24])
            if src != port or des != 12345:
                continue
            data, = unpack("!H", data[32:34])
            rst = (data & 4) >> 2
            if rst == 1:
                open.append(port)
        except:
            filter = filter + 1
        break


# Fin Scan
def Fin_scan(mysocket,ipaddress,port):
    mainpacket = generate_Packet(get_host_ip_address(), ipaddress, port, 0, 0, 1)
    mainpacket.generate_packet()
    mysocket.sendto(mainpacket.packet, (ipaddress, 0))
    global open, closed
    while 1:
        try:
            data = mysocket.recv(1024)
            maindata = data
            src, = unpack("!H", maindata[20:22])
            des, = unpack("!H", maindata[22:24])
            if src != port or des != 12345:
                continue
            data, = unpack("!H", data[32:34])
            rst = (data & 4) >> 2
            if rst == 1:
                closed = closed + 1
        except:
            open.append(port)
        break


# Windows Scan
def Windows_scan(mysocket,ipaddress,port):
    mainpacket = generate_Packet(get_host_ip_address(), ipaddress, port, 1, 0, 0)
    mainpacket.generate_packet()
    mysocket.sendto(mainpacket.packet, (ipaddress, 0))
    global open, closed,filter
    while 1:
        try:
            data = mysocket.recv(1024)
            maindata = data
            src, = unpack("!H", maindata[20:22])
            des, = unpack("!H", maindata[22:24])
            if src != port or des != 12345:
                continue
            data, = unpack("!H", data[32:34])
            windowssize, = unpack("!H", maindata[34:36])
            rst = (data & 4) >> 2
            if rst == 1 and windowssize > 0:
                open.append(port)

            elif rst == 1 and windowssize == 0:
                closed = closed + 1
        except:
            filterlist.append(port)
        break

# ***********Main*******************


# Get Input
list = _input_()

# ***************************Connect Scan**************************
if list[2] == 'CS':
    print("Starting Scan at",datetime.datetime.now())
    for port in range(int(list[1][0]), int(list[1][1]) + 1):
        connect_scan(list[0][0], port,float(list[3]))
    print("Scan Report for", list[0][0])
    print("Not Shown:", closed, "Closed Ports")
    if len(open) > 0:
        print("PORT      STATE      SERVICE ")
        for i in range(len(open)):
            print(open[i], "       open      ", socket.getservbyport(open[i]))

# ***************************syn Scan******************************
elif list[2] == 'SS':
    mysocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    mysocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    mysocket.settimeout(float(list[3]))
    print("Starting Scan at", datetime.datetime.now())
    for port in range(int(list[1][0]), int(list[1][1]) + 1):
        Syn_scan(mysocket,list[0][0], port)
    print("Scan Report for", list[0][0])
    if closed != 0:
        print("Not Shown:", closed, "Closed Ports")
    if filter != 0:
        print("Not Shown:", filter, "filterd Ports")
    print("PORT      STATE      SERVICE ")
    for i in range(len(open)):
        print(open[i], "       open      ", socket.getservbyport(open[i]))

# ***************************Ack Scan******************************

elif list[2] == 'AS':
    mysocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    mysocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    mysocket.settimeout(float(list[3]))
    print("Starting Scan at", datetime.datetime.now())
    for port in range(int(list[1][0]), int(list[1][1]) + 1):
        Ack_scan(mysocket,list[0][0], port)
    print("Scan Report for", list[0][0])
    if list[1][1] == len(open):
        print("All",len(open),"scanned ports on", list[0][0], "are unfiltered")
        exit(0)
    if list[1][1] == filter:
        print("All",filter,"scanned ports on", list[0][0], "are filtered")
        exit(0)
    print("All",list[1][1],"scanned ports on", list[0][0], "are filtered",'(',filter,')','or unfiltered','(',len(open),')')

# ***************************Fin Scan******************************

elif list[2] == 'FS':
    mysocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    mysocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    mysocket.settimeout(float(list[3]))
    print("Starting Scan at", datetime.datetime.now())
    for port in range(int(list[1][0]), int(list[1][1]) + 1):
        Fin_scan(mysocket,list[0][0], port)
    print("Scan Report for", list[0][0])
    if len(open) == list[1][1]:
        print('All',list[1][1],'scanned ports on',list[0][0],'are open|filtered')

# ***************************Windows Scan******************************

elif list[2] == 'WS':
    mysocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    mysocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    mysocket.settimeout(float(list[3]))
    print("Starting Scan at", datetime.datetime.now())
    for port in range(int(list[1][0]), int(list[1][1]) + 1):
        Windows_scan(mysocket,list[0][0], port)
    print("Scan Report for", list[0][0])
    if len(open) > 0:
        print("PORT      STATE      SERVICE ")
    for i in range(len(open)):
        try:
            print(open[i], "       open      ", socket.getservbyport(open[i]))
        except:
            continue
    else:
        print('All',list[1][1],'scanned ports on',list[0][0],'are filtered')











































