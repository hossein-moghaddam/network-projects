import socket
from struct import *
import binascii
import time
# PCAP Global Header Values
PCAP_GLOBAL_HEADER_FMT = '@ I H H i I I I '
# Global Header Values
PCAP_MAGICAL_NUMBER = 2712847316
PCAP_MJ_VERN_NUMBER = 2
PCAP_MI_VERN_NUMBER = 4
PCAP_LOCAL_CORECTIN = 0
PCAP_ACCUR_TIMSTAMP = 0
PCAP_MAX_LENGTH_CAP = 65535
PCAP_DATA_LINK_TYPE = 1


#Ethernet header
class ethernet_header:
    def __init__(self, data):
        try:
            dest_mac, src_mac, proto = unpack('! 6s 6s H', data[:14])
            dest_mac = binascii.hexlify(dest_mac)
            src_mac = binascii.hexlify(src_mac)
            proto = socket.htons(proto)
            print("------------------------------------------------------------------------------------")
            des_mac =(dest_mac.decode('ascii'))
            src_mac =(src_mac.decode('ascii'))
            des_mac = (des_mac[:2]+":"+des_mac[2:4]+":"+des_mac[4:6]+":"+des_mac[6:8]+":"+des_mac[8:10]+":"+des_mac[10:12])
            src_mac = (src_mac[:2]+":"+src_mac[2:4]+":"+src_mac[4:6]+":"+src_mac[6:8]+":"+src_mac[8:10]+":"+src_mac[10:12])
            print("\tEthernet Frame:\n")
            print("\t\t-Destination MAC Addres:", des_mac)
            print("\t\t-Source MAC Addres:", src_mac)
            print("\t\t-Protocole:", proto)
            self.protocol = proto
        except:
            print("Unknow problem happend while tying to unpack ehernet header!")


# ARP header
class arp_header:
    def __init__(self, data):
        try:
            data = unpack("!H2s1s1sH6s4s6s4s", data[:28])
            proto_type = data[4]
            print("\t- Arp Header:\n")
            print("\t\tHardware type:   ", data[0])
            print("\t\tProtocol type:   ", binascii.hexlify(data[1]).decode('ascii'))
            print("\t\tHardware size:", binascii.hexlify(data[2]).decode('ascii') ,"Protocol size:", binascii.hexlify(data[3]).decode('ascii'))
            print("\t\tOpcode:          ", data[4])
            src_mac = binascii.hexlify(data[5]).decode('ascii')
            src_mac = (src_mac[:2]+":"+src_mac[2:4]+":"+src_mac[4:6]+":"+src_mac[6:8]+":"+src_mac[8:10]+":"+src_mac[10:12]).upper()
            print("\t\tSource MAC:      ", src_mac)
            print("\t\tSource IP:       ", socket.inet_ntoa(data[6]))
            des_mac = binascii.hexlify(data[7]).decode('ascii')
            des_mac = (des_mac[:2]+":"+des_mac[2:4]+":"+des_mac[4:6]+":"+des_mac[6:8]+":"+des_mac[8:10]+":"+des_mac[10:12]).upper()
            print("\t\tDest MAC:        ", des_mac)
            print("\t\tDest IP:         ", socket.inet_ntoa(data[8]))
        except:
            print("Unknow problem happend while tying to unpack ARP header!")

# ip header
class ip_header:
    def __init__(self, data):
        try:
            maindata = data
            data = unpack('!BBHHHBBH4s4s', data[:20])
            version = (data[0] >> 4)
            header_length = (data[0] & 0xF) * 4
            top = data[1]  # Type Of service
            total_length = data[2]
            identification = data[3]
            ip_flag = data[4] >> 13
            fragment_offset = data[4] & 0x1FFF
            time_to_live = data[5]
            protocole = data[6]
            header_checksum = hex(data[7])
            source_ip = socket.inet_ntoa(data[8])
            des_ip = socket.inet_ntoa(data[9])
            self.nextheader = maindata[((data[0] & 0xF) * 4):]
            self.nextprotocol = protocole
            print("\tIp V4 Packet:\n")

            print("\t\t- version:", version, "header-length:", header_length, "Type Of Servie:", top, "Total Length:",
                  total_length,
                  "Identification:", identification, "Ip_Flag:", ip_flag, "Fragment Offset:", fragment_offset,
                  "Time To Live:", time_to_live
                  , "Protocole:", protocole, "Header Checksum:", header_checksum, "Source Ip Address:", source_ip,
                  "Destination Ip Address:"
                  , des_ip)
        except:
            print("Unknow problem happend while tying to unpack Ip header!")

        # ------------------------------------------------------------

# ICMP header
class icmp_header:
    def __init__(self,data):
        try:
            type, code, checksum = unpack('!BBH', data[:4])
            self.type = type
            self.code = code
            self.checksum = hex(checksum)
            self.data = repr(data[4:])
            print("-Icmp Packet:")
            print("\t -Type:", self.type, "Code:", self.code, "Checksum:", self.checksum)
            print("\t -data:")
            print("\t", self.data)
        except:
            print("Unknow problem happend while tying to unpack ICMP header!")

# Tcp header
class tcp_header:
    def __init__(self, data):
        try:
            maindata = data
            data = unpack("!HHLLHHHH", data[:20])
            source_port = data[0]
            des_port = data[1]
            seq_number = data[2]
            ack_num = data[3]
            data_offset = ((data[4]&0xF000)>>12)*4
            _reversed = (data[4]&0x0E00)>>9
            ns = (data[4]&256)>>8
            cwr = (data[4] & 128) >> 7
            ece = (data[4] & 64) >> 6
            urg = ((data[4] & 32) >> 5)
            ack = (data[4]&16)>>4
            psh = (data[4]&8)>>3
            rst =  (data[4]&4)>>2
            syn = (data[4]&2)>>1
            fin = data[4]&1
            windows_size = data[5]
            checksum = data[6]
            urg_pointer = data[7]
            self.data_1 = maindata[((data[4]&0xF000)>>12)*4:]
            self.s_port = source_port
            self.d_port = des_port
            print("\t- Tcp Segment:\n")
            print("\t\t- Source Port:", source_port, "Destination Port:", des_port)
            print("\t\t- Sequence number:", seq_number, "Acknowledgment number:", ack_num)
            print("\t\t- Data Offset:", data_offset, "reversed:", _reversed)
            print("\t\t- Flags:")
            print("\t\t\t- NS:", ns, "CWR:", cwr, "ECE:", ece)
            print("\t\t\t- URG:", urg, "ACK:", ack, "PSH:", psh)
            print("\t\t\t- RST:", rst, "SYN:", syn, "FIN:", fin)
            print("\t\t- Windows Size:", windows_size, "Checksum:", checksum, "Urgent Pointer:", urg_pointer)
        except:
            print("Unknow problem happend while tying to unpack TCP header!")


# UDP header
class udp_header:
    def __init__(self, data):
        try:
            maindata = data
            data = unpack("!HHHH", data[:8])
            self.src_port = data[0]
            self.destin_port = data[1]
            length = data[2]
            udp_checksum = hex(data[3])
            self.Data = maindata[8:]
            print("\t- Udp Segment:\n")
            print("\t\t- Source Port:", self.src_port, "Destination Port:", self.destin_port)
            print("\t\t- Length:", length, "Checksum:", udp_checksum)
        except:
            print("Unknow problem happend while tying to unpack UDP header!")


# a function used to decode dns queris and answers
def decode_dns_data(message, offset):
    try:
        labels = []
        list = []
        while True:
            length, = unpack_from("!B", message, offset)
            if (length & 0xC0) == 0xC0:
                pointer, = unpack_from("!H", message, offset)
                offset += 2
                list, offset = decode_dns_data(message, pointer & 0x3FFF)
                return labels+list, offset

            if (length & 0xC0) != 0x00:
                print("unknown label encoding")

            offset += 1

            if length == 0:
                return labels, offset

            labels.append(*unpack_from("!%ds" % length, message, offset))
            offset += length
    except:
        print("Unknow problem happend while tying to unpack DNS DATA!")


# DNS header
class dns_packet:
    def __init__(self, data):
        try:
            maindata = data
            data= unpack('!HHHHHH', data[:12])
            identification = data[0]
            flags = data[1]
            number_queries = data[2]
            number_response = data[3]
            number_authority = data[4]
            number_additional = data[5]
            qr = (flags & 32768)
            opcode = (flags & 30720) >> 11
            aa = (flags & 1024) >> 10
            tc = (flags & 512) >> 9
            rd = (flags & 256) >> 8
            ra = (flags & 128) >> 7
            z = (flags & 64) >> 6
            AD = (flags & 32) >> 5
            CD = (flags & 16) >> 4
            Rcode = (flags & 15)
            print("\t- dns protocol:")
            print("\t\t- Identification:", identification)
            print("\t\t- Flags:")
            print("\t\t\t AA:", aa, "TC:", tc, "RD:", rd)
            print("\t\t\t RA:", ra, "Z:", z, "AD:", AD, "CD:", CD)
            print("\t\t Rcode:", Rcode)
            print("\t\t Number Of Questions: ", number_queries, "Number Of Answer RRs:", number_response)
            print("\t\t Number Of authority RRs: ", number_authority, "Number OF Additional RRs:", number_additional)
            print("\t-Data:")
            # ******decode DNS Queris*********
            name, offset = decode_dns_data(maindata, 12)
            query = b''
            for q in name:
                query = query + q + b'.'
            query = query.decode('ascii')
            qtype, qclass = unpack_from("! 2H" ,maindata, offset)
            print("\t\tQueris:")
            print("\t\t\t Name:",query[0:-1], "Type:", qtype, "Class:", qclass)
            offset = offset + 4
            # ******decode DNS Answers*********

            for i in range(number_response):
                if i == 0:
                    print("\t\tAnswers:")
                name, nu = decode_dns_data(maindata, offset)
                answer = b''
                for q in name:
                    answer = answer + q + b'.'
                answer = answer.decode("ascii")
                offset = offset + 2
                ans_type, ans_class,ttl,data_length = unpack_from("!HHIH",maindata,offset)
                offset = offset + 10
                if data_length != 4:
                    address,nu = decode_dns_data(maindata, offset)
                else:
                    address = unpack_from("!4s",maindata,offset)
                offset = offset + data_length
                addr = b''
                for q in address:
                    addr = addr + q + b'.'
                if data_length == 4:
                    addr = socket.inet_ntoa(addr[0:-1])
                    print("\t\t\t Name:", answer[0:-1], "Type:", ans_type, "Class:", ans_class)
                    print("\t\t\t TTL:", ttl, "Data Length:", data_length, "Address:", addr)
                else:
                    addr = addr.decode('ascii')
                    if ans_type == 5:
                        print("\t\t\t Name:",answer[0:-1], "Type:", ans_type, "Class:", ans_class)
                        print("\t\t\t TTL:", ttl, "Data Length:", data_length, "CNAME:", addr[0:-1])
                    elif type == 12:
                        print("\t\t\t Name:",answer[0:-1], "Type:", ans_type, "Class:", ans_class)
                        print("\t\t\t TTL:", ttl, "Data Length:", data_length, "Domain Name:", addr[0:-1])
                print()
        except:
            print("Unknow problem happend while tying to unpack DNS header!")


class http_header:
    def __init__(self, data):
        try:
            print("\t\t- HTTP Data:")
            header = data.split(b'\r\n')
            request = header[0]
            request = request.decode("ascii")
            print("\t\t\t HTTP request:", request, "\n")
            var = 0
            print("\t\t\t HTTP Header:")
            for d in header[1:]:
                var = var +1
                if d == b'':
                    if len(header[var+1:]) > 0:
                        print("\n\t\t\t HTTP Body:")
                        print("\t\t\t", header[var+1:])
                        break
                else:
                    print("\t\t\t",d.decode("ascii"))
        except:
            print("Unknow problem happend while tying to unpack ARP header!")


# save in .pcap file
class Pcap:

    def __init__(self, filename, link_type=PCAP_DATA_LINK_TYPE):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write(pack('@ I H H i I I I ', PCAP_MAGICAL_NUMBER, PCAP_MJ_VERN_NUMBER, PCAP_MI_VERN_NUMBER, PCAP_LOCAL_CORECTIN, PCAP_ACCUR_TIMSTAMP, PCAP_MAX_LENGTH_CAP, link_type))

    def writelist(self, data):
        for i in data:
            self.write(i)
            return

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcap_file.write(pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()


# *********************************************************MAIN*********************************************************

# ***Start*****
# creating a raw socket
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
pcap = Pcap('packet.pcap') # Open to write as Pcap file
while 1:

    # receiving a packet
    raw_data, addr = conn.recvfrom(65535)
    pcap.write(raw_data)

    # print ethernet header information
    ethernet = ethernet_header(raw_data[:14])

    # print ARP header information
    if ethernet.protocol == 1544:
        arp_header(raw_data[14:])
        continue
    # ---------------------------------------------------------

    # print Ip header
    Ip_Header = ip_header(raw_data[14:])
    protocole = Ip_Header.nextprotocol
    next_header = Ip_Header.nextheader

    # TCP
    if protocole == 6:
        Tcp_Header = tcp_header(next_header)
        # print Tcp Header
        data = Tcp_Header.data_1
        source_port = Tcp_Header.s_port
        des_port = Tcp_Header.d_port
        if source_port == 53 or des_port == 53:# ******** DNS
            dns_packet(data)
        if len(data) > 0:
            if source_port == 80 or des_port == 80:# *********HTTP
                http_header(data)
            else:
                print("\t\t- Tcp Data:")
                print(data)
        print("\n")
        print("------------------------------------------------------------------------------------")
        # ---------------------------------------------------------------------------

        # Icmp packet
    elif protocole == 1:
        Icmp_Header = icmp_header(next_header)
        print("\n")
        print("------------------------------------------------------------------------------------")
        # ---------------------------------------------------------------------------

        # UDP packet
    elif protocole == 17:
        Udp_Header = udp_header(next_header)
        src_port = Udp_Header.src_port
        destin_port = Udp_Header.destin_port
        _data = Udp_Header.Data
        if src_port == 53 or destin_port == 53:
            dns_packet(_data)
        elif len(_data) > 0:
            print("\t\t- Udp Data:")
            print(_data)
        print("\n")
        print("------------------------------------------------------------------------------------")
        # Other protocols
    else:
        print("\t\t Other Protocols:")
        print(next_header)

