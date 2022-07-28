from ctypes import BigEndianStructure
import socket
from ctypes import *
import sys
import shutil

def mac_format(mac):#Makes MAC Readable
    
    mac = map('{:02x}'.format, mac) #preceding the width field by a zero ('0') character enables sign-aware zero-padding for numeric types. This is equivalent to a fill character of '0' with an alignment type of '='
	
    return ':'.join(mac).upper() #Makes everything upper case and joins with ':'

class Ethernet_Frame(BigEndianStructure):

    _fields_ = [
        ("dest",        c_ubyte * 6),
        ("src",         c_ubyte * 6),
        ("protocol",    c_ushort)
    ]

    def __new__(self, buffer=None):
            return self.from_buffer_copy(buffer)    
        
    def __init__(self, buffer=None):

        self.src_mac = mac_format(self.src) #Readable MAC Addresses
        self.dest_mac = mac_format(self.dest) #Readable MAC Addresses
        self.data = buffer[14:] #Throw back Ethernet data 


def ipv4_format(address):#Makes IPv4 addresses Readable

	return '.'.join(map(str, address)) #Makes everything a string (from ASCII to string) and then puts '.' between them

class IP_Packet(BigEndianStructure):

    _fields_ = [
        ("version",         c_ubyte, 4),
        ("len",             c_ubyte, 4),
        ("tos",             c_ubyte),
        ("total_len",       c_ushort),
        ("id",              c_ushort),
        ("rsv",             c_ubyte, 1),
        ("df",              c_ubyte, 1),
        ("mf",              c_ubyte, 1),
        ("offset",          c_ushort, 13),
        ("ttl",             c_ubyte),
        ("protocol_num",    c_ubyte),
        ("sum",             c_ushort),
        ("src",             c_ubyte * 4),
        ("dst",             c_ubyte * 4)
    ]

    def __new__(self, buffer=None):
        return self.from_buffer_copy(buffer)    
        
    def __init__(self, buffer=None):
        
        self.header_len = int((self.len * 32) / 8) #Convert to bytes
        
        # human readable IP addresses
        self.source_ip = ipv4_format(self.src)
        self.target_ip = ipv4_format(self.dst)

        self.data = buffer[20:]

class TCP_Segment(BigEndianStructure):

    _fields_ = [
        ("src_port",        c_ushort),
        ("dst_port",        c_ushort),
        ("seqarray",        c_ubyte * 4),
        ("ackarray",        c_ubyte * 4),
        ("off",             c_ushort, 10),
        ("flag_urg",        c_ubyte, 1),
        ("flag_ack",        c_ubyte, 1),
        ("flag_psh",        c_ubyte, 1),
        ("flag_rst",        c_ubyte, 1),
        ("flag_syn",        c_ubyte, 1),
        ("flag_fin",        c_ubyte, 1),                   
    ]

    def __new__(self, buffer=None):
        return self.from_buffer_copy(buffer)    
        
    def __init__(self, buffer=None):

        
        joined_seq = ''.join('{:02x}'.format(x) for x in self.seqarray) #Push the byte array together
        joined_ack = ''.join('{:02x}'.format(x) for x in self.ackarray) #Push the byte array together
        self.seq = int(joined_seq, 16) #Convert Hex to integer
        self.ack = int(joined_ack, 16) #Convert Hex to integer
        self.offset = (self.off >> 12) * 4 #Not currently shown
        self.data = buffer[14:] #Throws back TCP data

class UDP_Datagram(BigEndianStructure):

    _fields_ = [
        ("src_port",        c_ushort),
        ("dst_port",        c_ushort),
        ("length",          c_ushort)
    ]

    def __new__(self, buffer=None):
        return self.from_buffer_copy(buffer)    
        
    def __init__(self, buffer=None):

        self.data = buffer[6:]#Throws back UDP data

class ICMP_Packet(BigEndianStructure):

    _fields_ = [
        ("type",        c_ubyte),
        ("code",        c_ubyte)
    ]

    def __new__(self, buffer=None):
        return self.from_buffer_copy(buffer)    
        
    def __init__(self, buffer=None):

        self.data = buffer[2:] #Throws back ICMP data

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) #Open Socket at Frame Level

    while True: #Main Loop

        raw_data = s.recv(65535)

        #-----Ethernet
        
        eth = Ethernet_Frame(raw_data) #Parse out the Ethernet Header

        print('Ethernet Frame:')

        eth_protocol_map = {2048: "IP", 2054: "ARP"}
        try:
            eth_protocol = eth_protocol_map[eth.protocol]
        except Exception as e:
            eth_protocol = str(eth.protocol)

        print('Source: {}, Destination: {}, Protocol: {}'.format(eth.src_mac, eth.dest_mac, eth_protocol))

        #---- IP

        

        if (eth_protocol == 'IP'):

            ip = IP_Packet(eth.data) #Parse out the IP Header

            print("\nIP Header:")

            ip_protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

            try:
                ip_protocol = ip_protocol_map[ip.protocol_num]
            except Exception as e:
                ip_protocol = str(ip.protocol_num)
#return ip_version, ip_header_len, ip_tos, ip_total_len, ip_id, ip_flags, ip_df, ip_mf, ip_offset, ip_ttl, ip_protocol_num, ipv4_format(ip_source_ip), ipv4_format(ip_target_ip), data

            print('Source: {}, Destination: {}, Protocol: {}'.format(ip.source_ip, ip.target_ip, ip_protocol))
            print('Version: {}, Header Length: {}, TOS: {}'.format(ip.version, ip.header_len, ip.tos))
            print('Total Length: {}, ID: {}, TTL: {}'.format(ip.total_len, ip.id, ip.ttl))
            print('Flags:')
            print('DF: {}, MF: {}'.format(ip.df, ip.mf))

            #---- TCP

            if (ip_protocol == 'TCP'):
                tcp = TCP_Segment(ip.data)

                print('\nTCP Segment:')

                print('Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dst_port))
                print('Sequence: {}, Acknowledgment: {}'.format(tcp.seq, tcp.ack))
                print('Flags:')
                print('URG: {}, ACK: {}, PSH:{}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print('RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))         
                print("")
                print(tcp.data)

            #---- UDP

            elif (ip_protocol == 'UDP'):
                udp = UDP_Datagram (ip.data)
                print('\nUDP Datagram:')

                print('Source Port: {}, Destination Port: {}'.format(udp.src_port, udp.dst_port))
                print('Length: {}'.format(udp.length))
                print("")
                print(udp.data)

            #---- ICMP

            elif (ip_protocol == 'ICMP'):
                icmp = ICMP_Packet (ip.data)

                icmp_type_map = {0: "Echo Reply", 3: "Destination Unreachable", 8: "Echo Request"}

                try:
                    icmp_type = icmp_type_map[icmp.type]
                except Exception as e:
                    icmp_type = str(icmp.type)

                if (icmp.type == 3): #Destination Unreachable
                    icmp_code_map = {0: "Destination Network Unreachable", 1: "Destination Host Unreachable", 2: "Destination Protocol Unreachable", 3: "Destination Port Unreachable"} ##And Many Others

                    try:
                        icmp_code = icmp_code_map[icmp.code]
                    except Exception as e:
                        icmp_code = str(icmp.code)
                else:
                    icmp_code = str(icmp.code)


                print('\nICMP Packet:')

                print('Type: {}, Code: {}'.format(icmp_type, icmp_code))
                print("")
                print(icmp.data)

            else:
                print(ip.data) #NOT TCP or UDP OR ICMP
        else:
            print (eth.data) #NOT IP

        #Print line between frames
        ts = shutil.get_terminal_size()
        print("")
        print ('-' * ts[0])
        print("")

if __name__ == '__main__':
    
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting...")
        sys.exit(0)