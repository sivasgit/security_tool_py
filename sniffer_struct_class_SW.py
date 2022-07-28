import socket
import struct
import sys
import shutil

def mac_format(mac):#Makes MAC Readable
	mac = map('{:02x}'.format, mac) #preceding the width field by a zero ('0') character enables sign-aware zero-padding for numeric types. This is equivalent to a fill character of '0' with an alignment type of '='
	return ':'.join(mac).upper() #Makes everything upper case and joins with ':'

class Ethernet_Frame:
    def __init__(self, buffer=None):
        ethernet_data = struct.unpack('>6s6sH', buffer[:14])
        self.dest_mac = mac_format(ethernet_data[0])
        self.src_mac = mac_format(ethernet_data[1])
        self.protocol = ethernet_data[2]
        self.data = buffer[14:] #Throw back Ethernet data            

def ipv4_format(address):#Makes IPv4 addresses Readable

	return '.'.join(map(str, address)) #Makes everything a string (from ASCII to string) and then puts '.' between them

class IP_Packet:
    def __init__(self, buffer=None):

        ip_header_data = struct.unpack('>BBHHHBBH4s4s', buffer[:20])
        self.version = ip_header_data[0] >> 4
        self.header_len = int(((ip_header_data[0] & 15) * 32) / 8) #or 0xF
        self.tos = ip_header_data[1]
        self.total_len = ip_header_data[2]
        self.id = ip_header_data[3]
        self.flags = ip_header_data[4] >> 13
        self.df = (self.flags & 2) >> 1
        self.mf = self.flags & 1
        self.offset = (ip_header_data[4] & 8191)
        self.ttl = ip_header_data[5]
        self.protocol_num = ip_header_data[6]
        #self.header_data[7] would be checksum
        self.source_ip = ipv4_format(ip_header_data[8])
        self.target_ip = ipv4_format(ip_header_data[9])
        self.data = buffer[20:] #Throw back the IP data        

class TCP_Segment:
    def __init__(self, buffer=None):

        tcp_header_data = struct.unpack('>HHLLH', buffer[:14])

        self.src_port = tcp_header_data[0]
        self.dst_port = tcp_header_data[1]
        self.seq = tcp_header_data[2]
        self.ack = tcp_header_data[3]
        self.offset_flags = tcp_header_data[4]

        self.offset = (self.offset_flags >> 12) * 4 #Not currently shown
        self.flag_urg = (self.offset_flags & 32) >> 5
        self.flag_ack = (self.offset_flags & 16) >> 4
        self.flag_psh = (self.offset_flags & 8) >> 3
        self.flag_rst = (self.offset_flags & 4) >> 2
        self.flag_syn = (self.offset_flags & 2) >> 1
        self.flag_fin = self.offset_flags & 1 
        self.data = buffer[14:] #Throws back TCP data

class UDP_Datagram:
    def __init__(self, buffer=None):

        udp_header_data =  struct.unpack('>HHH', buffer[:6])

        self.src_port = udp_header_data[0]
        self.dst_port = udp_header_data[1]
        self.length = udp_header_data[2]
        self.data = buffer[6:] #Throws back UDP data

class ICMP_Packet:
    def __init__(self, buffer=None):

        icmp_header_data = struct.unpack('>BB', buffer[:2])
        self.type = icmp_header_data[0]
        self.code = icmp_header_data[1]
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
                print('RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_rst))         
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
