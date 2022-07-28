import socket
import struct
import sys
import shutil

def mac_format(mac):#Makes MAC Readable
	mac = map('{:02x}'.format, mac) #preceding the width field by a zero ('0') character enables sign-aware zero-padding for numeric types. This is equivalent to a fill character of '0' with an alignment type of '='
	return ':'.join(mac).upper() #Makes everything upper case and joins with ':'

def ethernet_frame(raw_data): #Handles Ethernet Header
    ethernet_data = struct.unpack('>6s6sH', raw_data[:14])
    eth_dest_mac = mac_format(ethernet_data[0])
    eth_src_mac = mac_format(ethernet_data[1])
    eth_protocol = ethernet_data[2]
    data = raw_data[14:] #Throw back Ethernet data
    
    return eth_dest_mac, eth_src_mac, eth_protocol, data 

def ipv4_format(address):#Makes IPv4 addresses Readable

	return '.'.join(map(str, address)) #Makes everything a string (from ASCII to string) and then puts '.' between them

def ipv4_packet(ip_data): #Handles IP Header

    ip_header_data = struct.unpack('>BBHHHBBH4s4s', ip_data[:20])
    ip_version = ip_header_data[0] >> 4
    ip_header_len = int(((ip_header_data[0] & 15) * 32) / 8) #or 0xF
    ip_tos = ip_header_data[1]
    ip_total_len = ip_header_data[2]
    ip_id = ip_header_data[3]
    ip_flags = ip_header_data[4] >> 13
    ip_df = (ip_flags & 2) >> 1
    ip_mf = ip_flags & 1
    ip_offset = ip_header_data[4] & 8191
    ip_ttl = ip_header_data[5]
    ip_protocol_num = ip_header_data[6]
    #ip_header_data[7] would be checksum
    ip_source_ip = ip_header_data[8]
    ip_target_ip = ip_header_data[9]
    data = ip_data[20:] #Throw back the IP data

    return ip_version, ip_header_len, ip_tos, ip_total_len, ip_id, ip_flags, ip_df, ip_mf, ip_offset, ip_ttl, ip_protocol_num, ipv4_format(ip_source_ip), ipv4_format(ip_target_ip), data


def tcp_segment (tcp_data): #Handles TCP Header

    tcp_header_data = struct.unpack('>HHLLH', tcp_data[:14])

    tcp_src_port = tcp_header_data[0]
    tcp_dst_port = tcp_header_data[1]
    tcp_seq = tcp_header_data[2]
    tcp_ack = tcp_header_data[3]
    tcp_offset_flags = tcp_header_data[4]

    tcp_offset = (tcp_offset_flags >> 12) * 4 #Not currently shown
    tcp_flag_urg = (tcp_offset_flags & 32) >> 5
    tcp_flag_ack = (tcp_offset_flags & 16) >> 4
    tcp_flag_psh = (tcp_offset_flags & 8) >> 3
    tcp_flag_rst = (tcp_offset_flags & 4) >> 2
    tcp_flag_syn = (tcp_offset_flags & 2) >> 1
    tcp_flag_fin = tcp_offset_flags & 1 
    data = tcp_data[14:] #Throws back TCP data


    return tcp_src_port, tcp_dst_port, tcp_seq, tcp_ack, tcp_offset, tcp_flag_urg, tcp_flag_ack, tcp_flag_psh, tcp_flag_rst, tcp_flag_syn, tcp_flag_fin, data

def udp_datagram (udp_data): #Handles UDP Header

    udp_header_data =  struct.unpack('>HHH', udp_data[:6])

    udp_src_port = udp_header_data[0]
    udp_dst_port = udp_header_data[1]
    udp_length = udp_header_data[2]
    data = udp_data[6:] #Throws back UDP data

    return udp_src_port, udp_dst_port, udp_length, data

def icmp_packet (icmp_data): #Handles ICMP Header

    icmp_header_data = struct.unpack('>BB', icmp_data[:2])
    icmp_type = icmp_header_data[0]
    icmp_code = icmp_header_data[1]
    data = icmp_data[2:] #Throws back ICMP data

    return icmp_type, icmp_code, data

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) #Open Socket at Frame Level

    while True: #Main Loop
        
        raw_data = s.recv(65535)

        #-----Ethernet

        eth = ethernet_frame(raw_data) #Parse out the Ethernet Header

        print('Ethernet Frame:')

        eth_protocol_map = {2048: "IP", 2054: "ARP"}
        try:
            eth_protocol = eth_protocol_map[eth[2]]
        except Exception as e:
            eth_protocol = str(eth[2])

        print('Source: {}, Destination: {}, Protocol: {}'.format(eth[1], eth[0], eth_protocol))

        #-----IP

        if (eth_protocol == 'IP'):

            ip = ipv4_packet (eth[3]) #Parse out the IP Header

            print("\nIP Header:")

            ip_protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

            try:
                ip_protocol = ip_protocol_map[ip[10]]
            except Exception as e:
                ip_protocol = str(ip[10])
#return ip_version, ip_header_len, ip_tos, ip_total_len, ip_id, ip_flags, ip_df, ip_mf, ip_offset, ip_ttl, ip_protocol_num, ipv4_format(ip_source_ip), ipv4_format(ip_target_ip), data

            print('Source: {}, Destination: {}, Protocol: {}'.format(ip[11], ip[12], ip_protocol))
            print('Version: {}, Header Length: {}, TOS: {}'.format(ip[0], ip[1], ip[2]))
            print('Total Length: {}, ID: {}, TTL: {}'.format(ip[3], ip[4], ip[9]))
            print('Flags:')
            print('DF: {}, MF: {}'.format(ip[6], ip[7]))

            #-----TCP

            if (ip_protocol == 'TCP'):
                tcp = tcp_segment (ip[13])

                print('\nTCP Segment:')

                print('Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
                print('Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))
                print('Flags:')
                print('URG: {}, ACK: {}, PSH:{}'.format(tcp[5], tcp[6], tcp[7]))
                print('RST: {}, SYN: {}, FIN:{}'.format(tcp[8], tcp[9], tcp[10]))         
                print("")
                print(tcp[11])

            #-----UDP

            elif (ip_protocol == 'UDP'):
                udp = udp_datagram (ip[13])
                print('\nUDP Datagram:')

                print('Source Port: {}, Destination Port: {}'.format(udp[0], udp[1]))
                print('Length: {}'.format(udp[2]))
                print("")
                print(udp[3])

            #-----ICMP

            elif (ip_protocol == 'ICMP'):
                icmp = icmp_packet (ip[13])

                icmp_type_map = {0: "Echo Reply", 3: "Destination Unreachable", 8: "Echo Request"}

                try:
                    icmp_type = icmp_type_map[icmp[0]]
                except Exception as e:
                    icmp_type = str(icmp[0])

                if (icmp[0] == 3): #Destination Unreachable
                    icmp_code_map = {0: "Destination Network Unreachable", 1: "Destination Host Unreachable", 2: "Destination Protocol Unreachable", 3: "Destination Port Unreachable"} ##And Many Others

                    try:
                        icmp_code = icmp_code_map[icmp[1]]
                    except Exception as e:
                        icmp_code = str(icmp[1])
                else:
                    icmp_code = str(icmp[1])


                print('\nICMP Packet:')

                print('Type: {}, Code: {}'.format(icmp_type, icmp_code))
                print("")
                print(icmp[2])

            else:
                print(ip[13]) #NOT TCP or UDP OR ICMP
        else:
            print (eth[3]) #NOT IP

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
 