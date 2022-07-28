import ipaddress
import threading
import socket
import struct
import sys
import time

subnet = '10.10.10.0/24'
message = b'PLURALSIGHT'

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

# Alternative option using TCP
def tcp_sender ():

    for ip in ipaddress.ip_network(subnet).hosts():

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        
        s.settimeout(.1) #This may be too fast for some devices
        host = str(ip)
        try:
            s.connect((host, 5555))
        except ConnectionRefusedError: #Device responded, has to be up for that!
            print ("The IP Address {0} refused, Likely Up".format(ip))
        except TimeoutError: #A timeout would be normal if the device is down
            pass
        finally:
            s.close()

def udp_sender ():

    time.sleep(1)
    for ip in ipaddress.ip_network(subnet).hosts():

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)        
        #s.settimeout(.1)
        host = str(ip)
        try:
            s.sendto(message, (host, 5555))
        except ConnectionRefusedError:
            print ("The IP Address {0} refused, Likely Up".format(ip))
        except TimeoutError:
            pass
            #print ("The IP Address {0} timed out".format(ip))
        except Exception as e:
            print(e)
        finally:
            s.close()
    
def main(receive_socket):

    t = threading.Thread(target=udp_sender)
    t.start()

    while True: #Main Loop

        if (t.is_alive()):
            closing = time.time()
        else:
            if ((closing + 2) <= (time.time())): #Wait 2 seconds from thread completion to break out of loop
                receive_socket.close()
                break

        raw_data = receive_socket.recv(65535)

        #-----Ethernet
        
        eth = Ethernet_Frame(raw_data) #Parse out the Ethernet Header

        #---- IP

        if (eth.protocol == 2048): #IP

            ip = IP_Packet(eth.data) #Parse out the IP Header

            #---- ICMP

            if (ip.protocol_num == 1): #ICMP
                icmp = ICMP_Packet (ip.data)

                ##Host returned ICMP message, meaning it is up!
                if (icmp.type == 3) & (icmp.code == 3): #Destination Unreachable, Destination Port Unreachable
                    
                    data = icmp.data
                    data = str(data)
                    if (data.find(message.decode()) != -1): #Look for our message in return packet
                        print ("The IP Address {0} refused, Likely Up".format(ip.source_ip))


if __name__ == '__main__':
    
    main_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) #Open Socket at Frame Level

    try:
        main(main_socket)
    except KeyboardInterrupt:
        print("Exiting...")
        main_socket.close()
        sys.exit(0)
