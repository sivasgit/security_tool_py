import socket

HOST = '10.10.10.101'

def main():
    
    #socket_protocol = socket.IPPROTO_TCP
    #socket_protocol = socket.IPPROTO_UDP
    #socket_protocol = socket.IPPROTO_ICMP
    #socket.IPPROTO_IP doesn't work on Linux

    #sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    #sniffer.bind((HOST, 0))
    #sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) #Not needed as we aren't transmitting
    #https://man7.org/linux/man-pages/man7/raw.7.html
   
    print(sniffer.recv(65565)) #65535 is the max size of an IP packet
    
if __name__ == '__main__':
    main()
