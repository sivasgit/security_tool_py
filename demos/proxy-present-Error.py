import sys
import socket
import select
from ipaddress import ip_address

HEX_FILTER = ''.join(
    [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])


def hexdump(src, length=16, show=True): #Nice little function to print out wordsharkish output.
    if isinstance(src, bytes): #Converts Bytes into a string
        src = src.decode()
    results = list()
    for i in range(0, len(src), length): #process 16 bit chunks at a time (by default)
        word = str(src[i:i+length]) #Make the chunk a string
        printable = word.translate(HEX_FILTER) #translate it via HEX_FILTER
        hexa = ' '.join([f'{ord(c):02X}' for c in word]) #Format HEX to two digits (instead of 0x) and in a 16 digit format
        hexwidth = length*3
        results.append(f'{i:04x}  {hexa:<{hexwidth}}  {printable}') #Formats list items
    if show:
        for line in results:
            print(line)
    else:
        return results

def proxy_handler(client_socket, remote_host, remote_port):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    while True:
        r, w, x = select.select([client_socket, remote_socket], [], [])
        if client_socket in r:
            data = client_socket.recv(1024)
            if len(data) == 0:
                break
            print("[<==] Received %d bytes from local." % len(data))
            hexdump(data)
            remote_socket.send(data)
        if remote_socket in r:
            data = remote_socket.recv(1024)
            if len(data) == 0:
                break
            print("[<==] Received %d bytes from remote." % len(data))
            hexdump(data)
            client_socket.send(data)
    print("Closing Sockets...")            
    client_socket.close()
    remote_socket.close()


def server_loop(local_host, local_port, remote_host, remote_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((local_host, local_port))
    except Exception as e:
        print("[!!] Failed to listen on %s:%d" % (local_host, local_port))
        print(repr(e))
        sys.exit()

    print("[*] Listening on %s:%d" % (local_host, local_port))
    server.listen()
    while True:
        try:
            client_socket, addr = server.accept()
            print("> Received incoming connection from %s:%d" % (addr[0], addr[1]))        
            proxy_handler (client_socket, remote_host, remote_port)
        except KeyboardInterrupt:
            print("Exiting...")
            server.close()
            sys.exit()


def main():

    ip_valid = False

    while not ip_valid:
        
        try:
            local_host = input("Local IP: ")
            local_host = ip_address(local_host)
        except ValueError: 
            print("This is an invalid IP address")
        except Exception as e: 
            print(repr(e))
        else:
            local_host = str(local_host)
            ip_valid = True

  
    port_valid = False

    while not port_valid:
        try:
            local_port = input('Enter Local TCP Port: ')
            local_port = int(local_port)
            if (local_port >= 1) and (local_port <= 65535):
                pass
            else:
                raise Exception("Port Number Out of Range")
        except Exception as e: 
            print(repr(e))
        else:
            port_valid = True

    ip_valid = False

    while not ip_valid:
        
        try:
            remote_host = input("Remote IP: ")
            remote_host = ip_address(remote_host)
        except ValueError: 
            print("This is an invalid IP address")
        except Exception as e: 
            print(repr(e))            
        else:
            remote_host = str(remote_host)
            ip_valid = True

    port_valid = False

    while not port_valid:
        try:
            remote_port = input('Enter Remote TCP Port: ')
            remote_port = int(remote_port)
            if (remote_port >= 1) and (remote_port <= 65535):
                pass
            else:
                raise Exception("Port Number Out of Range")            
        except Exception as e: 
            print(repr(e))
        else:
            port_valid = True

    server_loop(local_host, local_port, remote_host, remote_port)            

if __name__ == '__main__':

    try:
        main()
    except KeyboardInterrupt:
        print("Exiting...")
    except Exception as e:
        print(repr(e))