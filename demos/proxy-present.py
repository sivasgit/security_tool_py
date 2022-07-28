import sys
import socket
import select

#Directly from Black Hat Python Book
HEX_FILTER = ''.join(
    [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])

#Directly from Black Hat Python Book
def hexdump(src, length=16): #Nice little function to print out wordsharkish output.
    results = list()
    try:
        if isinstance(src, bytes): #Converts Bytes into a string
            src = src.decode()
        for i in range(0, len(src), length): #process 16 bit chunks at a time (by default)
            word = str(src[i:i+length]) #Make the chunk a string
            printable = word.translate(HEX_FILTER) #translate it via HEX_FILTER
            hexa = ' '.join([f'{ord(c):02X}' for c in word]) #Format HEX to two digits (instead of 0x) and in a 16 digit format
            hexwidth = length*3
            results.append(f'{i:04x}  {hexa:<{hexwidth}}  {printable}') #Formats list items
    except Exception as e:
        print(repr(e))

    if results:
        for line in results:
            print(line)

def proxy_handler(client_socket, remote_host, remote_port):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    while True:
        r, _, _ = select.select([client_socket, remote_socket], [], [])

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

    local_host = input("Local IP: ")

    local_port = input('Enter Local TCP Port: ')
    local_port = int(local_port)

    remote_host = input("Remote IP: ")

    remote_port = input('Enter Remote TCP Port: ')
    remote_port = int(remote_port)

    server_loop(local_host, local_port, remote_host, remote_port)            

if __name__ == '__main__':

    try:
        main()
    except KeyboardInterrupt:
        print("Exiting...")
    except Exception as e:
        print(repr(e))