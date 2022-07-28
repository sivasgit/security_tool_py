import socket
import sys

HOST = '127.0.0.1'
PORT = 5555



client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.bind((HOST,PORT))
print(f'[*] Bound to {HOST}:{PORT}', " Press Ctrl-C to Exit")

while True:
    try:
        data, client = client_socket.recvfrom (1024)
        print ("Received :", data.decode("utf-8")) 
        client_socket.sendto(b'THIS_IS_THE_SERVER_SPEAKING', client)

    except KeyboardInterrupt:                        
        print("\nClosing Server Socket...")
        client_socket.close()
        sys.exit(-1)

