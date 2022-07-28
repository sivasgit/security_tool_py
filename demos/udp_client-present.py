import socket

HOST = '10.10.10.103'
PORT = 5555



client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.connect((HOST, PORT))
message = (b"THIS_IS_THE_CLIENT_SPEAKING")
print("Sending :", message.decode("utf-8"))
client_socket.send(message)
response = client_socket.recv(4096)
print("Received :", response.decode('utf-8'))
client_socket.close()
