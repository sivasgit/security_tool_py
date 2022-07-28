import getpass
import socket
import select
import sys

import paramiko


def handler(chan, host, port):
    print("Getting New Socket")
    sock = socket.socket()
    try:
        sock.connect((host, port))
    except Exception as e:
        print ("Forwarding request to %s:%d failed: %r" % (host, port, e))
        return

    print ("Connected!  Tunnel open %r -> %r -> %r" % (chan.origin_addr, chan.getpeername(), (host, port)))
    
    while True:
        r, w, x = select.select([sock, chan], [], [])
        if sock in r:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            chan.send(data)
        if chan in r:
            data = chan.recv(1024)
            if len(data) == 0:
                break
            sock.send(data)
    chan.close()
    sock.close()
    print ("Tunnel closed from %r" % (chan.origin_addr,))


def reverse_forward_tunnel(server_port, remote_host, remote_port, transport):
    transport.request_port_forward("", server_port)
    while True:
        chan = transport.accept(1000)
        print("Opening New Channel...")
        if chan is None:
            continue #Why?
        handler(chan, remote_host, remote_port)       


def main():

    lip = input('Enter SSH Server IP: ')

    lport = input('Enter SSH Server port or <CR>: ') or 22
    lport = int(lport)

    user = input('SSH Server Username: ')
    password = getpass.getpass()

    fport = input('Enter SSH Server Forwarding port or <CR>: ') or 3000
    fport = int(fport)

    rip = input('Enter Remote Server IP: ')
    rport = input('Enter Remote port or <CR>: ')
    rport = int(rport)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print ("Connecting to ssh host %s:%d ..." % (lip, lport))
    try:
        client.connect(
            lip,
            lport,
            user,
            password,
        )
    except Exception as e:
        print("*** Failed to connect to %s:%d: %r" % (lip, lport, e))
        sys.exit(1)

    print ("Now forwarding SSH Server port %d to %s:%d ..." % (fport, rip, rport))


    try:
        reverse_forward_tunnel(
            fport, rip, rport, client.get_transport()
        )
    except KeyboardInterrupt:
        print("C-c: Port forwarding stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
