from __future__ import print_function
import socket
import ssl
import sys
import sslpsk

clientPsk = (b'secret', b'clientId')

def client(host, port):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.connect((host, port))
    
    ssl_sock = sslpsk.wrap_socket(tcp_socket,
                                  ssl_version=ssl.PROTOCOL_TLSv1_2,
                                  ciphers='PSK-AES128-CBC-SHA',
                                  psk=clientPsk)

    msg = "ping"
    ssl_sock.sendall(msg.encode())
    msg = ssl_sock.recv(400).decode()
    print('Client received: %s'%(msg))

    ssl_sock.shutdown(socket.SHUT_RDWR)
    ssl_sock.close()

def _sslobj(sock):
    if (3, 5) <= sys.version_info <= (3, 7):
        return sock._sslobj._sslobj
    else:
        return sock._sslobj

sslpsk.sslpsk._sslobj = _sslobj

def main():
    host = '127.0.0.1'
    port = 5000
    client(host, port)

if __name__ == '__main__':
    main()