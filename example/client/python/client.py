from __future__ import print_function
import socket
import ssl
import sslpsk

clientPsk = (b'secret', b'clientId')

def client(host, port):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.connect((host, port))
    ssl.wrap_socket()

    ssl_sock = sslpsk.wrap_socket(tcp_socket,
                                  ssl_version=ssl.PROTOCOL_TLSv1_2,
                                  ciphers='TLS-PSK-WITH-AES-128-CBC-SHA:TLS_PSK_WITH_AES_128_CBC_SHA',
                                  psk=clientPsk)

    msg = "ping"
    ssl_sock.sendall(msg.encode())
    msg = ssl_sock.recv(4).decode()
    print('Client received: %s'%(msg))

    ssl_sock.shutdown(socket.SHUT_RDWR)
    ssl_sock.close()

def main():
    host = '127.0.0.1'
    port = 5000
    client(host, port)

if __name__ == '__main__':
    main()