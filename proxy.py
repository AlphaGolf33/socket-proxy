#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This is a simple HTTP/HTTPS proxy only made with network sockets
"""

import socket
import threading


class Conn(threading.Thread):
    """
    Threading class for a connection between the client and the server.
    It contains 2 sockets : client <-> proxy and proxy <-> server.
    """

    def __init__(self, client_socket, client_addr):
        """
        This takes as argument an already open socket to the client.
        This socket comes from accept() in main() function
        """
        super().__init__()
        self.killed = False
        self.client = client_socket
        self.client_addr = client_addr
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_addr = None

    def get_host(self, request):
        """
        Parse client request headers to get the host field.
        i.e. the server to connect with.
        """
        headers = request.split(b'\r\n')
        for raw_header in headers:
            header = raw_header.decode('utf-8')
            if header.startswith('Host: '):
                host = header[6:].split(':')
                domain = host[0]
                port = 80 # Default port
                if len(host) == 2:
                    port = int(host[1])
                return (domain, port)

    def is_connect(self, request):
        """
        In case of a proxy the client sends a CONNECT request before starting
        the TLS handshake. The proxy must respond to this request.
        """
        try:
            headers = request.split(b'\r\n')
            for raw_header in headers:
                header = raw_header.decode('utf-8')
                if header.startswith('CONNECT'):
                    return True
        except Exception:
            pass
        return False

    def recv_timeout(self, sock, timeout=0.05):
        """
        This recieve function is non-blocking and avoid many problems due
        to sockets.
        """
        sock.settimeout(timeout)
        total_data = b'';
        data = b'';

        while True:
            try:
                data = sock.recv(8192)
                if data:
                    total_data += data
                else: # Connection closed
                    return None
            except socket.timeout: # End of wait, return packets
                break
            except OSError: # Connection closed
                return None
        return total_data


    def run(self):
        """
        Main function of the thread. Forward the requests and the responses
        between the client and the server
        """
        while not self.killed:
            # Read client request
            request = self.recv_timeout(self.client)
            if request is None: # Connection closed
                self.stop(self.client_addr, 'closed')
                return

             # First connection: open socket to server
            if self.server_addr is None:
                self.server_addr = self.get_host(request)
                if self.server_addr is None:
                    self.stop(self.client_addr, 'unable to read host field')
                    return
                try:
                    self.server.connect(self.server_addr)
                except TimeoutError:
                    self.stop(self.server_addr, 'timeout')
                    return
                except socket.gaierror:
                    self.stop(self.server_addr, 'invalid address')
                    return
                print('{}:{} <-> {}:{} connected'.format(
                    self.client_addr[0], self.client_addr[1],
                    self.server_addr[0], self.server_addr[1]
                ))

            # Begining TLS handshake with a proxied connection
            if self.is_connect(request):
                response = b'HTTP/1.1 200 Connection established\r\n\r\n'

            # Forward client request otherwize
            else:
                if request:
                    try:
                        self.server.sendall(request)
                    except BrokenPipeError:
                        self.stop(self.server_addr, 'broken pipe')
                        return

                # Read server response
                response = self.recv_timeout(self.server)
                if response is None: # Connection closed
                    self.stop(self.server_addr, 'closed')
                    return

             # Forward server response to client
            if response:
                try:
                    self.client.sendall(response)
                except BrokenPipeError:
                    self.stop(self.client_addr, 'broken pipe')
                    return

    def stop(self, remote_addr, msg):
        """
        Called if a socket is closed to stop the thread
        """
        print('{}:{} {}'.format(remote_addr[0], remote_addr[1], msg))
        if self.server_addr:
            print('{}:{} <-> {}:{} disconnected'.format(
                self.client_addr[0], self.client_addr[1],
                self.server_addr[0], self.server_addr[1]
            ))
        self.kill()

    def kill(self):
        """
        Close each connections. It can be called by the main() in case of ^C
        """
        if self.killed is False:
            self.killed = True
            self.client.close()
            self.server.close()


def main():
    """
    Bind the proxy to a port an create a thread for each new connection
    """
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind(('', 1337)) # All interfaces, port 1337
    proxy.listen(64) # Max 64 simultanous connections
    conns = [] # Array of threads created

    try:
        while True:
            client, client_addr = proxy.accept() # New connection
            c = Conn(client, client_addr) # Detach as a thread
            c.start() # Start the thread
            conns.append(c)
            conns = [c for c in conns if c.is_alive()] # Clean old threads
    except KeyboardInterrupt:
        print(' ABORT THE MISSION !!!')
        proxy.close()
        for c in conns: # Kill all threads
            c.kill()
            c.join()
        print('Proxy terminated')
        return


if __name__ == '__main__':
    main()
