"""
Initial version based on https://github.com/cour4g3/proxy-negotiate
See also https://pypi.python.org/pypi/Proxy-Negotiate/1.0.0

Modified by Patrick Spielmann, info@spielmann.rocks
See https://github.com/spielmap/proxy-negotiate

Modifications incorporate ideas from https://github.com/gevent/gevent/blob/master/examples/portforwarder.py

2018-02-09
-Added exception handling for socket errors
-Added retry loop for acquiring the SPNEGO token (certain GSS-APIs causing issues here)

"""

import base64
import fcntl
import datetime
import gevent
import gssapi
import os
import socket
import sys

from logging import getLogger
from gevent.server import StreamServer
from gevent.socket import create_connection, wait_read

logger = getLogger(__name__)

__version__ = '1.0.1'
GET_TOKEN_NUM_RETRIES = 3


def log(msg):
    # TODO: Clarify, if "print" is blocking or could be used here
    sys.stderr.write(str(datetime.datetime.now()) + " " + msg + '\n')
    #print str(datetime.datetime.now()), msg


def forward(src, dst):
    try:
        while True:
            try:
                data = src.recv(1024)
            except socket.error:
                log("  ==> Could not read data from socket [%s], closing socket!" % src)
            if not data:
                break
            try:
                dst.sendall(data)
            except socket.error:
                log("  ==> Could not send data to socket [%s], closing socket!" % dst)
                break
    finally:
        src.close()


def forward_stdin(sock):
    # set stdin to non-blocking so we can read available bytes
    fd = sys.stdin.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    try:
        while True:
            try:
                wait_read(sys.stdin.fileno())
                data = sys.stdin.read()
            except:
                log("  ==> Could not read data from socket [%s], closing socket!" % sock)

            if not data:
                break
            try:
                sock.sendall(data)
            except socket.error:
                log("  ==> Could not send data to socket [%s], closing socket!" % sock)
    finally:
        sock.close()


def forward_stdout(sock):
    try:
        while True:
            try:
                data = sock.recv(1024)
            except socket.error:
                log("  ==> Could not read data from socket [%s], closing socket!" % sock)
            if not data:
                break
            sys.stdout.write(data)
            sys.stdout.flush()
    finally:
        sock.close()


class NegotiateProxy(StreamServer):
    def __init__(self, listener, upstream, **kwargs):
        super(NegotiateProxy, self).__init__(listener, **kwargs)

        self.upstream = upstream

    def handle(self, src, addr):
        data = b''
        while True:
            try:
                data += src.recv(1024)
            except socket.error:
                log("  ==> Could not read data from socket [%s], closing socket!" % src)
                return
            if not data:
                log("  ==> Received no data from socket [%s], closing socket!" % src)
                return
            if b'\r\n\r\n' in data:
                break

        service = gssapi.Name('HTTP@%s' % self.upstream[0], gssapi.NameType.hostbased_service)
        ctx = gssapi.SecurityContext(name=service, usage='initiate')
        retry_counter = 0
        while True:
            try:
                token = ctx.step()
                break
            except:
                retry_counter += 1
                log("  ==> Exception while getting Kerberos token! Number of retries [%s]" % retry_counter)
                if retry_counter > GET_TOKEN_NUM_RETRIES:
                    log("  ==> Retry limit reached while trying to get a Kerberos token - giving up!")
                    return
        b64token = base64.b64encode(token).encode('ascii')

        # TODO: Check if Header handling can/should be moved to the forwarder function
        headers, data = data.split(b'\r\n\r\n', 1)
        headers = headers.split('\r\n')

        replaced = False
        for i, header in enumerate(headers):
            if header.startswith('Proxy-Authorization:'):
                headers[i] = b'Proxy-Authorization: Negotiate %s' % b64token
                replaced = True
                break

        if not replaced:
            headers.append(b'Proxy-Authorization: Negotiate %s' % b64token)

        try:
            dst = create_connection(self.upstream)
        except:
            log("  ==> Could not connect to upstream proxy [%s:%s]!" % self.upstream[:2])
            return

        try:
            dst.sendall(b'\r\n'.join(headers) + b'\r\n\r\n' + data)
        except:
            log("  ==> Could not send data to upstream proxy [%s:%s]!" % self.upstream[:2])
            return

        forwarders = (gevent.spawn(forward, src, dst),
                      gevent.spawn(forward, dst, src))

        gevent.joinall(forwarders)


def netcat(host, port, proxy_host, proxy_port):
    request = [('CONNECT %s:%d HTTP/1.1' % (host, port)).encode('ascii')]
    request.append(('Host: %s:%d' % (host, port)).encode('ascii'))
    request.append(('Proxy-Connection: Keep-Alive').encode('ascii'))
    request.append(('\r\n').encode('ascii'))

    dst = create_connection((proxy_host, proxy_port))
    dst.sendall(b'\r\n'.join(request))

    data = b''
    while True:
        data += dst.recv(1024)
        if b'\r\n\r\n' in data:
            break

    if b'200 Connection established' not in data and b'407' in data:
        service = gssapi.Name('HTTP@%s' % proxy_host, gssapi.NameType.hostbased_service)
        ctx = gssapi.SecurityContext(name=service, usage='initiate')
        token = ctx.step()
        b64token = base64.b64encode(token).encode('ascii')
        request[-1] = ('Proxy-Authorization: Negotiate %s' % b64token).encode('ascii')

        request.append(('\r\n').encode('ascii'))

        try:
            dst.sendall(b'\r\n'.join(request))
        except:
            # if proxy does not support Keep-Alive
            dst.close()
            dst = create_connection((proxy_host, proxy_port))
            dst.sendall(b'\r\n'.join(request))

        data = b''
        while True:
            data += dst.recv(1024)
            if b'\r\n\r\n' in data:
                break

    if b'200 Connection established' in data:
        sys.stderr.write('Proxy connection established\n')
        data = data.split(b'\r\n\r\n', 1)[1]
        if data:
            dst.sendall(data)

        forwarders = (gevent.spawn(forward_stdin, dst),
                      gevent.spawn(forward_stdout, dst))

        gevent.joinall(forwarders)
    elif b'407' in data:
        sys.stderr.write('Proxy authentication failed\n')
    else:
        version, status_code, status_message = data.split(b'\r\n', 1)[0].split(b' ', 2)
        sys.stderr.write('Proxy returned %s %s\n' % (status_code, status_message))
