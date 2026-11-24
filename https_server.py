#!/usr/bin/env python3
"""Tiny HTTPS server for the lab.
usage: https_server.py <bind_ip> <port> <certdir> <webdir>
GET serves files from webdir; POST accepts and discards the body (used for uploads/exfil tests).
"""
import os
import ssl
import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ip, port, certdir, webdir = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]


class Handler(SimpleHTTPRequestHandler):
    def do_POST(self):
        remaining = int(self.headers.get('Content-Length', 0))
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, *args):
        pass


httpd = ThreadingHTTPServer((ip, port), partial(Handler, directory=webdir))
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.path.join(certdir, 'cert.pem'), os.path.join(certdir, 'key.pem'))
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
