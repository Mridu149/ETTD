#!/usr/bin/env python3
"""Tiny HTTPS client using Python's own TLS settings (gives a different JA3 than curl).
usage: py_client.py <server_ip> <hostname> <path> [port]"""
import socket
import ssl
import sys

ip, name, path = sys.argv[1:4]
port = int(sys.argv[4]) if len(sys.argv) > 4 else 443
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection((ip, port), timeout=10) as s:
    with ctx.wrap_socket(s, server_hostname=name) as t:
        t.sendall(f"GET {path} HTTP/1.0\r\nHost: {name}\r\n\r\n".encode())
        while t.recv(65536):
            pass
