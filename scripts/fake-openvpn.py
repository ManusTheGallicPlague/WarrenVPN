#!/usr/bin/env python3
"""A stand-in for the openvpn binary, for testing warrenvpnd's management relay
without a real VPN server. It parses `--management <sock> unix`, creates and
listens on that unix socket, then on connect announces a CONNECTED state and a
byte-count, the way OpenVPN's management interface would."""
import os
import socket
import sys

args = sys.argv[1:]
sock_path = None
for i, a in enumerate(args):
    if a == "--management" and i + 1 < len(args):
        sock_path = args[i + 1]
        break

if not sock_path:
    sys.exit("fake-openvpn: no --management socket in args")

try:
    os.unlink(sock_path)
except FileNotFoundError:
    pass

srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sock_path)
srv.listen(1)

conn, _ = srv.accept()
conn.sendall(b">INFO:OpenVPN Management Interface Version 5 -- type 'help'\r\n")
conn.sendall(b">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.7,1194,,\r\n")
conn.sendall(b">BYTECOUNT:1024,2048\r\n")

# Drain whatever the daemon sends (state on / bytecount / hold release / signal),
# keeping the connection open briefly so the daemon can read our notifications.
conn.settimeout(8)
try:
    while True:
        data = conn.recv(4096)
        if not data:
            break
except socket.timeout:
    pass
conn.close()
