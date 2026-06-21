#!/usr/bin/env python3
"""Stand-in openvpn that exercises the static-challenge (SCRV1) auth flow."""
import os
import socket
import sys
import time

# password "s3cret" + challenge "1234" -> SCRV1:base64(s3cret):base64(1234)
EXPECT_USER = 'username "Auth" "alice"'
EXPECT_PASS = 'password "Auth" "SCRV1:czNjcmV0:MTIzNA=="'

args = sys.argv[1:]
sock_path = None
for i, a in enumerate(args):
    if a == "--management" and i + 1 < len(args):
        sock_path = args[i + 1]
        break
if not sock_path:
    sys.exit("fake-openvpn-sc: no --management socket")

try:
    os.unlink(sock_path)
except FileNotFoundError:
    pass

srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sock_path)
srv.listen(1)
conn, _ = srv.accept()
f = conn.makefile("rwb", buffering=0)

f.write(b">INFO:OpenVPN Management Interface Version 5\r\n")
while True:
    line = f.readline()
    if not line:
        sys.exit(0)
    if b"hold release" in line:
        break

f.write(b">PASSWORD:Need 'Auth' username/password SC:0,Enter token PIN\r\n")

got_user = got_pass = None
while got_user is None or got_pass is None:
    line = f.readline()
    if not line:
        break
    s = line.decode(errors="replace").strip()
    if s.startswith("username "):
        got_user = s
    elif s.startswith("password "):
        got_pass = s

out = os.environ.get("WARRENVPN_AUTH_OUT")
if out:
    with open(out, "w") as fh:
        fh.write(f"{got_user}\n{got_pass}\n")

if got_user == EXPECT_USER and got_pass == EXPECT_PASS:
    f.write(b">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.7,1194,,\r\n")
else:
    f.write(b">STATE:1700000000,EXITING,auth-failure,,,\r\n")

time.sleep(3)
conn.close()
