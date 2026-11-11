# Unix sockets: guest paths in bind, connect and the socket names.
import os
import shutil
import socket
import stat
import struct
import sys
import tempfile

fails = 0


def ok(cond, what):
    global fails
    print(("ok   " if cond else "FAIL ") + what)
    fails += not cond


d = os.path.realpath(tempfile.mkdtemp(prefix="burrow-sock."))
path = d + "/s"
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(1)
ok(stat.S_ISSOCK(os.stat(path).st_mode), "bind makes a socket at the guest path")
ok(server.getsockname() == path, "getsockname")
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.connect(path)
ok(client.getpeername() == path, "getpeername")
conn, _ = server.accept()
client.sendall(b"ping")
ok(conn.recv(4) == b"ping", "data")
ok(conn.getpeername() in ("", None, b""), "an unnamed peer")
for s in (conn, client, server):
    s.close()

os.chdir(d)
rel = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
rel.bind("r")
ok(os.path.exists(d + "/r"), "bind on a relative path")
sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
sender.sendto(b"dgram", d + "/r")
ok(rel.recv(5) == b"dgram", "sendto a guest path")
rel.close()
sender.close()

abstract = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
abstract.bind("\0burrow-test-%d" % os.getpid())
ok(abstract.getsockname() == b"\0burrow-test-%d" % os.getpid(), "abstract name")
abstract.close()

a, b = socket.socketpair()
a.sendall(b"pair")
ok(b.recv(4) == b"pair", "socketpair")

# Netlink route sockets: Android refuses bind() and RTM_GETLINK, Burrow answers.
ok(any(name == "lo" for _, name in socket.if_nameindex()), "if_nameindex (RTM_GETLINK)")
nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
nl.bind((0, 0))
pid = nl.getsockname()[0]
ok(pid != 0, "netlink bind and getsockname")
nl.send(struct.pack("=LHHLLBBHiII", 32, 18, 0x301, 7, 0, 0, 0, 0, 0, 0, 0))  # RTM_GETLINK dump
names, done = [], False
while not done:
    data, at = nl.recv(65536), 0
    while at + 16 <= len(data):
        length, kind, _, seq, to = struct.unpack_from("=LHHLL", data, at)
        done |= kind == 3  # NLMSG_DONE
        if kind == 16 and seq == 7 and to == pid:  # RTM_NEWLINK
            a = at + 32
            while a + 4 <= at + length:
                n, t = struct.unpack_from("=HH", data, a)
                if t == 3:  # IFLA_IFNAME
                    names.append(data[a + 4:a + n].rstrip(b"\0"))
                a += (n + 3) & ~3
        at += (length + 3) & ~3
ok(b"lo" in names, "RTM_GETLINK dump")
nl.close()
os.chdir("/")
shutil.rmtree(d)
sys.exit(1 if fails else 0)
