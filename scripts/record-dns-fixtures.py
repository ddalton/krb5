#!/usr/bin/env python3
"""Record real DNS replies for src/dns.rs's tests.

    scripts/record-dns-fixtures.py <out-dir> [nameserver]

For each (name, type) below, builds a query independently of the Rust
encoder, sends it over UDP to the nameserver (default: the first in
/etc/resolv.conf), and writes the raw reply as <out-dir>/<label>.bin,
with the query ID as its first two octets as always. A truncated reply is
fetched again over TCP. The answers are public records of public realms.
"""
import os
import random
import socket
import struct
import sys

QUERIES = [
    ("athena-udp-srv", "_kerberos._udp.athena.mit.edu.", 33),
    ("athena-tcp-srv", "_kerberos._tcp.athena.mit.edu.", 33),
    ("fedora-tcp-srv", "_kerberos._tcp.fedoraproject.org.", 33),
    ("fedora-uri", "_kerberos.fedoraproject.org.", 256),
    ("freeipa-uri", "_kerberos.demo1.freeipa.org.", 256),
    ("nxdomain-srv", "_kerberos._tcp.no-such-realm.invalid.", 33),
]


def query(qid, name, qtype):
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\0" + struct.pack(">HH", qtype, 1)


def nameserver():
    for line in open("/etc/resolv.conf"):
        w = line.split()
        if len(w) >= 2 and w[0] == "nameserver":
            return w[1].split("%")[0]
    return "127.0.0.1"


def main():
    out = sys.argv[1]
    server = sys.argv[2] if len(sys.argv) > 2 else nameserver()
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    os.makedirs(out, exist_ok=True)
    for label, name, qtype in QUERIES:
        qid = random.randrange(65536)
        q = query(qid, name, qtype)
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(q, (server, 53))
        reply, _ = s.recvfrom(4096)
        if reply[2] & 0x02:
            t = socket.create_connection((server, 53), timeout=5)
            t.sendall(struct.pack(">H", len(q)) + q)
            n = struct.unpack(">H", t.recv(2))[0]
            reply = b""
            while len(reply) < n:
                reply += t.recv(n - len(reply))
        assert reply[:2] == q[:2]
        with open(os.path.join(out, label + ".bin"), "wb") as f:
            f.write(reply)
        print(f"{label}: {len(reply)} octets, rcode {reply[3] & 15}, "
              f"{struct.unpack('>H', reply[6:8])[0]} answers")


main()
