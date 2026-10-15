#!/usr/bin/env python3
"""A UDP proxy in front of a KDC that writes every reply to a directory:
seeds for the kdc_message fuzz target from a real KDC.

    fuzz/capture-kdc.py <listen port> <kdc host:port> <dir>
"""
import socket
import sys


def main():
    port, kdc, out = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    host, kport = kdc.rsplit(":", 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    n = 0
    while True:
        req, peer = s.recvfrom(65535)
        up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        up.settimeout(5)
        up.sendto(req, (host, int(kport)))
        try:
            rep, _ = up.recvfrom(65535)
        except socket.timeout:
            continue
        n += 1
        with open(f"{out}/reply-{n:03d}.bin", "wb") as f:
            f.write(rep)
        s.sendto(rep, peer)


if __name__ == "__main__":
    main()
