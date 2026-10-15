#!/usr/bin/env python3
"""A RADIUS server for the OTP live tests: the token checker MIT's KDC asks.

    radius-test.py <udp port> <secret file> <log file> <code>

Answers each Access-Request (RFC 2865) with Access-Accept when its
User-Password is <code>, else Access-Reject. When the request carries a
Message-Authenticator (RFC 2869 §5.14), as MIT's libkrad does since the
BlastRADIUS fix and then requires back over UDP, so does the answer;
older libkrad sends none and refuses an answer with one. Each request is
logged as "<User-Name> <User-Password> accept|reject". Standard library
only: what MIT's own t_otp.py does with pyrad.
"""
import hashlib
import hmac
import socket
import sys

ACCESS_REQUEST, ACCESS_ACCEPT, ACCESS_REJECT = 1, 2, 3
USER_NAME, USER_PASSWORD, MESSAGE_AUTHENTICATOR = 1, 2, 80


def attributes(data):
    out, i = [], 0
    while i + 2 <= len(data):
        t, n = data[i], data[i + 1]
        if n < 2:
            break
        out.append((t, data[i + 2:i + n]))
        i += n
    return out


def decrypt_password(secret, auth, c):
    # RFC 2865 §5.2: p_i = c_i XOR MD5(secret || c_{i-1}), c_0 = auth.
    out, prev = b"", auth
    for i in range(0, len(c), 16):
        b = hashlib.md5(secret + prev).digest()
        block = c[i:i + 16]
        out += bytes(x ^ y for x, y in zip(block, b))
        prev = block
    return out.rstrip(b"\0")


def reply(secret, request, code, msgauth):
    rid, req_auth = request[1], request[4:20]
    # Message-Authenticator first, computed with the request authenticator
    # in place and itself zeroed; then the response authenticator over the
    # finished packet.
    attrs = bytes([MESSAGE_AUTHENTICATOR, 18]) + bytes(16) if msgauth else b""
    length = 20 + len(attrs)
    head = bytes([code, rid]) + length.to_bytes(2, "big")
    if msgauth:
        mac = hmac.new(secret, head + req_auth + attrs, hashlib.md5).digest()
        attrs = bytes([MESSAGE_AUTHENTICATOR, 18]) + mac
    resp_auth = hashlib.md5(head + req_auth + attrs + secret).digest()
    return head + resp_auth + attrs


def main():
    port, secret_file, log_file, code = sys.argv[1:5]
    secret = open(secret_file, "rb").read().strip()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", int(port)))
    while True:
        data, peer = sock.recvfrom(4096)
        if len(data) < 20 or data[0] != ACCESS_REQUEST:
            continue
        attrs = dict(attributes(data[20:]))
        user = attrs.get(USER_NAME, b"").decode(errors="replace")
        pw = decrypt_password(secret, data[4:20], attrs.get(USER_PASSWORD, b""))
        ok = pw == code.encode()
        with open(log_file, "a") as log:
            print(user, pw.decode(errors="replace"), "accept" if ok else "reject",
                  file=log, flush=True)
        verdict = ACCESS_ACCEPT if ok else ACCESS_REJECT
        sock.sendto(reply(secret, data, verdict, MESSAGE_AUTHENTICATOR in attrs), peer)


if __name__ == "__main__":
    main()
