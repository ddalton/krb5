#!/usr/bin/env python3
"""Seed fuzz/corpus/<target>/ from the repository's real fixtures: MIT's
AP-REQs and per-message tokens, Windows' and MIT's PACs, MIT's caches and
keytab, DNS answers, PKINIT certificates and PKCS #12 files. With a KDC
capture directory (fuzz/capture-kdc.py writes one) its replies seed
kdc_message too. Targets whose first octet selects a parser get one seed
per selector.

    fuzz/seed.py [capture-dir]
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "fuzz", "corpus")


def put(target, name, data):
    d = os.path.join(CORPUS, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def files(sub, exts=None):
    d = os.path.join(ROOT, sub)
    for n in sorted(os.listdir(d)):
        if exts is None or any(n.endswith(e) for e in exts):
            with open(os.path.join(d, n), "rb") as f:
                yield n, f.read()


def main():
    tokens = []
    for name in ("interop.json", "interop-mutual.json"):
        with open(os.path.join(ROOT, "testdata", name)) as f:
            for etype, fx in json.load(f).items():
                for k, v in fx.items():
                    if isinstance(v, str) and len(v) > 8 and all(c in "0123456789abcdef" for c in v):
                        tokens.append((f"{name}-{etype}-{k}", bytes.fromhex(v)))
    for n, t in tokens:
        put("acceptor_token", n, t)
        if t[:1] == b"\x60":
            # The AP-REQ after the GSS framing (OID and TOK_ID).
            put("acceptor_token", n + "-bare", t[17:])
            put("acceptor_inner", n + "-apreq", b"\x05" + t[17:])
        put("spnego", n + "-acc", b"\x00" + t)
        put("spnego", n + "-tok", b"\x03" + t)
    for n, p in files("testdata/pac"):
        put("pac", n, p)
    for n, c in files("testdata/ccache", [".ccache"]):
        put("ccache", n, c)
    with open(os.path.join(ROOT, "testdata", "interop.keytab"), "rb") as f:
        put("keytab", "interop.keytab", f.read())
    for n, m in files("testdata/dns"):
        # A whole message, through the second parse.
        put("dns", n, b"\x00" + m)
    for n, c in files("src/pkinit/testdata"):
        sel = {".pem": 1, ".p12": 2, ".der": 3}.get(os.path.splitext(n)[1])
        if sel is not None:
            put("pkinit", n, bytes([sel]) + c)
    put("text", "krb5.conf", open(os.path.join(ROOT, "testdata", "mit-settings.tsv"), "rb").read())
    put("text", "conf", b"[libdefaults]\n default_realm = A.ORG\n spake_preauth_groups = edwards25519 P-256\n"
        b"[realms]\n A.ORG = {\n  kdc = k.a.org:88\n }\n")
    if len(sys.argv) > 1:
        for n, m in files(sys.argv[1]):
            # AS (11) and TGS (13) replies and errors, as selectors 0 and 1.
            put("kdc_message", n + "-as", b"\x00" + m)
            put("kdc_message", n + "-tgs", b"\x01" + m)
            if m[:1] == b"\x7e":
                put("kdc_message", n + "-err", b"\x07" + m)
    for t in os.listdir(CORPUS):
        print(t, len(os.listdir(os.path.join(CORPUS, t))))


if __name__ == "__main__":
    main()
