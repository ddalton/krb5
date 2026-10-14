#!/usr/bin/env python3
"""Extract the AES known-answer vectors from MIT krb5's crypto tests.

    scripts/import-mit-vectors.py <krb5-checkout>/src/lib/crypto/crypto_tests <commit> \
        > testdata/mit-crypto.json

Reads the test_cases tables in t_decrypt.c, t_cksums.c, t_derive.c,
t_str2key.c and t_prf.c, keeps the entries for enctypes 17-20, and writes
them as hex. Nothing is computed: every value is MIT's, byte for byte.
"""
import json
import re
import sys

ENCTYPES = {
    "ENCTYPE_AES128_CTS_HMAC_SHA1_96": 17,
    "ENCTYPE_AES256_CTS_HMAC_SHA1_96": 18,
    "ENCTYPE_AES128_CTS_HMAC_SHA256_128": 19,
    "ENCTYPE_AES256_CTS_HMAC_SHA384_192": 20,
}
CKSUMTYPES = {
    "CKSUMTYPE_HMAC_SHA1_96_AES128": 15,
    "CKSUMTYPE_HMAC_SHA1_96_AES256": 16,
    "CKSUMTYPE_HMAC_SHA256_128_AES128": 19,
    "CKSUMTYPE_HMAC_SHA384_192_AES256": 20,
}
ERRORS = {"0": None, "KRB5_ERR_BAD_S2K_PARAMS": "KRB5_ERR_BAD_S2K_PARAMS"}

TOKEN = re.compile(
    r'\s+|/\*.*?\*/|//[^\n]*|(?P<str>"(?:[^"\\]|\\.)*")|(?P<punct>[{},])|(?P<word>[A-Za-z0-9_]+)',
    re.S,
)


def c_string(lit):
    """Decode one C string literal (without the quotes) to bytes."""
    out, i = bytearray(), 0
    while i < len(lit):
        c = lit[i]
        if c != "\\":
            out.append(ord(c))
            i += 1
            continue
        e = lit[i + 1]
        if e == "x":
            m = re.match(r"[0-9A-Fa-f]{1,2}", lit[i + 2 :])
            out.append(int(m.group(), 16))
            i += 2 + len(m.group())
        elif e in "01234567":
            m = re.match(r"[0-7]{1,3}", lit[i + 1 :])
            out.append(int(m.group(), 8))
            i += 1 + len(m.group())
        else:
            out.append({"n": 10, "t": 9, "\\": 92, '"': 34}[e])
            i += 2
    return bytes(out)


def tokens(src):
    pos, pending = 0, None
    while pos < len(src):
        m = TOKEN.match(src, pos)
        if not m:
            raise SyntaxError(f"cannot tokenize at {src[pos:pos + 40]!r}")
        pos = m.end()
        if m.group("str"):
            # Adjacent literals concatenate.
            pending = (pending or b"") + c_string(m.group("str")[1:-1])
            continue
        if m.group("punct") or m.group("word"):
            if pending is not None:
                yield pending
                pending = None
            yield m.group("punct") or m.group("word")
    if pending is not None:
        yield pending


def parse(toks):
    """Parse a brace initializer into nested lists."""
    items, cur = [], []
    for t in toks:
        if t == "{":
            cur.append(parse(toks))
        elif t == "}":
            if cur:
                items.append(cur)
            return items
        elif t == ",":
            items.append(cur)
            cur = []
        else:
            cur.append(t)
    raise SyntaxError("unbalanced braces")


def table(path, name):
    src = open(path).read()
    start = src.index("{", src.index(f"{name}[] = "))
    toks = tokens(src[start + 1 :])
    entries = []
    for e in parse(toks):
        if not e:
            continue
        # Each entry is [[field, field, ...]]; each field a list of tokens.
        (fields,) = e
        entries.append([f[0] if len(f) == 1 else f for f in fields])
    return entries


def data(field):
    """A krb5_data initializer { KV5M_DATA, len, "bytes" } -> bytes."""
    assert field[0] == ["KV5M_DATA"], field
    n = int(field[1][0])
    raw = field[2][0] if len(field) > 2 and field[2] and field[2][0] != "NULL" else b""
    assert len(raw) == n, (n, raw)
    return raw


def hx(b):
    return b.hex()


def decrypt(d):
    out = []
    for enctype, plain, usage, key, cipher in table(f"{d}/t_decrypt.c", "test_cases"):
        if enctype in ENCTYPES:
            out.append(dict(enctype=ENCTYPES[enctype], usage=int(usage), key=hx(data(key)),
                            plaintext=hx(data(plain)), ciphertext=hx(data(cipher))))
    return out


def cksums(d):
    out = []
    for plain, sumtype, enctype, usage, key, cksum in table(f"{d}/t_cksums.c", "test_cases"):
        if enctype in ENCTYPES:
            out.append(dict(enctype=ENCTYPES[enctype], cksumtype=CKSUMTYPES[sumtype],
                            usage=int(usage), key=hx(data(key)), plaintext=hx(data(plain)),
                            checksum=hx(data(cksum))))
    return out


def derive(d):
    out = []
    for enctype, inkey, constant, alg, expected in table(f"{d}/t_derive.c", "test_cases"):
        if enctype in ENCTYPES:
            out.append(dict(enctype=ENCTYPES[enctype], alg=alg, key=hx(data(inkey)),
                            constant=hx(data(constant)), derived=hx(data(expected))))
    return out


def str2key(d):
    out = []
    for enctype, string, salt, params, expected, err, weak in table(f"{d}/t_str2key.c", "test_cases"):
        if enctype in ENCTYPES:
            p = data(params)
            out.append(dict(enctype=ENCTYPES[enctype], password=hx(string), salt=hx(data(salt)),
                            params=hx(p) if p else None, key=hx(data(expected)),
                            error=ERRORS[err], allow_weak=weak == "TRUE"))
    return out


def prf(d):
    out = []
    for enctype, key, inp, expected in table(f"{d}/t_prf.c", "tests"):
        if enctype in ENCTYPES:
            out.append(dict(enctype=ENCTYPES[enctype], key=hx(data(key)), input=hx(data(inp)),
                            output=hx(data(expected))))
    return out


def main():
    d, commit = sys.argv[1], sys.argv[2]
    doc = {
        "source": "https://github.com/krb5/krb5/tree/"
        f"{commit}/src/lib/crypto/crypto_tests",
        "commit": commit,
        "note": "Generated by scripts/import-mit-vectors.py; enctypes 17-20 only. "
        "Copyright notices in testdata/MIT-KRB5-NOTICE.",
        "decrypt": decrypt(d),
        "checksum": cksums(d),
        "derive": derive(d),
        "string_to_key": str2key(d),
        "prf": prf(d),
    }
    json.dump(doc, sys.stdout, indent=1)
    sys.stdout.write("\n")


main()
