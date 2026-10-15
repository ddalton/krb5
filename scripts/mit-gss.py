#!/usr/bin/env python3
"""MIT krb5's GSS-API, as one end of a context, for tests/kdc.rs.

    mit-gss.py initiate <service@REALM> [options]   (TGT from KRB5CCNAME)
    mit-gss.py accept [options]                     (keys from KRB5_KTNAME)

Options:
    --spnego           negotiate with SPNEGO (1.3.6.1.5.5.2), not raw krb5
    --cb <hex>         channel bindings with this application data
    --flags <int>      GSS request flags (default mutual|integ|conf)

Speaks lines on stdin/stdout. Each token MIT produces is printed as
"tok <hex>" ("tok -" for none); each token from the peer is read as one
hex line. Once established it prints "done <flags> <peer name>" (the
acceptor's flags are MIT's ret_flags), then the initiator prints a Wrap of
"ping" and reads a Wrap that must hold "pong", the acceptor the reverse,
and both print "ok". A failure prints "err <message>" and exits 1.
"""
import sys

import gssapi
import gssapi.raw as raw

SPNEGO = gssapi.OID.from_int_seq("1.3.6.1.5.5.2")


def out(*words):
    print(*words, flush=True)


def read_token():
    line = sys.stdin.readline()
    if not line:
        raise SystemExit("peer hung up")
    return bytes.fromhex(line.strip())


def main():
    args = sys.argv[1:]
    role = args.pop(0)
    target = args.pop(0) if role == "initiate" else None
    spnego, cb, flags = False, None, None
    while args:
        a = args.pop(0)
        if a == "--spnego":
            spnego = True
        elif a == "--cb":
            cb = raw.ChannelBindings(application_data=bytes.fromhex(args.pop(0)))
        elif a == "--flags":
            flags = int(args.pop(0))
    if flags is None:
        f = gssapi.RequirementFlag
        flags = f.mutual_authentication | f.integrity | f.confidentiality

    if role == "initiate":
        name = gssapi.Name(target, gssapi.NameType.kerberos_principal)
        ctx = gssapi.SecurityContext(
            name=name, usage="initiate", flags=flags,
            mech=SPNEGO if spnego else None, channel_bindings=cb,
        )
        token = ctx.step()
    else:
        ctx = gssapi.SecurityContext(usage="accept", channel_bindings=cb)
        token = ctx.step(read_token())
    while True:
        out("tok", token.hex() if token else "-")
        if ctx.complete:
            break
        token = ctx.step(read_token())

    peer = ctx.target_name if role == "initiate" else ctx.initiator_name
    out("done", int(ctx.actual_flags), str(peer))
    if role == "initiate":
        out("wrap", ctx.wrap(b"ping", True).message.hex())
        reply = ctx.unwrap(read_token()).message
        assert reply == b"pong", reply
    else:
        got = ctx.unwrap(read_token()).message
        assert got == b"ping", got
        out("wrap", ctx.wrap(b"pong", True).message.hex())
    out("ok")


try:
    main()
except Exception as e:  # noqa: BLE001 - report anything to the test
    out("err", f"{type(e).__name__}: {e}".replace("\n", " "))
    sys.exit(1)
