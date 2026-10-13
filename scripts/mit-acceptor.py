#!/usr/bin/env python3
"""Run examples/gss_client against MIT krb5's own GSS-API acceptor.

    KRB5_CONFIG=<dir>/krb5.conf scripts/mit-acceptor.py <dir> <gss_client binary>

<dir> is the one scripts/test-kdc.sh set up. For each (client, service)
pair, MIT's gss_accept_sec_context must accept our AP-REQ, our client must
accept MIT's AP-REP, and each side must unwrap the other's Wrap token.
This is the interop gate for the initiator: a self-test cannot show that
a real acceptor speaks the same bytes.
"""
import os
import subprocess
import sys

import gssapi

d, client_bin = sys.argv[1], sys.argv[2]
os.environ["KRB5_KTNAME"] = f"FILE:{d}/service.keytab"
realm = "KRB5.TEST"
kdc = "127.0.0.1:18888"

# (client, password, service, session enctype or None for the KDC's pick):
# every ticket enctype, then every session enctype.
pairs = [("alice", "alicepw", "host/svc.krb5.test", None)]
pairs += [(f"u{n}", f"pw{n}", f"svc{n}/svc.krb5.test", None) for n in (17, 18, 19, 20)]
pairs += [("alice", "alicepw", "host/svc.krb5.test", n) for n in (17, 18, 19, 20)]

failed = 0
for user, pw, svc, enctype in pairs:
    env = dict(os.environ)
    if enctype:
        env["GSS_CLIENT_ENCTYPE"] = str(enctype)
    label = f"{user} -> {svc}" + (f" (session enctype {enctype})" if enctype else "")
    p = subprocess.Popen(
        [client_bin, kdc, f"{user}@{realm}", pw, f"{svc}@{realm}"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env,
    )
    try:
        ctx = gssapi.SecurityContext(usage="accept")  # any key in the keytab
        ap_rep = ctx.step(bytes.fromhex(p.stdout.readline()))
        assert ctx.complete, "MIT context not complete after AP-REQ"
        assert str(ctx.initiator_name) == f"{user}@{realm}", ctx.initiator_name
        p.stdin.write(ap_rep.hex() + "\n"); p.stdin.flush()

        got = ctx.unwrap(bytes.fromhex(p.stdout.readline()))
        assert got.message == b"ping" and got.encrypted, got
        p.stdin.write(ctx.wrap(b"pong", True).message.hex() + "\n"); p.stdin.flush()

        assert p.stdout.readline().strip() == "ok", "client did not accept MIT's Wrap"
        assert p.wait(10) == 0
        print(f"ok    {label}")
    except Exception as e:  # noqa: BLE001 - report and keep going
        failed += 1
        p.kill()
        print(f"FAIL  {label}: {e!r}")

sys.exit(1 if failed else 0)
