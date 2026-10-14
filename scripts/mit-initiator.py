#!/usr/bin/env python3
"""MIT krb5's own GSS-API initiator, for tests/kdc.rs.

    KRB5_CONFIG=... KRB5CCNAME=... scripts/mit-initiator.py <service principal> [delegate]

Prints one hex line: the initial context token MIT's gss_init_sec_context
makes for the service, from the TGT in KRB5CCNAME. With "delegate" it
asks for GSS_C_DELEG_FLAG, so the token carries a forwarded TGT (which
needs a forwardable TGT: kinit -f).
"""
import sys

import gssapi

name = gssapi.Name(sys.argv[1], gssapi.NameType.kerberos_principal)
flags = [gssapi.RequirementFlag.mutual_authentication,
         gssapi.RequirementFlag.integrity, gssapi.RequirementFlag.confidentiality]
if sys.argv[2:] == ["delegate"]:
    flags.append(gssapi.RequirementFlag.delegate_to_peer)
ctx = gssapi.SecurityContext(name=name, usage="initiate", flags=flags)
print(ctx.step().hex())
