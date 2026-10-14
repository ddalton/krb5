# krb5

[![crates.io](https://img.shields.io/crates/v/krb5.svg)](https://crates.io/crates/krb5)
[![docs.rs](https://docs.rs/krb5/badge.svg)](https://docs.rs/krb5)

Pure-Rust Kerberos 5 — GSS-API **acceptor** and **initiator**, and a
**KDC client** — with no dependency on MIT krb5, Heimdal or glibc. Built
for servers authenticating Kerberos clients (e.g. NFS with
`sec=krb5`/`krb5i`/`krb5p` via RPCSEC_GSS) and for clients that need
tickets without shelling out to `kinit`.

- **Keytabs** — load MIT-format keytabs; key selection by principal,
  enctype and kvno.
- **Acceptor** — decrypt and validate the AP-REQ (ticket, authenticator,
  clock skew, validity window, INVALID flag), honour the initiator
  subkey, and build the AP-REP for mutual authentication.
- **KDC client** — AS exchange with a password or keytab, including
  PA-ENC-TIMESTAMP pre-authentication and ETYPE-INFO2 salts; TGS exchange
  for service tickets; TCP transport.
- **Initiator** — the AP-REQ context token (subkey, sequence number,
  RFC 4121 checksum) and AP-REP verification, including acceptor subkeys.
- **Crypto** — RFC 3961 n-fold and DR/DK, RFC 3962
  (`aes128/256-cts-hmac-sha1-96`), RFC 8009
  (`aes128-cts-hmac-sha256-128`, `aes256-cts-hmac-sha384-192`).
- **Per-message tokens** — RFC 4121 §4.2 Wrap and MIC.

Not implemented: a KDC, UDP, KDC discovery (DNS SRV / krb5.conf),
cross-realm referrals, FAST, PKINIT, credential caches, delegation.

## Server

```rust
use krb5::{Keytab, KerberosContext};

let keytab = Keytab::load("/etc/krb5.keytab")?;
let (ctx, ap_rep) = KerberosContext::accept_token(&keytab, &init_token)?;
println!("authenticated {}", ctx.client_principal);
// Return `ap_rep` to the client (empty unless it asked for mutual auth).

let tokens = ctx.per_message_tokens()?; // Wrap / MIC for krb5i / krb5p
```

`accept_token` allows the RFC 4120 recommended 5 minutes of clock skew;
use `accept_token_with_skew` to apply your own policy.

## Client

```rust
use krb5::initiator::{GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG};
use krb5::{InitiatorContext, KdcClient, Keytab, Principal};

let kdc = KdcClient::new("EXAMPLE.COM", ["kdc1.example.com", "kdc2.example.com:88"]);

let me = Principal::parse("alice@EXAMPLE.COM")?;
let tgt = kdc.login_with_password(&me, "secret")?;
// or: kdc.login_with_keytab(&me, &Keytab::load("alice.keytab")?)?

let service = Principal::parse("nfs/server.example.com@EXAMPLE.COM")?;
let creds = kdc.service_ticket(&tgt, &service)?;

let (mut ctx, token) = InitiatorContext::new(&creds, GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG)?;
// send `token`, receive the server's AP-REP:
ctx.step(&ap_rep)?;
let tokens = ctx.per_message_tokens()?;
```

`examples/gss_client.rs` is a complete client.

## Testing

```sh
cargo test
```

Every primitive carries known-answer tests copied from the RFCs and from
MIT krb5's own `crypto_tests` (decrypt, checksum, key derivation,
string-to-key and PRF, `testdata/mit-crypto.json`), and the acceptor is tested against tickets, AP-REQs, MIC and Wrap tokens recorded
from a live MIT KDC and MIT `libgssapi` for all four enctypes, with and
without mutual authentication (`testdata/`). The keytab in `testdata/`
belongs to a throwaway test realm and protects nothing.

The client is tested against a live MIT KDC, and its tokens against MIT's
own GSS acceptor. On Debian/Ubuntu (`krb5-kdc krb5-admin-server
python3-gssapi`):

```sh
scripts/test-kdc.sh /tmp/krb5test            # throwaway realm on port 18888
set -a; . /tmp/krb5test/test.env; set +a
cargo test                                   # tests/kdc.rs now runs live
cargo build --example gss_client
KRB5_CONFIG=/tmp/krb5test/krb5.conf scripts/mit-acceptor.py /tmp/krb5test target/debug/examples/gss_client
```

CI runs both on every push.

## Origin

The acceptor was extracted from the NFS server in
[flint](https://github.com/ddalton/flint).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT license](LICENSE-MIT) at your option.
