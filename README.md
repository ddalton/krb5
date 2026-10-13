# krb5

[![crates.io](https://img.shields.io/crates/v/krb5.svg)](https://crates.io/crates/krb5)
[![docs.rs](https://docs.rs/krb5/badge.svg)](https://docs.rs/krb5)

Pure-Rust Kerberos 5, **acceptor side**: what a server needs to
authenticate Kerberos clients over GSS-API (e.g. NFS with
`sec=krb5`/`krb5i`/`krb5p` via RPCSEC_GSS), with no dependency on MIT
krb5, Heimdal or glibc.

- **Keytabs** — load MIT-format keytabs; key selection by principal,
  enctype and kvno.
- **AP-REQ / AP-REP** — decrypt and validate the ticket and
  authenticator (clock skew, validity window, INVALID flag), honour the
  initiator subkey, and build the AP-REP for mutual authentication.
- **Crypto** — RFC 3961 n-fold and DR/DK, RFC 3962
  (`aes128/256-cts-hmac-sha1-96`), RFC 8009
  (`aes128-cts-hmac-sha256-128`, `aes256-cts-hmac-sha384-192`).
- **Per-message tokens** — RFC 4121 §4.2 Wrap and MIC.

There is no KDC and no initiator (client) yet.

## Usage

```rust
use krb5::{Keytab, KerberosContext};

let keytab = Keytab::load("/etc/krb5.keytab")?;
let (ctx, ap_rep) = KerberosContext::accept_token(&keytab, &init_token)?;
println!("authenticated {}@{}", ctx.client_principal, ctx.client_realm);
// Return `ap_rep` to the client (empty unless it asked for mutual auth).

let tokens = ctx.per_message_tokens()?; // Wrap / MIC for krb5i / krb5p
```

`accept_token` allows the RFC 4120 recommended 5 minutes of clock skew;
use `accept_token_with_skew` to apply your own policy.

## Testing

Every primitive carries known-answer tests copied from the RFCs, and
the acceptor is tested against tickets, AP-REQs, MIC and Wrap tokens
recorded from a live MIT KDC and MIT `libgssapi` for all four
enctypes, with and without mutual authentication (`testdata/`).
The keytab in `testdata/` belongs to a throwaway test realm and
protects nothing.

```sh
cargo test
```

## Origin

Extracted from the NFS server in [flint](https://github.com/ddalton/flint).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT license](LICENSE-MIT) at your option.
