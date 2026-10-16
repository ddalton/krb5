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
  subkey, and build the AP-REP for mutual authentication. Replayed
  authenticators are refused (an in-memory replay cache, on by default,
  about 160 ns an AP-REQ; pluggable for services spread over several
  processes or hosts). GSS-API tokens or bare AP-REQs (`krb5_rd_req`).
- **User-to-user** — tickets in the session key of a server's TGT
  (RFC 4120 §2.9.2, `kvno --u2u`), for servers with no keytab: requested,
  accepted with the TGT, and kept in caches as MIT keeps them.
- **KDC client** — AS exchange with a password or keytab, including
  PA-ENC-TIMESTAMP pre-authentication and ETYPE-INFO2 salts; TGS exchange
  for service tickets, in other realms too (RFC 6806 referrals and
  `[capaths]`, as MIT follows them); FAST armoring (RFC 6113, as with
  `kinit -T`: the encrypted challenge, armored errors and replies, TGS
  requests too); UDP and TCP, chosen as MIT chooses. KDCs come from `krb5.conf`, from DNS
  (URI and SRV records, as MIT looks them up), or are passed in directly.
- **Async** (optional `tokio` feature) — `AsyncKdcClient`, the KDC
  client on tokio: every exchange above, kpasswd and the DNS lookups
  `async`, with `Send` futures and the same requests, checks and
  transport choices as the blocking client (one implementation drives
  both). Against MIT's KDC on an M1, 500 logins (encrypted timestamp)
  with a service ticket each take 0.26 s spawned concurrently, against
  0.76 s one after another.
- **SPAKE** — password login that a recorded exchange cannot be used to
  guess passwords against offline (MIT 1.17+'s SPAKE pre-authentication),
  preferred when the KDC offers it, as MIT's client does: edwards25519
  (implemented here, constant-time) by default, and P-256, P-384 and P-521
  with the optional `spake-nist` feature; `spake_preauth_groups` from
  krb5.conf. Checked against MIT's test vectors and live against MIT's
  KDC, inside FAST too.
- **OTP** — one-time-password login (RFC 6560, FreeIPA's two-factor
  login): the KDC's challenge answered inside FAST, tokens chosen and
  PINs handled as MIT's `kinit` does. Tested against MIT's KDC checking
  codes with RADIUS.
- **S4U** — S4U2Self (protocol transition, `kvno -U`) and S4U2Proxy
  (constrained delegation, traditional and resource-based), as MIT's
  client makes and checks them.
- **PAC** — the MS-PAC in tickets from Active Directory and MIT: logon
  info (user and group SIDs, NDR-decoded), client info, UPN and DNS
  domain, delegation path, attributes; the server, KDC, ticket and full
  signatures (HMAC-MD5 and AES). The acceptor keeps a ticket's PAC once
  it verifies, as MIT's does. Tested on PACs from Windows Server 2003,
  2008, 2019 and 2022, and from MIT's KDC.
- **PKINIT** (optional `pkinit` feature) — login with an X.509
  certificate and an RSA or elliptic-curve key (RFC 4556, `kinit -X
  X509_user_identity=...`), anonymous PKINIT (RFC 8062, `kinit -n`), and
  FAST armor from an anonymous TGT (`auto_fast_armor`). Key exchange by
  Diffie-Hellman over MODP groups 14 and 16, or by ECDH on P-256, P-384
  and P-521 against MIT 1.22 and later (RFC 5349), with the RFC 8636 KDFs
  and MIT's group negotiation; the KDC's signature (RSA or ECDSA),
  certificate chain (`pkinit_anchors`), its revocation (CRLs:
  `pkinit_revoke`, `pkinit_require_crl_checking`) and name are checked as
  MIT checks them. Pure Rust, no OpenSSL: crypto-bigint's constant-time arithmetic
  for DH and RSA, RustCrypto's `p256`/`p384`/`p521` for the curves.
  Identities from PEM files or PKCS #12 (`PKCS12:file.p12`, modern AES or
  legacy 3DES/RC2 encryption). Not yet: PKCS #11 (smart cards).
- **kadmin** — a client for MIT's `kadmind` (the kadm5 RPC protocol over
  RPCSEC_GSS, privacy-protected, API versions 2–4): principals (get,
  list, create with a password or random keys, modify, rename, delete,
  change password, randomize keys, extract keys, `ktadd` to a keytab),
  policies, string attributes. Keytabs are written as MIT writes them.
- **kpasswd** — password changes over the kpasswd protocol (port 464):
  your own (`kpasswd`), and RFC 3244 set-password for an administrator,
  to `kadmind` or Active Directory, with the server's reasons for a
  refusal.
- **Credential caches** — MIT's `FILE:` format (versions 1-4), `DIR:`
  collections, and `KCM:` (sssd-kcm, the Fedora/RHEL default, or
  Heimdal's `kcm`, over its Unix socket), so tickets move both ways between this crate and
  `kinit`, `klist`, `kvno` and other GSS programs. Default cache name as
  MIT resolves it (`KRB5CCNAME`, `default_ccache_name`,
  `/tmp/krb5cc_%{uid}`).
- **krb5.conf** — MIT's profile format, parsed as MIT does (includes,
  final flags, `KRB5_CONFIG` lists): default realm, a realm's KDCs,
  `[domain_realm]` host-to-realm mapping, and the client `[libdefaults]`
  (enctype lists, `ticket_lifetime`, `renew_lifetime`, `forwardable`,
  `proxiable`).
- **Initiator** — the AP-REQ context token (subkey, sequence number,
  RFC 4121 checksum) and AP-REP verification, including acceptor subkeys;
  delegation of a forwarded TGT (`GSS_C_DELEG_FLAG`), which the acceptor
  receives and can use.
- **SPNEGO** (RFC 4178) — both sides, for HTTP `Negotiate`, SMB, LDAP
  and Windows peers: Kerberos 5 under its own OID or Microsoft's,
  `mechListMIC`s exchanged when MIT would exchange them, and a bare
  Kerberos token accepted too.
- **Channel bindings** — RFC 4121 bindings on both sides, checked as MIT
  checks them, with the TLS bindings built in (`tls-server-end-point`,
  `tls-exporter`, `tls-unique`) and MS-KILE's KERB_AP_OPTIONS_CBT
  (`GSS_C_CHANNEL_BOUND_FLAG`, `client_aware_channel_bindings`).
- **Crypto** — RFC 3961 n-fold and DR/DK, RFC 3962
  (`aes128/256-cts-hmac-sha1-96`), RFC 8009
  (`aes128-cts-hmac-sha256-128`, `aes256-cts-hmac-sha384-192`), on the
  CPU's AES and SHA instructions (x86 and ARM, detected at run time).
- **Per-message tokens** — RFC 4121 §4.2 Wrap and MIC. On an Apple M1,
  aes128-cts-hmac-sha1-96: a 64-octet Wrap in 0.4 µs, 64 KiB sealed at
  about 800 MB/s and unsealed at 1.7 GB/s; accepting an AP-REQ about
  10 µs.

Not implemented: a KDC, `KEYRING:` and `API:`
caches, and macOS's KCM, which is reached over Mach IPC rather than a
socket (point `KRB5CCNAME` at a `FILE:` cache there).

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
use `accept_token_with_skew` to apply your own policy, and
`accept_token_with` for channel bindings too.

Each authenticator is accepted once: a replay fails with
`KerberosError::Replay`. The default replay cache lives in the process,
shared by every acceptor in it. A service that runs as several processes,
or on several hosts behind a load balancer, gives
`AcceptOptions::replay_cache` a store they share (any
`krb5::rcache::ReplayStore`). `KRB5RCACHETYPE=none` turns it off, as for
MIT.

An HTTP `Negotiate` server takes SPNEGO, bound to its TLS certificate:

```rust
use krb5::acceptor::AcceptOptions;
use krb5::spnego::SpnegoAcceptor;
use krb5::{ChannelBindings, Keytab};

let keytab = Keytab::load("/etc/krb5.keytab")?;
let mut opts = AcceptOptions::default();
opts.channel_bindings = ChannelBindings::tls_server_end_point(&server_cert_der);
let mut acc = SpnegoAcceptor::with_options(&keytab, opts);
// token: base64-decoded from "Authorization: Negotiate <token>"
let reply = acc.step(&token)?; // base64 into "WWW-Authenticate: Negotiate <reply>"
if acc.is_established() {
    println!("authenticated {}", acc.context().unwrap().client_principal);
}
```

## Client

```rust
use krb5::initiator::{GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG};
use krb5::{InitiatorContext, KdcClient, Keytab, Principal};

// KDCs from KRB5_CONFIG or /etc/krb5.conf ([realms] EXAMPLE.COM kdc = ...),
// else DNS (_kerberos URI, then _kerberos._tcp SRV records)
let kdc = KdcClient::discover("EXAMPLE.COM")?;
// or name them: KdcClient::new("EXAMPLE.COM", ["kdc1.example.com", "kdc2.example.com:88"])

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

With a credential cache, as `kinit` and `kvno` use one:

```rust
use krb5::{CCache, CacheName, KdcClient, Krb5Conf, Principal};

let conf = Krb5Conf::load_default()?;
let cache = CacheName::default(&conf)?; // KRB5CCNAME, else /tmp/krb5cc_<uid>

// kinit: log in and write the cache
let kdc = KdcClient::from_config(&conf, "EXAMPLE.COM")?;
let tgt = kdc.login_with_password(&Principal::parse("alice@EXAMPLE.COM")?, "secret")?;
cache.write(&CCache::with_credentials(&tgt))?;

// kvno: a service ticket from the cache, or bought with its TGT and stored
let service = Principal::parse("nfs/server.example.com@EXAMPLE.COM")?;
let creds = kdc.service_ticket_cached(&cache, &service)?;
```

On tokio (the `tokio` feature), the same calls are `async`:

```rust
use krb5::{AsyncKdcClient, KdcClient, Principal};

let kdc = AsyncKdcClient::discover("EXAMPLE.COM").await?;
// or: AsyncKdcClient::new(KdcClient::new("EXAMPLE.COM", ["kdc.example.com"]))
let tgt = kdc.login_with_password(&Principal::parse("alice@EXAMPLE.COM")?, "secret").await?;
let creds = kdc.service_ticket(&tgt, &Principal::parse("nfs/server.example.com@EXAMPLE.COM")?).await?;
```

`examples/gss_client.rs` is a complete client.

## Features

| Feature | Adds | Dependencies |
|---|---|---|
| (default) | everything not listed below | `aes`, `hmac`, `sha1`, `sha2`, `chrono`, `rand`, `thiserror`, `tracing` |
| `spake-nist` | SPAKE over P-256, P-384 and P-521 | `p256`, `p384`, `p521` |
| `pkinit` | `krb5::pkinit` (implies `spake-nist`) | `crypto-bigint`, `des`, `rc2`, `pbkdf2` |
| `tokio` | `AsyncKdcClient`, kpasswd's `_async` functions | `tokio` (`net`, `time`, `io-util`) |

No third-party type appears in the public API, so these dependencies can
move to new major versions without a major version of this crate.

## Rust version and stability

The minimum supported Rust version is 1.85 (`rust-version` in
`Cargo.toml`, tested in CI). It is raised only in a minor release, noted
in the changelog, and only to a version at least six months old.

The crate follows [Semantic Versioning](https://semver.org/). Error
enums, structs the crate returns, and option structs are
`#[non_exhaustive]`, so variants and fields can be added in a minor
release: match errors with a `_` arm, and build options from `Default`,
setting fields (`let mut o = AcceptOptions::default(); o.max_skew_secs =
60;`). Types that mirror a fixed wire structure (`Principal`,
`ChannelBindings`, a PAC's `Sid` and `GroupMembership`) are not.

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
own GSS acceptor; SPNEGO and channel bindings against MIT's initiator and
acceptor both (`scripts/mit-gss.py`). On Debian/Ubuntu (`krb5-kdc krb5-admin-server
python3-gssapi`):

```sh
scripts/test-kdc.sh /tmp/krb5test            # throwaway realm on port 18888
set -a; . /tmp/krb5test/test.env; set +a
cargo test                                   # tests/kdc.rs now runs live
cargo build --example gss_client
KRB5_CONFIG=/tmp/krb5test/krb5.conf scripts/mit-acceptor.py /tmp/krb5test target/debug/examples/gss_client
```

CI runs both on every push.

Every parser that reads what a peer sends has a libFuzzer target
(`fuzz/`, see `fuzz/README.md`); the inputs they have crashed on are
kept in `testdata/fuzz/` and replayed by `cargo test`, and CI runs each
target briefly on every push.

## Origin

The acceptor was extracted from the NFS server in
[flint](https://github.com/ddalton/flint).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT license](LICENSE-MIT) at your option.
