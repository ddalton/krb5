# Changelog

All notable changes to this crate. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
follows [Semantic Versioning](https://semver.org/) (pre-1.0: a minor bump
may break the API).

## [Unreleased]

## [1.0.0] - 2026-10-16

### Added

- An async KDC client on tokio, with the new `tokio` feature:
  `AsyncKdcClient`, with every `KdcClient` exchange as an `async fn`
  (logins with a password, keytab, OTP or certificate, anonymous PKINIT,
  service tickets across realms, `kinit` and `kvno` through caches,
  renewal and validation, forwarded TGTs, S4U2Self and S4U2Proxy,
  user-to-user), its DNS lookups too (`AsyncKdcClient::from_config`,
  `discover`, `for_realm`), and `kpasswd::change_password_async`,
  `change_password_with_ticket_async` and `set_password_async`. Every
  future is `Send`. Make one from a configured `KdcClient`
  (`AsyncKdcClient::new`).
  - The exchanges are written once and driven by both clients: the
    blocking one runs them on `std::net`'s sockets, the async one on
    tokio's, so the requests, the checks on the replies, and the choice
    and order of UDP and TCP (MIT's waits and retries) are the same.
  - Tested live against MIT's KDC as the blocking client is (logins,
    FAST, referrals, S4U, PKINIT, caches MIT's tools read, kpasswd, DNS
    SRV), with 64 logins at once across a multi-threaded runtime, and the
    transport and DNS unit tests run on both.
  - Cache reads and writes (`service_ticket_cached`, the `kinit_*`
    methods) stay synchronous: a local file, or the KCM daemon over a
    Unix socket. kadmin has no async client.

### Changed

The public API is settled for 1.0: what it promises is smaller, and what
remains can grow in minor releases.

- The raw crypto is no longer public: the `kdf`, `nfold` and `profile`
  modules, and `token`'s header and rotation helpers (`mic_header`,
  `wrap_header`, `header_for_seal`, `header_for_sign`, `rotate_left`,
  `rotate_right`, `seal_input`, `sign_input`, `mic_input`). Keys,
  encryption and checksums are reached through `Key`, and per-message
  tokens through `token::PerMessageTokens` and `ContextKey`, as before.
  This also drops the duplicate enctype enums `kdf::Enctype` and
  `profile::Enctype`; `EncType` names enctypes.
- `token::PerMessageCrypto` is sealed: `ContextKey` implements it, and
  no one else can, so it can gain methods.
- `#[non_exhaustive]` on the error enums (`KerberosError`, `PacError`,
  `TokenError`, and `KeyError`), on enums that may grow (`EncType`,
  `Transport`, `SpakeGroup`, `dns::Record`, `kpasswd::ResultCode`), and on
  the structs with public fields (`Credentials`, `KerberosContext`,
  `ServiceKey`, `CCache`, `ccache::Entry`, `ClientDefaults`,
  `dns::Resolver`, the OTP, kadmin and PAC structs, `token::Verified`) and
  options (`AcceptOptions`, `InitOptions`, `PrincipalChanges`, `Policy`,
  `OtpAnswer`). Their fields stay public. Build options from `Default`
  and set fields: `let mut o = AcceptOptions::default(); o.max_skew_secs
  = 60;`. New constructors for the ones built by hand:
  `ServiceKey::new`, and `OtpAnswer::new` with `with_pin`. `Principal`,
  `ChannelBindings`, and the PAC's `Sid` and `GroupMembership`, which
  mirror fixed wire structures, are unchanged.
- `KdcClient::login_with_otp_by`'s callback must be `Sync`.

### Documentation

- Every public item is documented (`#![warn(missing_docs)]`, an error in
  CI), and docs.rs marks the items each feature adds.
- The README lists the features and their dependencies, and states the
  MSRV policy (1.85; raised only in a minor release, to a version at
  least six months old) and what `#[non_exhaustive]` allows.
- 0.13.1's notes counted the default build's direct dependencies as 9;
  there are 8.

## [0.13.1] - 2026-10-15

### Changed

- Faster string-to-key: PBKDF2 now precomputes the HMAC key's inner and
  outer states and runs each of its thousands of rounds as two calls of
  the compression function, where the `pbkdf2` crate went through
  `hmac`'s cloning and buffering every round. That overhead had made
  string-to-key about 12% slower on x86 in 0.12.1 than in 0.12.0. On an
  AMD EPYC 7763, against 0.13.0: aes128-cts-hmac-sha1-96 503 µs to
  416 µs, aes256-cts-hmac-sha1-96 1.0 ms to 0.83 ms,
  aes256-cts-hmac-sha384-192 17.2 ms to 16.6 ms (aes128-cts-hmac-sha256-128
  unchanged at 3.5 ms), each now faster than 0.12.0 too.
- The `pbkdf2` crate is now a dependency only with `pkinit` (for PKCS #12
  files): the default build has 9 direct dependencies.

## [0.13.0] - 2026-10-15

### Added

- Certificate revocation for PKINIT: the KDC's certificate chain is
  checked against CRLs, as MIT's client checks it through OpenSSL. A
  `pkinit_revoke` already in krb5.conf, ignored before, now takes effect.
  - Every certificate below the trust anchor is looked up in a CRL from
    its issuer: those of `pkinit_revoke` in krb5.conf (`FILE:` and `DIR:`
    locations of PEM CRLs) or `pkinit::RevocationLists`
    (`KdcClient::with_pkinit_revocation_lists`), and those the KDC sends
    in its SignedData. A revoked certificate fails the login, and so does
    a CRL that has expired or is not yet valid, is not signed by its
    issuer (or one without `cRLSign`), does not cover the certificate
    (issuingDistributionPoint), or has an unhandled critical extension.
  - With `pkinit_require_crl_checking` (or
    `KdcClient::with_pkinit_require_crl_checking`), a certificate with no
    CRL from its issuer fails too; without, it passes, as in MIT.
  - MIT's quirks are kept: only the first CRL loaded from each issuer
    counts, the trust anchor itself is never checked, and of several
    CRLs for a certificate OpenSSL's choice is made (current first, then
    the latest). Delta, indirect and reason-partitioned CRLs are not used,
    as OpenSSL does not use them for MIT; OCSP is not done, nor by MIT.
  - Tested live against MIT 1.21 and 1.22: our client and MIT's `kinit`
    reach the same outcome for each case (no CRL, a current CRL, the KDC's
    certificate revoked, an expired CRL, the order of two CRLs, with and
    without the requirement); unit tests make CRLs to order for the rest.
  - The `pkinit` fuzz target parses and checks CRLs too.

## [0.12.1] - 2026-10-15

### Security

- A malformed AP-REQ could panic the acceptor before any decryption: a
  DER length running past the end of its input was sliced, not refused
  (and the indefinite form and over-long length fields were not
  rejected). Any client able to reach a service could take down a
  process that does not catch panics. Found by fuzzing, as were two
  lesser panics, each reachable only with a key: a KerberosTime holding
  a non-ASCII character in a decrypted ticket or authenticator, and the
  same in an X.509 certificate's validity times (PKINIT).

### Added

- Fuzzing: a libFuzzer target for every parser that reads what a peer
  sends (the acceptor's tokens and what they decrypt to, SPNEGO, Wrap
  and MIC tokens, the PAC, KDC replies and errors, FAST, KRB-CRED, OTP
  and SPAKE challenges, DNS, kadmind's RPC, kpasswd, PKINIT's
  certificates, CMS, keys and PKCS #12, ccaches, keytabs, krb5.conf),
  seeded from the recorded MIT traffic in `testdata/`. See
  `fuzz/README.md`. Crashing inputs are kept in `testdata/fuzz/` and
  replayed by `cargo test`; CI fuzzes every target briefly on each push.

### Changed

- Faster crypto, through RustCrypto's current `aes`, `sha1`, `sha2`,
  `hmac` and `pbkdf2` (and, for PKCS #12, `des` and `rc2`), which use the
  CPU's AES and SHA instructions on ARM as well as x86, chosen at run
  time; the previous versions ran AES and SHA in software on ARM. Wrap
  and unwrap now encrypt in place, decrypt CBC blocks several at a time,
  and copy a message once rather than about seven times, and the
  confounder comes from the thread-local CSPRNG, not a system call per
  message, as MIT draws it from its own generator. On an Apple M1, with
  aes128-cts-hmac-sha1-96: a 64-octet Wrap 3.5 µs to 0.4 µs, 64 KiB
  1.2 ms to 80 µs (unwrap 1.2 ms to 38 µs), a 64 KiB MIC 69 µs to 29 µs,
  accepting an AP-REQ about 22 µs to 10 µs, and string-to-key for
  aes128-cts-hmac-sha256-128 12.5 ms to 2.6 ms. The direct dependency
  count is unchanged, and seven duplicate crates leave the build.
- `token::PerMessageCrypto` gains `encrypt_parts` and `get_mic_parts`,
  provided methods (defaulting to the existing ones), so the token layer
  can encrypt and checksum a header and a message without joining them.

## [0.12.0] - 2026-10-15

### Added

- SPAKE pre-authentication (draft-ietf-kitten-krb-spake-preauth, MIT 1.17
  and later): a password or keytab login whose recorded exchange gives an
  eavesdropper nothing to guess passwords against offline. As in MIT's
  client, it is used whenever the KDC offers it.
  - The flow is MIT's. The support message lists our groups, the KDC's
    challenge (sent with MORE_PREAUTH_DATA_REQUIRED and a cookie holding
    its state) is answered with our public value and an encrypted SF-NONE
    factor, and the reply comes in K'[0]. An optimistic challenge is
    answered directly. A KDC that takes none of our groups leaves the
    login to encrypted timestamps, and SPAKE works inside FAST too.
  - edwards25519, MIT's client default, is implemented in the crate, in
    constant time, with no new dependency. P-256, P-384 and P-521 come
    with the new `spake-nist` feature (also part of `pkinit`), on
    RustCrypto's curves. A response costs about 0.2 ms on edwards25519
    and 0.6 to 2.2 ms on the NIST curves.
  - `client::spake::SpakeGroup`, `KdcClient::with_spake_groups`, and
    `spake_preauth_groups` in krb5.conf (`ClientDefaults::spake_groups`)
    set the groups offered. An empty list (or `none` in krb5.conf) turns
    SPAKE off.
  - Tested against MIT's test vectors for every group (w, T, S, K, the
    transcript hash, K'[0..3]), and live against MIT 1.21 and 1.22, whose
    test KDC now offers SPAKE in edwards25519, P-256 and P-384: each
    group, the fallback for P-521, a wrong password, a keytab key, and
    inside FAST.
- OTP pre-authentication (RFC 6560): one-time passwords, as FreeIPA uses
  them for two-factor login. `KdcClient::login_with_otp` answers the
  KDC's PA-OTP-CHALLENGE inside FAST armor as MIT's `kinit` does: the
  token the value fits, the PIN before the value or apart as the token
  says, the nonce encrypted in the armor key, which becomes the reply key.
  `login_with_otp_by` sees the challenge (`client::otp::OtpChallenge`)
  and chooses the token and gives the PIN itself. Tokens MIT's client
  cannot answer for are dropped the same way.
  - Tested live against MIT 1.21 and 1.22, whose KDC checks the code with
    a RADIUS server (`scripts/radius-test.py`, standard-library Python, in
    the test realm): the right code logs in, a wrong one is refused.

### Changed

- Breaking: `ClientDefaults` has a new field, `spake_groups`.
- Password and keytab logins use SPAKE when the KDC offers it, which takes
  one round trip more than encrypted timestamps. `with_spake_groups(&[])`
  restores the old behavior.

## [0.11.0] - 2026-10-15

### Added

- A replay cache (RFC 4120 §3.2.3). The acceptor refuses an authenticator
  it has accepted before while that authenticator could still pass the
  clock-skew check, with `KerberosError::Replay` (KRB_AP_ERR_REPEAT). It
  is on by default: `AcceptOptions::replay_cache` defaults to a
  process-wide in-memory cache (`rcache::ReplayCache::global`), unless
  `KRB5RCACHETYPE=none` or `KRB5RCACHENAME=none:` as in MIT. As in MIT, an
  authenticator is known by the checksum that ends its ciphertext.
  - The cache is sharded and expires entries a whole generation at a
    time, about 160 ns an AP-REQ on one thread.
  - `rcache::ReplayStore` lets a service that runs as several processes,
    or on several hosts, plug in a store they share. MIT's own file cache
    is not shared: locking it as MIT does needs `fcntl`.
  - Tested live both ways: a re-sent MIT authenticator is refused, and
    MIT's acceptor refuses a re-sent one of ours.
- User-to-user (RFC 4120 §2.9.2).
  - `KdcClient::user_to_user` asks for a ticket in the session key of a
    server's TGT (ENC-TKT-IN-SKEY), as `kvno --u2u` does.
  - `InitOptions::use_session_key` sets USE-SESSION-KEY in the AP-REQ.
  - `KerberosContext::accept_token_u2u` and `accept_ap_req_u2u` accept
    such a ticket with the server's TGT.
  - `CCache::store_user_to_user` and `find_user_to_user` keep these
    tickets as MIT does (`is_skey`, with the server's TGT as the second
    ticket).
  - Tested live with MIT's KDC, MIT's `kvno --u2u`, and MIT's `uuserver`.
- `KerberosContext::accept_ap_req`: a bare AP-REQ, not wrapped in a
  GSS-API token, as MIT's `krb5_rd_req` takes one, and a bare AP-REP for
  mutual authentication.

### Changed

- Breaking: `AcceptOptions` has a new field, `replay_cache`;
  `InitOptions` has `use_session_key`; `KerberosError` has `Replay`.
- Accepting the same AP-REQ twice now fails. Code that did so on purpose
  (tests replaying a captured token) sets `replay_cache: None` or gives
  each acceptance its own `ReplayCache`.

### Fixed

- `CCache::find`, and so `service_ticket_cached` and `tgt`, no longer
  return a user-to-user ticket from a cache MIT's `kvno --u2u` wrote,
  which only the TGT it is in can accept. MIT's lookups skip them too.

## [0.10.0] - 2026-10-15

### Added

- S4U (MS-SFU). `KdcClient::s4u2self` gets a ticket to the service in a
  user's name (protocol transition, `kvno -U`). It sends PA-S4U-X509-USER
  (checksummed with the authenticator subkey) and PA-FOR-USER (HMAC-MD5),
  and checks the KDC's checksummed reply as MIT does: our nonce, our
  subkey, and the user it names. `KdcClient::s4u2proxy` turns such a
  ticket, or one the user sent, into a ticket to another service
  (constrained delegation). It sends the evidence ticket with
  cname-in-addl-tkt and PA-PAC-OPTIONS, so the KDC can apply either
  traditional or resource-based delegation rules. Both work in the
  service's own realm, and inside FAST armor when FAST is configured.
- `pac`: the MS-PAC.
  - `Pac::parse` reads the buffer table as MIT checks it. There are
    readers for the logon info (`KERB_VALIDATION_INFO`, NDR-decoded: user
    and group SIDs, extra and resource-group SIDs, logon details), client
    info, UPN/DNS info, delegation info, attributes and the requestor SID.
  - The server, KDC and full signatures are verified, with HMAC-MD5 under
    any key, as for RC4, or AES. `verify_ticket_signature` and
    `verify_ticket` check a ticket the way MIT's `krb5_kdc_verify_ticket`
    does, re-encoding the ticket for its ticket signature. Like MIT 1.21,
    a service ticket's PAC must carry the full signature, which KDCs
    before MIT 1.21 and Windows' November 2022 update don't add.
  - Tested against PACs from Windows Server 2003, 2008, 2019 and 2022
    (MIT's `t_pac.c` and `t_ndr.c` fixtures, with impacket's decoding as
    the reference) and from MIT's KDC.
- `KerberosContext::pac`: the ticket's PAC. As in MIT's acceptor, it is
  kept only when its server signature and client info verify. One that
  fails is dropped, and authentication still succeeds.

### Changed

- Breaking: `KerberosContext` has a new public field, `pac`, so code that
  builds one with a struct literal must set it.

### Fixed

- A TGS reply encrypted in an authenticator subkey without FAST (as for
  S4U2Self) is decrypted with the subkey, as RFC 4120 says. Before, a
  subkey always meant FAST armor.

## [0.9.0] - 2026-10-15

### Added

- `spnego`: SPNEGO (RFC 4178), the negotiation wrapper for HTTP
  `Negotiate`, SMB, LDAP SASL `GSS-SPNEGO` and Windows peers.
  `SpnegoInitiator` and `SpnegoAcceptor` are stepped like
  `gss_init_sec_context` and `gss_accept_sec_context`. The mechanism is
  Kerberos 5, under its own OID or the one Microsoft uses (which Windows
  lists first). The state machine is MIT's: an optimistic Kerberos token,
  and `mechListMIC`s exchanged exactly when MIT exchanges them. A MIC is
  required when the acceptor did not pick the initiator's first choice
  (`request-mic`), and is answered whenever the peer sends one. The
  acceptor also takes a bare Kerberos token, as MIT's does. `send_seq` and
  `recv_seq` give the sequence numbers the MICs leave for per-message
  tokens.
- Channel bindings (RFC 4121 §4.1.1.2): `ChannelBindings`, with
  `tls_server_end_point` (RFC 5929, hashed as the certificate's signature
  algorithm says), `tls_exporter` (RFC 9266) and `tls_unique`.
  `InitiatorContext::with_options` (`InitOptions`) sends them, and
  `KerberosContext::accept_token_with` (`AcceptOptions`) checks them as
  MIT does:
  - bindings that differ are refused (`KerberosError::BadBindings`);
  - an initiator that sent none is accepted;
  - matching bindings set `GSS_C_CHANNEL_BOUND_FLAG`.
- `GSS_C_CHANNEL_BOUND_FLAG` on the initiator adds MS-KILE's
  KERB_AP_OPTIONS_CBT to the authenticator, as MIT 1.22 does, and the
  acceptor then requires the bindings it has. MIT 1.19 to 1.21 send
  KERB_AP_OPTIONS_CBT only when `client_aware_channel_bindings` is set,
  which `Krb5Conf::client_aware_channel_bindings` reads.
- `KerberosContext` gains `initiator_seq`, `acceptor_seq` and `mech_oid`.
- The acceptor accepts tokens framed with Microsoft's Kerberos OID
  (1.2.840.48018.1.2.2), and answers in kind, as MIT does.

### Changed

- Breaking: `KerberosError` has two new variants (`BadBindings`,
  `Negotiation`), and `KerberosContext` has three new public fields.

### Fixed

- The acceptor keeps only the initiator flags MIT's acceptor keeps
  (`INITIATOR_FLAGS`, and deleg when credentials came). Before, a flag
  only an acceptor may set, such as `GSS_C_CHANNEL_BOUND_FLAG`, passed
  straight through from the initiator's checksum.

## [0.8.1] - 2026-10-15

### Added

- Ticket renewal and validation. `KdcClient::renew` renews any ticket,
  a TGT or a service ticket, with a TGS request that presents the ticket
  itself with the RENEW option, as MIT's `krb5_get_renewed_creds` does.
  `KdcClient::validate` makes a postdated ticket valid in the same way,
  with the VALIDATE option. `kinit_renew` (`kinit -R`) and
  `kinit_validate` (`kinit -v`) do the same for the TGT in a credential
  cache and leave the cache holding only the new TGT, as MIT's `kinit`
  does.
- Postdated tickets: `KdcClient::with_start_time` (`kinit -s`) asks for
  initial tickets that start later and are issued invalid.
- `Credentials::can_renew_at` and `Credentials::is_invalid`.
- AS replies are now checked against the times we asked for, as MIT's
  `verify_as_reply` checks them. A postdated ticket must start at the time
  requested, and no ticket may end after `till` or be renewable past
  `rtime`. Otherwise the reply is rejected as `KRB5_KDCREP_MODIFIED`.

### Changed

- When `renew_lifetime` is shorter than the ticket lifetime, the requested
  renewable life is raised to match the lifetime, as MIT does.

### Fixed

- A TGS reply that came back for a ticket whose server name has a single
  component no longer panics in the ok-as-delegate check.

## [0.8.0] - 2026-10-14

### Added

- `kadmin::AdminClient`: a client for MIT's `kadmind`, as `kadmin` uses it.
  ONC RPC over TCP (program 2112), authenticated and encrypted by
  RPCSEC_GSS (RFC 2203) with privacy, every reply's verifier and sealed
  sequence number checked; the kadm5 API version negotiated down from 4
  as MIT's client does. Principals: `get_principal`, `list_principals`,
  `create_principal` (password or random keys), `modify_principal`
  (`PrincipalChanges`, `attributes`), `rename_principal`,
  `delete_principal`, `change_password`, `randomize_keys`,
  `extract_keys`, `ktadd` (random or `-norandkey`); policies
  (`get/list/create/modify/delete_policy`); string attributes
  (`get_strings`, `set_string`); `privileges`. kadm5 error codes keep
  MIT's names (`Kadm5Code`). `AdminClient::admin_server` reads
  `admin_server` and `kadmind_port` from `krb5.conf`.
- `kpasswd`: `change_password` (`kpasswd`: an initial ticket for
  `kadmin/changepw` from the old password, then the new one in a
  KRB-PRIV under a fresh subkey), `change_password_with_ticket`, and RFC
  3244 `set_password` for administrators; the server's AP-REP must answer
  this request, and its result text (Active Directory's packed policy
  too) comes back on refusal. `kpasswd_server` finds the server as MIT
  does. TCP first, then UDP.
- `KdcClient::initial_ticket_with_password` / `initial_ticket_with_keytab`:
  an AS exchange for a named service (`kinit -S`), for services that take
  no TGS-issued ticket.
- Keytab writing: `Keytab::new`, `add`, `to_bytes`, `save`, and
  `Keytab::append_to` as `ktadd` appends; files created mode 0600.
- `scripts/test-kdc.sh` runs `kadmind` too (kadmin and kpasswd), with an
  admin principal and a restricted one.

### Fixed

- Keytabs: the 32-bit kvno MIT writes after the key is read, so a kvno
  above 255 is no longer taken modulo 256.

## [0.7.1] - 2026-10-14

### Added

- PKCS #12 identities (`pkinit` feature): `pkinit::Identity::from_pkcs12`,
  and `PKCS12:file.p12` in `Identity::load` / `load_with_password`, as
  `X509_user_identity` names them. The certificate for the key comes first
  and the file's other certificates go along as intermediates. Read: PBES2
  (PBKDF2 with HMAC-SHA-1/224/256/384/512, AES-128/192/256-CBC or
  3DES-CBC), the legacy PKCS #12 PBEs (SHA-1 with 3DES or RC2, as OpenSSL
  1.x, Windows and older Java write them), unencrypted bags; MACs by
  HMAC (PKCS #12 KDF) or PBMAC1 (RFC 9579), checked first, so a wrong
  password is reported as one; BER with indefinite lengths. With no
  password the empty one is tried both ways, as MIT and OpenSSL do. Adds
  RustCrypto's `des` and `rc2` to the feature (decryption only).
- `scripts/make-pkcs12-testdata.sh`; the test KDC script also writes
  alice's identity as PKCS #12, modern and legacy.

## [0.7.0] - 2026-10-14

### Added

- PKINIT, behind the new `pkinit` feature (the default build's
  dependencies are unchanged; the feature adds crypto-bigint and
  RustCrypto's `p256`, `p384` and `p521`):
  - `KdcClient::login_with_certificate` / `kinit_with_certificate`: an X.509
    certificate and its RSA or EC (P-256/384/521) key (`pkinit::Identity`,
    loaded from PEM as `X509_user_identity = FILE:cert,key` names them;
    PKCS #8, PKCS #1 or SEC1) sign the AuthPack in a CMS SignedData
    (RFC 4556), with RSA or ECDSA as MIT's client does.
  - `KdcClient::login_anonymous` / `kinit_anonymous`: anonymous PKINIT
    (RFC 8062), `kinit -n`. The session key is checked to come from the
    KDC's PA-PKINIT-KX contribution, as MIT checks it.
  - `auto_fast_armor` (`[realms]`, or `KdcClient::with_auto_fast_armor`):
    every login is FAST-armored with an anonymous PKINIT TGT.
  - Key exchange (`pkinit::DhGroup`, `KdcClient::with_pkinit_dh_group`,
    `pkinit_dh_min_bits` as MIT reads it, `P-256` and the like included):
    Diffie-Hellman over MODP groups 14 and 16, or ECDH on P-256, P-384 and
    P-521 (RFC 5349) for MIT 1.22 and later. A KDC that refuses the group
    lists the ones it takes (TD-DH-PARAMETERS) and the request is made
    again with the first stronger one, as MIT's client does. The RFC 8636
    KDFs (SHA-1/256/512) and octetstring2key; freshness tokens (RFC 8070).
  - The KDC's reply is verified: its CMS signature, its certificate's
    chain to `pkinit_anchors` (`pkinit::TrustAnchors`, `FILE:` or `DIR:`;
    validity, CA flags, key usage, path length, critical extensions;
    RSA and ECDSA signatures), its name (a PKINIT subjectAltName of
    `krbtgt/REALM@REALM`, or a dNSName in `pkinit_kdc_hostname` with the
    KDC key purpose), and its nonce. An ECDSA signature labelled
    `sha256WithRSAEncryption`, as MIT's KDC labels them before 1.22, is
    verified as ECDSA, as OpenSSL does.
  - All in pure Rust: X.509, CMS, PKCS #1 v1.5 RSA (verification compares
    the whole encoded block; signing is constant-time) and DH on
    crypto-bigint; ECDH and ECDSA on RustCrypto's NIST curves. Not
    supported yet: PKCS #11/#12 identities, revocation checking.
  - Tested live against MIT 1.20 (CI's Ubuntu package), 1.21 and 1.22
    (built from source in CI), with RSA and EC KDC keys.
- `ClientError::Pkinit`, and names for the PKINIT KDC error codes.

### Changed

- A KRB-ERROR other than PREAUTH_REQUIRED whose e-data is not METHOD-DATA
  (MIT sends some as TYPED-DATA) is reported as the KDC's error, not as a
  malformed message.

## [0.6.2] - 2026-10-14

### Added

- FAST negotiation (RFC 6806 §11), as MIT's clients do it: every AS
  request asks for the KDC's checksum over it (PA-REQ-ENC-PA-REP), which
  is verified in the reply's encrypted part when the KDC sets
  enc-pa-rep, and which says whether the KDC supports FAST.
  `KdcClient::kinit_with_password` / `kinit_with_keytab` write the TGT to
  a cache as MIT's `kinit` does, with its `fast_avail` and `pa_type`
  config entries; `CCache::fast_avail` and `CCache::set_config` read and
  write them. `KdcClient::with_fast_armor_cache` takes armor from a
  cache: armored from the first request when the cache records
  `fast_avail` for the realm, otherwise upgraded to FAST when the KDC
  offers it, and plain against a KDC that does not.

### Changed

- AS requests carry PA-REQ-ENC-PA-REP; a reply with enc-pa-rep set and no
  valid checksum over the request is refused. A KDC that rejects the
  extra PA-DATA (pre-1.7 MIT) gets one retry without it.

## [0.6.1] - 2026-10-14

### Added

- FAST (RFC 6113), as MIT's `kinit -T` uses it:
  `KdcClient::with_fast_armor` takes a TGT (a host's, from its keytab, or
  one from a cache) whose AP-REQ, with a fresh subkey, armors every AS
  request. The request body and pre-authentication travel encrypted in
  the armor key; pre-authentication is the encrypted challenge, and the
  KDC's own challenge is verified, so the KDC is authenticated too.
  Replies must carry the armored response with the request's nonce and a
  `finished` checksum over the ticket; a strengthen key, if sent, is
  applied to the reply key; errors are unwrapped from `PA-FX-ERROR` and
  cookies echoed. TGS requests from such a client are armored as MIT
  armors them, with the implicit armor of the TGT and an authenticator
  subkey, whose key (strengthened) then decrypts the reply.
- `Key::prf_plus` and `Key::cf2` (KRB-FX-CF2), checked against MIT's
  `t_cf2` vectors.

## [0.6.0] - 2026-10-14

### Added

- The `[libdefaults]` settings MIT's clients read, applied by
  `KdcClient::from_config` and `discover` (`Krb5Conf::client_defaults`):
  `default_tkt_enctypes` and `default_tgs_enctypes` (falling back to
  `permitted_enctypes`, then `DEFAULT`), `ticket_lifetime`,
  `renew_lifetime`, `forwardable` and `proxiable`, the last four also per
  realm in a `[libdefaults] REALM = { ... }` subsection.
- `config::parse_enctype_list` and `config::parse_duration`, MIT's
  enctype-list syntax (names, aliases, families, `DEFAULT`, `+`/`-`) and
  `krb5_string_to_deltat`, checked against MIT's own functions on 96
  strings (`testdata/mit-settings.tsv`, `scripts/record-mit-settings.sh`).
- `KdcClient::with_tkt_enctypes`, `with_tgs_enctypes`,
  `with_renew_lifetime`, `with_forwardable`, `with_proxiable` and
  `with_defaults`. AS requests carry the forwardable, proxiable and
  renewable options (and `rtime`) these ask for.
- `Krb5Conf::libdefault` and `ConfigError::BadValue`.
- `[libdefaults] clockskew` for the acceptor (`Krb5Conf::clockskew`,
  `KerberosContext::accept_token_with_conf`), read as MIT reads it: a
  plain integer, and the default (300) if it is not one.

- UDP, as MIT's `k5_sendto_kdc` uses it: a request of at most
  `udp_preference_limit` octets (default 1465) goes over UDP first, a
  larger one over TCP first; a pass over every KDC tries the preferred
  transport and then the other, two more passes resend over UDP, and a
  UDP reply of `KRB_ERR_RESPONSE_TOO_BIG` sends the request again over
  TCP only. `KdcClient::with_udp`, `with_udp_preference_limit`,
  `client::Transport`, `dns::locate_kdc_servers`.

- Delegation (`GSS_C_DELEG_FLAG`), as MIT's GSS-API does it:
  `KdcClient::forwarded_tgt` gets a forwarded TGT (FORWARDED, preferring
  the service session key's enctype), `InitiatorContext::new_delegating`
  sends it as a KRB-CRED in the RFC 4121 authenticator checksum, sealed in
  the ticket session key; the acceptor reads the checksum it used to skip,
  and `KerberosContext::delegated` holds the TGT (decrypted with the
  session key or subkey, or unencrypted, as MIT accepts it) and
  `KerberosContext::gss_flags` the initiator's flags.

### Changed

- `KerberosContext` has two new public fields, `gss_flags` and
  `delegated`.
- Requests go over UDP first by default (see above); `with_udp(false)`
  keeps the previous TCP-only behaviour.
- DNS lookup follows MIT's order with both transports: URI `tcp` and
  `udp` entries together, then `_udp` SRV records before `_tcp` ones, all
  kept (previously only the first transport that answered). `udp`
  entries and `_udp` targets may still be tried over TCP.
- `from_config` and `discover` apply the settings above, so a
  `krb5.conf` that sets them now changes what is asked for, and one whose
  value does not parse, or leaves no AES enctype, is an error.
- TGS requests ask again for the TGT's forwardable, proxiable,
  may-postdate and renewable flags, as MIT's do (`KDC_TKT_COMMON_MASK`).

## [0.5.0] - 2026-10-14

### Added

- Cross-realm service tickets, as MIT's `krb5_get_credentials` gets
  them: RFC 6806 referrals (canonicalize, followed realm by realm, at
  most 10 hops, loops refused), a TGT path through `[capaths]`
  intermediates when the service's realm is known (backing off to closer
  realms and chasing off-path TGTs), and the host-domain fallback realm
  when the first referral fails. `KdcClient::service_ticket` and
  `service_ticket_cached` do this; other realms' KDCs come from the
  client's `krb5.conf` and DNS, or `KdcClient::with_realm_kdcs`.
  `service_ticket_cached` reuses cached cross-realm TGTs (including
  MIT's) and stores the ones it asked for.
- `Principal::host_service` (`krb5_sname_to_principal`: realm from
  `[domain_realm]`, else the empty referral realm),
  `Principal::krbtgt_for`, `Credentials::ticket_server`,
  `KdcClient::for_realm`, `client::MAX_HOPS`.
- `ClientError::Config` and `ClientError::Referral`.
- TGS replies are checked as MIT checks them: the reply's client is the
  TGT's, the ticket and the encrypted part name the same server, and a
  server other than the one asked for is accepted only with
  canonicalize or between TGTs. A foreign realm's ok-as-delegate is
  cleared unless the TGT used had it.

### Changed

- `service_ticket` sets the canonicalize option on its first request,
  as MIT does, so a KDC may return the service's canonical name. The
  credentials keep the name as requested (as MIT stores them);
  `ticket_server()` gives the name in the ticket.

## [0.4.1] - 2026-10-14

### Added

- KDC discovery through DNS, as MIT's `locate_kdc.c` does when
  `[realms] REALM kdc` lists nothing and `dns_lookup_kdc` allows it:
  URI records at `_kerberos.REALM` (`krb5srv:...:tcp:host`), then SRV
  records at `_kerberos._tcp.REALM`, ordered by priority. Because the
  client is TCP-only, `udp` URI entries and `_kerberos._udp` SRV records
  are used over TCP when nothing else is published (ATHENA.MIT.EDU
  publishes only `_udp`). `KdcClient::from_config` and `discover` use
  it; `from_config_with_resolver` takes a resolver of the caller's.
- `dns::Resolver`, a small stub resolver (no new dependencies): the
  nameservers, `timeout:` and `attempts:` of `/etc/resolv.conf`, UDP
  with TCP retry on truncation, replies matched by ID, question and
  source.
- `KdcClient::kdcs`.
- `ConfigError::NoKdcFound` and `ConfigError::Dns`.

### Changed

- When `krb5.conf` lists no `kdc` for the realm, `KdcClient::from_config`
  and `discover` now query DNS (set `dns_lookup_kdc = false` to stop
  that), and report finding nothing as `ConfigError::NoKdcFound` rather
  than `ConfigError::NoKdcs`, which now means only that the realm's
  `kdc` entries are all unusable.

## [0.4.0] - 2026-10-14

### Added

- `krb5.conf` support (`Krb5Conf`), parsed as MIT's profile library does:
  `include`/`includedir`, final flags, quoted values, merged sections, and
  `KRB5_CONFIG` lists of files and directories. Lookups for the default
  realm, a realm's KDCs (`host`, `host:port`, `[v6]:port`) and
  `[domain_realm]` host-to-realm mapping.
- `KdcClient::from_config` and `KdcClient::discover`, which take a realm's
  KDCs from `krb5.conf`.
- Credential caches (`CCache`, `CacheName`): MIT's `FILE:` format,
  versions 1-4 read and version 4 written, and `DIR:` collections.
  Configuration entries, unknown header fields and entries with
  unsupported enctypes are kept on rewrite. Caches are replaced by an
  atomic rename rather than modified in place, so no file locking (and
  no libc) is needed. The default name is resolved as MIT does
  (`KRB5CCNAME`, `default_ccache_name` with `%{uid}`-style tokens,
  `FILE:/tmp/krb5cc_%{uid}`).
- `KdcClient::service_ticket_cached`: `kvno` against a credential cache.
- `KCM:` credential caches (Unix only), over the KCM daemon's Unix socket
  (`[libdefaults] kcm_socket`, default
  `/var/run/.heim_org.h5l.kcm-socket`). Uses MIT's `GET_CRED_LIST` and
  `REPLACE` extensions where the daemon has them (sssd-kcm) and falls back
  to the Heimdal operations where it does not. macOS's Mach-based KCM is
  not supported.
- `CacheName::resolved` and `CacheName::parse_with`.

### Changed

- **Breaking:** `ClientError` is `#[non_exhaustive]` and has new variants
  `Cache` and `NoTgt`. The new `ConfigError` and `CacheError` are
  `#[non_exhaustive]` too.

### Fixed

- `scripts/test-kdc.sh` runs under macOS's bash 3.2.

## [0.3.0] - 2026-10-14

### Changed

- **Breaking:** `kdf::string_to_key` and `Key::from_password` refuse a
  string-to-key iteration count below the enctype's default (4096 for
  17/18, 32768 for 19/20) with the new `KdfError::IterationsTooLow`, as
  MIT krb5 does. The count arrives in an unauthenticated ETYPE-INFO2, so a
  spoofed KDC could otherwise ask for one iteration and make the
  PA-ENC-TIMESTAMP a cheap offline password guess. Adding the variant is
  itself breaking for exhaustive matches on `KdfError`.
- Error messages no longer mention flint.

### Added

- The RFC 3961 PRF for enctypes 17/18 (`kdf::prf_simplified`), and
  `kdf::prf` / `Key::prf` for all four enctypes.
- MIT krb5's crypto known-answer tests (`t_decrypt`, `t_cksums`,
  `t_derive`, `t_str2key`, `t_prf`) for enctypes 17-20, run as unit tests
  from `testdata/mit-crypto.json`.

## [0.2.0] - 2026-10-13

### Added

- KDC client (`KdcClient`): AS exchange with a password or a keytab,
  PA-ENC-TIMESTAMP pre-authentication with ETYPE-INFO2 salts, TGS exchange
  for service tickets, over TCP.
- GSS-API initiator (`InitiatorContext`): the AP-REQ context token with a
  subkey, sequence number and RFC 4121 checksum, AP-REP verification
  including acceptor subkeys, and per-message tokens.
- `Key`, `Principal` and `Credentials` types.
- Tests against a live MIT KDC and MIT's GSS acceptor
  (`scripts/test-kdc.sh`, `tests/kdc.rs`).

### Fixed

- The acceptor's AP-REP encoded DER INTEGERs without their sign octet, so
  a `cusec` in 128..=255 or 32768..=65535 decoded as negative and about 1
  mutual-auth handshake in 30 failed with `KRB_AP_ERR_MUT_FAIL`.

## [0.1.0] - 2026-10-13

Initial release: the GSS-API acceptor extracted from
[flint](https://github.com/ddalton/flint)'s NFS server.

- MIT-format keytabs, with key selection by principal, enctype and kvno.
- AP-REQ validation (ticket, authenticator, clock skew, validity window,
  INVALID flag), the initiator subkey, and the AP-REP for mutual
  authentication.
- RFC 3961 n-fold and DR/DK, RFC 3962 and RFC 8009 AES enctypes.
- RFC 4121 Wrap and MIC tokens.

[Unreleased]: https://github.com/ddalton/krb5/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ddalton/krb5/compare/v0.13.1...v1.0.0
[0.13.1]: https://github.com/ddalton/krb5/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/ddalton/krb5/compare/v0.12.1...v0.13.0
[0.12.1]: https://github.com/ddalton/krb5/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/ddalton/krb5/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/ddalton/krb5/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/ddalton/krb5/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/ddalton/krb5/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/ddalton/krb5/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/ddalton/krb5/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/ddalton/krb5/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/ddalton/krb5/compare/v0.6.2...v0.7.0
[0.6.2]: https://github.com/ddalton/krb5/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/ddalton/krb5/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/ddalton/krb5/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/ddalton/krb5/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/ddalton/krb5/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ddalton/krb5/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ddalton/krb5/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ddalton/krb5/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ddalton/krb5/releases/tag/v0.1.0
