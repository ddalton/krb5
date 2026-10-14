# Changelog

All notable changes to this crate. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
follows [Semantic Versioning](https://semver.org/) (pre-1.0: a minor bump
may break the API).

## [Unreleased]

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

[Unreleased]: https://github.com/ddalton/krb5/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/ddalton/krb5/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/ddalton/krb5/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/ddalton/krb5/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/ddalton/krb5/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ddalton/krb5/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ddalton/krb5/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ddalton/krb5/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ddalton/krb5/releases/tag/v0.1.0
