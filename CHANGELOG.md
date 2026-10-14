# Changelog

All notable changes to this crate. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
follows [Semantic Versioning](https://semver.org/) (pre-1.0: a minor bump
may break the API).

## [Unreleased]

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

[Unreleased]: https://github.com/ddalton/krb5/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/ddalton/krb5/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ddalton/krb5/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ddalton/krb5/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ddalton/krb5/releases/tag/v0.1.0
