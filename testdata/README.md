# Kerberos interop fixtures

Recorded from a **live MIT KDC** on 2026-08-27 and consumed by
`src/interop.rs`. They are what makes the interop tests interop tests
rather than round-trips: MIT produced every byte here, this crate only
consumes it.

## `interop.keytab` — yes, this is a keytab, and yes it is safe to publish

It belongs to a **disposable test realm** (`FLINT.TEST`) whose KDC lived
in a throwaway Lima VM and no longer exists. The keys are random, were
never used for anything, and authenticate nothing anywhere. It is
committed for the same reason MIT krb5 ships test keytabs in its own
tree: without it the fixture tickets cannot be decrypted and the tests
cannot run.

Do not add a keytab here that belongs to any realm you care about.

## The two fixture sets

| file | AP-REQ asked for mutual auth? | what it pins |
|---|---|---|
| `interop.json` | no | context completes in one step, so these carry MIC and Wrap tokens — and the acceptor must reply with **no** AP-REP |
| `interop-mutual.json` | yes | the initiator is not complete until it has this crate's AP-REP, so these pin the AP-REP path |

Both cover all four AES enctypes (17/18/19/20). Note the KDC picks a
session-key enctype that may differ from the ticket enctype — the
fixtures exercise that mismatch, which is worth keeping.

## Regenerating

Needs a KDC. `scripts/test-kdc.sh` builds a suitable realm (it already
creates one `svcNN/svc.krb5.test` principal per enctype in
`service.keytab`), though under `KRB5.TEST` rather than `FLINT.TEST`. The
script that drove `python3-gssapi` to record the tokens was never
committed; the shape is:

1. `kdb5_util create -s -r FLINT.TEST`
2. one service principal **per enctype**, each with `addprinc -e <enctype>`
3. `ktadd -k interop.keytab` for each
4. `python3-gssapi` as the initiator, `MUTUAL=1` and `MUTUAL=0`, no
   mutual auth meaning the context completes on the first step

⚠ Give each enctype its **own** principal only for these fixtures. A real
keytab holds one key per enctype for the *same* principal, and that
difference hid a shipped bug: `find_key` matched on principal name alone
and picked an arbitrary enctype. See
`a_multi_enctype_keytab_selects_by_the_tickets_enctype` in `src/acceptor.rs`.

The authenticators in these fixtures are frozen in time, so the tests use
`accept_token_with_skew`. Production keeps the 5-minute default.

## `mit-crypto.json` — MIT krb5's crypto known-answer tests

The enctype 17-20 entries of the tables in MIT krb5's
`src/lib/crypto/crypto_tests/` (`t_decrypt.c`, `t_cksums.c`,
`t_derive.c`, `t_str2key.c`, `t_prf.c`), consumed by
`src/mit_vectors.rs`. The file records the MIT commit it came from;
`MIT-KRB5-NOTICE` carries the source files' copyright notices.

Regenerate from a krb5 checkout with:

```sh
scripts/import-mit-vectors.py <krb5>/src/lib/crypto/crypto_tests <commit> > testdata/mit-crypto.json
```

The script only reformats: every value is MIT's.

## `ccache/` — credential caches written by MIT krb5

`mit-v1.ccache` to `mit-v4.ccache` were written by MIT's `kinit` and
`kvno` in each file format version (`ccache_type = 1..4`), each holding a
TGT, a service ticket and MIT's `fast_avail` / `pa_type` config entries;
`mit-vN.klist` is `klist -e -f` of each. Consumed by `src/ccache.rs`, whose
tests include re-encoding `mit-v4.ccache` octet for octet. Like the
keytab, the keys belong to a throwaway realm.

Regenerate against a realm from `scripts/test-kdc.sh`:

```sh
scripts/make-ccache-fixtures.sh /tmp/krb5test testdata/ccache
```

## `dns/` — DNS replies recorded from a real resolver

Raw replies to SRV and URI queries for public realms' Kerberos records
(ATHENA.MIT.EDU, FEDORAPROJECT.ORG, DEMO1.FREEIPA.ORG) and an NXDOMAIN,
each beginning with its query ID. Consumed by `src/dns.rs`, whose tests
parse them and replay them through a fake nameserver. Recorded with:

```sh
scripts/record-dns-fixtures.py testdata/dns [nameserver]
```

The script builds its queries itself, so the fixtures do not depend on the
Rust encoder they are used to test.

## `mit-settings.tsv` — MIT's reading of durations and enctype lists

Each line is an input (`D` for a `ticket_lifetime`-style duration, `E` for
a `permitted_enctypes`-style list), a tab, and what MIT krb5's own
`krb5_string_to_deltat` or `krb5int_parse_enctype_list` made of it:
seconds, enctype numbers, or `ERR`. `src/config.rs` must agree on every
line. Recorded by compiling `scripts/record-mit-settings.c` against MIT's
libkrb5; MIT 1.20 (Ubuntu) and 1.21 (Homebrew) give identical output:

```sh
scripts/record-mit-settings.sh [path/to/krb5-config]
```

## `pac/` — PACs from Windows KDCs

Copied, byte for byte, from MIT krb5 1.22.2's own tests (their files'
licences, KTH's and Red Hat's, are in `MIT-KRB5-NOTICE`):

- from `src/lib/krb5/krb/t_pac.c`:
  - `saved_pac.bin`: Samba's torture PAC, from Windows Server 2003, signed
    with RC4 keys;
  - the four `s4u_pac_*.bin`: S4U2Self PACs from Windows Server 2008;
  - `w2022_ticket.der`: a ticket issued by Windows Server 2022, with a
    full PAC.

  The keys are in `t_pac.c` and in `src/pac/tests.rs`.
  `w2022_pac.bin` is that ticket's PAC, decrypted out of it.
- from `src/kdc/t_ndr.c`:
  - `s4u_di_*.bin`: S4U_DELEGATION_INFO buffers from Active Directory
    2019;
  - `ndr_fuzz*.bin`: two buffers MIT's fuzzer found.

The expected field values in `src/pac/tests.rs` are what impacket 0.12.0
(`impacket.krb5.pac`) decodes from the same bytes.
