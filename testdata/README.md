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
| `interop-mutual.json` | yes | the initiator is not complete until it has flint's AP-REP, so these pin the AP-REP path |

Both cover all four AES enctypes (17/18/19/20). Note the KDC picks a
session-key enctype that may differ from the ticket enctype — the
fixtures exercise that mismatch, which is worth keeping.

## Regenerating

Needs a KDC. The scripts that built this realm are recorded in the
project memory for this work; the shape is:

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
