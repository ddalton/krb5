# Fuzzing

libFuzzer targets for every parser that reads what a peer sends:

| target | input |
|---|---|
| `acceptor_token` | a GSS-API initial context token, or a bare AP-REQ |
| `acceptor_inner` | what decrypts: EncTicketPart (and its PAC), Authenticator, the GSS checksum, AP options; Ticket, AP-REQ |
| `spnego` | SPNEGO tokens to the acceptor and to the initiator, AP-REPs, Wrap and MIC tokens |
| `pac` | a PAC: every reader, every signature check, a ticket's PAC |
| `kdc_message` | KDC-REP, KRB-ERROR, EncKDCRepPart, the FAST response, KRB-CRED, OTP and SPAKE challenges, PA-DATA |
| `dns` | DNS answers (SRV, URI, CNAME), resolv.conf |
| `kadmin` | kadmind's RPC replies and their XDR (principals, policies, keys, name lists) |
| `kpasswd` | a kpasswd server's reply, its KRB-PRIV, the result |
| `pkinit` | X.509 certificates and chains, PEM, PKCS #12, CMS SignedData, RSA/EC/DH keys, PA-PK-AS-REP |
| `ccache`, `keytab`, `text` | credential caches, keytabs, krb5.conf, principal and cache names |

Most targets take a first octet that picks the parser for the rest. The
entry points are in `src/**/fuzz.rs`, built only with `--cfg fuzzing` (as
`cargo fuzz` builds) or for tests. Parsers that only ever see decrypted data
are reached by encrypting the input in a known key first.

## Running

```sh
cargo install cargo-fuzz
fuzz/seed.py                        # seed fuzz/corpus/ from testdata/
cargo +nightly fuzz run -O acceptor_token -- -max_total_time=600
```

On macOS with only the Command Line Tools, libFuzzer's C++ needs the SDK:

```sh
export CXXFLAGS="-isysroot $(xcrun --show-sdk-path) -I$(xcrun --show-sdk-path)/usr/include/c++/v1"
```

`cargo test --lib -- --ignored fuzz_seeds` adds the decrypted tickets and
authenticators of MIT's recorded AP-REQs to `acceptor_inner`'s corpus.
`fuzz/capture-kdc.py` sits in front of a KDC (`scripts/test-kdc.sh`) and
records its replies; `fuzz/seed.py <dir>` adds them to `kdc_message`'s.

## Regressions

Every input a fuzzer has crashed on is kept in `testdata/fuzz/<target>/`,
and `cargo test` replays them all through their targets
(`fuzz::fuzz_regressions`).
