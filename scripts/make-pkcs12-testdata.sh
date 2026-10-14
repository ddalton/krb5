#!/usr/bin/env bash
# Make the PKCS #12 files src/pkinit's tests read, from the certificates
# and keys make-pkinit-testdata.sh made:
#
#   scripts/make-pkcs12-testdata.sh src/pkinit/testdata
#
# Each holds kdc.pem (with inter.pem) and kdc-key.pem, password "secret"
# unless named otherwise, encrypted as some tool writes them:
#
# modern.p12   OpenSSL 3's default: PBES2, PBKDF2-HMAC-SHA256, AES-256-CBC;
#              MAC HMAC-SHA-256
# legacy.p12   OpenSSL 1.x / Windows / old Java: certificates in 40-bit RC2,
#              the key in 3DES (PKCS #12 PBEs); MAC HMAC-SHA-1
# pbes2-3des.p12 PBES2 with 3DES-CBC and PBKDF2-HMAC-SHA1, MAC SHA-1
# pbmac1.p12   PBES2/AES, MAC PBMAC1 (RFC 9579; OpenSSL 3.4+)
# ec.p12       ec-kdc.pem and its P-256 key, OpenSSL 3's default
# nopass.p12   the empty password
# plain.p12    nothing encrypted, no MAC
set -euo pipefail
cd "$1"
p12() { openssl pkcs12 -export -in kdc.pem -inkey kdc-key.pem -certfile inter.pem "$@"; }
p12 -passout pass:secret -out modern.p12
p12 -legacy -passout pass:secret -out legacy.p12
p12 -keypbe DES-EDE3-CBC -certpbe DES-EDE3-CBC -macalg sha1 -passout pass:secret -out pbes2-3des.p12
p12 -pbmac1_pbkdf2 -passout pass:secret -out pbmac1.p12
openssl pkcs12 -export -in ec-kdc.pem -inkey ec-kdc-key.pem -passout pass:secret -out ec.p12
p12 -passout pass: -out nopass.p12
p12 -keypbe NONE -certpbe NONE -nomac -passout pass: -out plain.p12
