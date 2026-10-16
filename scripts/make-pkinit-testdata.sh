#!/usr/bin/env bash
# Make the certificates src/pkinit's unit tests use:
#
#   scripts/make-pkinit-testdata.sh src/pkinit/testdata
#
# ca.pem        root CA (key: rsa2048.pem, the RSA tests' key)
# inter.pem     intermediate CA under ca, pathlen 0
# kdc.pem       KDC certificate under inter: PKINIT SAN krbtgt/TEST.REALM@TEST.REALM,
#               id-pkinit-KPKdc, digitalSignature; key kdc-key.pem
# host.pem      certificate under inter with only a dNSName (kdc.test.realm),
#               id-pkinit-KPKdc and digitalSignature; key kdc-key.pem
# leafsigned.pem a "CA" signed by kdc.pem's key, which is not a CA
# sub.pem       a CA under inter, beyond inter's path length; subleaf.pem under it
# ca-crl.pem    ca's CRL as OpenSSL writes one (CRL number, authorityKeyIdentifier),
#               revoking inter.pem (keyCompromise), current 2026-2126
# other-ca.pem  an unrelated root
# ec-ca.pem     a P-384 root; ec-kdc.pem, a P-256 KDC certificate under it
#               (as kdc.pem, ECDSA throughout), key ec-kdc-key.pem (SEC1)
#
# All are valid from when they are made for a century; the tests check
# them at a fixed time inside that window.
set -euo pipefail
out=$1
mkdir -p "$out"
cd "$out"
o() { openssl "$@" 2>/dev/null; }
cat >ext.cnf <<'EXT'
[inter]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
[kdc]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.5
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name
[kdc_princ_name]
realm=EXP:0,GeneralString:TEST.REALM
principal_name=EXP:1,SEQUENCE:kdc_principal_seq
[kdc_principal_seq]
name_type=EXP:0,INTEGER:2
name_string=EXP:1,SEQUENCE:kdc_principals
[kdc_principals]
princ1=GeneralString:krbtgt
princ2=GeneralString:TEST.REALM
[host]
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=1.3.6.1.5.2.3.5
subjectAltName=DNS:kdc.test.realm
[fake_ca]
basicConstraints=critical,CA:TRUE
EXT
o req -x509 -new -key rsa2048.pem -out ca.pem -days 36500 -subj "/CN=PKINIT Test Root" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
o genrsa -out inter-key.pem 2048
o req -new -key inter-key.pem -out inter.req -subj "/CN=PKINIT Test Intermediate"
o x509 -req -in inter.req -CA ca.pem -CAkey rsa2048.pem -set_serial 2 -out inter.pem \
    -days 36500 -extfile ext.cnf -extensions inter
o genrsa -out kdc-key.pem 2048
o req -new -key kdc-key.pem -out kdc.req -subj "/CN=kdc"
o x509 -req -in kdc.req -CA inter.pem -CAkey inter-key.pem -set_serial 3 -out kdc.pem \
    -days 36500 -extfile ext.cnf -extensions kdc
o x509 -req -in kdc.req -CA inter.pem -CAkey inter-key.pem -set_serial 4 -out host.pem \
    -days 36500 -extfile ext.cnf -extensions host
o req -new -key inter-key.pem -out fake.req -subj "/CN=Not A CA"
o x509 -req -in fake.req -CA kdc.pem -CAkey kdc-key.pem -set_serial 5 -out leafsigned.pem \
    -days 36500 -extfile ext.cnf -extensions fake_ca
o req -new -key inter-key.pem -out sub.req -subj "/CN=PKINIT Test Sub-CA"
o x509 -req -in sub.req -CA inter.pem -CAkey inter-key.pem -set_serial 6 -out sub.pem \
    -days 36500 -extfile ext.cnf -extensions fake_ca
o x509 -req -in kdc.req -CA sub.pem -CAkey inter-key.pem -set_serial 7 -out subleaf.pem \
    -days 36500 -extfile ext.cnf -extensions kdc
cat >ca.cnf <<CA
[ca]
default_ca = d
[d]
database = index.txt
crlnumber = crlnumber
default_md = sha256
crl_extensions = crl_ext
[crl_ext]
authorityKeyIdentifier = keyid:always
CA
touch index.txt
echo 01 >crlnumber
o ca -config ca.cnf -revoke inter.pem -cert ca.pem -keyfile rsa2048.pem -crl_reason keyCompromise
o ca -config ca.cnf -gencrl -cert ca.pem -keyfile rsa2048.pem -out ca-crl.pem \
    -crl_lastupdate 20260101000000Z -crl_nextupdate 21260101000000Z
rm -f ca.cnf index.txt* crlnumber*
o genrsa -out other-key.pem 2048
o req -x509 -new -key other-key.pem -out other-ca.pem -days 36500 -subj "/CN=PKINIT Test Root" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
o ecparam -name secp384r1 -genkey -noout -out ec-ca-key.pem
o req -x509 -new -key ec-ca-key.pem -out ec-ca.pem -days 36500 -subj "/CN=PKINIT Test EC Root" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
o ecparam -name prime256v1 -genkey -noout -out ec-kdc-key.pem
o req -new -key ec-kdc-key.pem -out ec-kdc.req -subj "/CN=ec-kdc"
o x509 -req -in ec-kdc.req -CA ec-ca.pem -CAkey ec-ca-key.pem -set_serial 8 -out ec-kdc.pem \
    -days 36500 -sha384 -extfile ext.cnf -extensions kdc
rm -f ec-ca-key.pem ext.cnf ./*.req inter-key.pem other-key.pem ./*.srl
