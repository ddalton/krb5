#!/usr/bin/env bash
# Start a throwaway MIT KDC for the live integration tests (tests/kdc.rs).
#
#   scripts/test-kdc.sh <dir> [port]
#
# Runs unprivileged: the realm, database, keytabs and log all live in
# <dir>, and the KDC listens on <port> (default 18888, TCP and UDP), so it
# can sit next to a system KDC without touching it. Needs MIT krb5's
# krb5kdc, kdb5_util and kadmin.local (Debian/Ubuntu: krb5-kdc
# krb5-admin-server).
#
# Two more realms are served by the same KDC for the cross-realm tests:
# CROSS.TEST, which KRB5.TEST trusts directly, and FAR.TEST, which is
# reached through CROSS.TEST ([capaths]). Hosts under .cross.test and
# .far.test map to them ([domain_realm]), which is what makes the KDC
# answer a host-based request with a referral.
#
# If openssl is installed and MIT's PKINIT plugin is present (Debian:
# krb5-pkinit), KRB5.TEST and CROSS.TEST also do PKINIT: a CA, a KDC
# certificate naming both realms, client certificates for alice (RSA, and
# P-256 in pki/alice-ec.pem) made as MIT's PKINIT guide makes them, and
# WELLKNOWN/ANONYMOUS for anonymous PKINIT. CROSS.TEST's KDC wants a
# stronger group than the default (pkinit_dh_min_bits 4096, or P-384 where
# the KDC has ECDH), so clients must negotiate. KRB5_TEST_PKINIT=1 then,
# and KRB5_TEST_PKINIT_ECDH=1 for an MIT 1.22+ KDC. With
# KRB5_TEST_PKINIT_EC_KDC=1 in the environment the KDC's key is P-256.
#
# kadmind serves KRB5.TEST on the next port (kadmin) and the one after
# (kpasswd), with admin/admin (password adminpw) allowed everything,
# extracting keys included, and limited (limitedpw) only to inquire and
# list. The KDC offers SPAKE (edwards25519, P-256 and P-384) alongside
# encrypted timestamps. Where MIT's otp plugin is installed, otpuser's KDC wants a
# one-time password, which a RADIUS server (scripts/radius-test.py) on the
# port after kpasswd's checks: 424242 is right. KRB5_TEST_OTP=1 then.
# kdc.pid holds the daemons' process IDs.
#
# Writes <dir>/test.env with the KRB5_TEST_* variables the tests read.
# The keys are random and the passwords are fixed strings: nothing here
# protects anything.
set -euo pipefail

DIR=$(mkdir -p "$1" && cd "$1" && pwd)
PORT=${2:-18888}
KADMIN_PORT=$((PORT + 1))
KPASSWD_PORT=$((PORT + 2))
REALM=${KRB5_TEST_REALM:-KRB5.TEST}
XREALM=CROSS.TEST
FREALM=FAR.TEST
HOST=${KRB5_TEST_HOST:-127.0.0.1}
PATH=$PATH:/usr/sbin:/usr/local/sbin

if [ -f "$DIR/kdc.pid" ]; then kill $(cat "$DIR/kdc.pid") 2>/dev/null || true; fi
rm -rf "${DIR:?}"/*

ENCTYPES="aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128"

cat >"$DIR/krb5.conf" <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    permitted_enctypes = $ENCTYPES
[realms]
    $REALM = {
        kdc = 127.0.0.1:$PORT
        admin_server = 127.0.0.1:$KADMIN_PORT
        kpasswd_server = 127.0.0.1:$KPASSWD_PORT
    }
    $XREALM = {
        kdc = 127.0.0.1:$PORT
    }
    $FREALM = {
        kdc = 127.0.0.1:$PORT
    }
[domain_realm]
    .cross.test = $XREALM
    .far.test = $FREALM
[capaths]
    $REALM = {
        $FREALM = $XREALM
    }
    $FREALM = {
        $REALM = $XREALM
    }
EOF

# S4U2Proxy needs delegation rules, which MIT's DB2 module cannot hold: a
# fourth realm on MIT's test KDB module (built with MIT, not installed by
# make install or packaged) when it is there.
S4UREALM=
KDCBIN=$(command -v krb5kdc || true)
for p in "${KDCBIN%/sbin/krb5kdc}/lib/krb5/plugins/kdb/test.so" /usr/lib/*/krb5/plugins/kdb/test.so; do
    if [ -f "$p" ]; then S4UREALM=S4U.TEST; fi
done
if [ -n "$S4UREALM" ]; then
    cat >>"$DIR/krb5.conf" <<EOF
[realms]
    $S4UREALM = {
        kdc = 127.0.0.1:$PORT
    }
EOF
fi

# PKINIT: on when openssl and MIT's pkinit plugin are both there.
PKINIT=
for p in "${KDCBIN%/sbin/krb5kdc}/lib/krb5/plugins/preauth/pkinit.so" \
         /usr/lib/*/krb5/plugins/preauth/pkinit.so /usr/lib*/krb5/plugins/preauth/pkinit.so; do
    if [ -f "$p" ] && command -v openssl >/dev/null; then PKINIT=1; fi
done
# OTP (RFC 6560): MIT's otp preauth plugin, checking codes with a RADIUS
# server (scripts/radius-test.py, which takes 424242) on the port after
# kpasswd's.
OTP=
RADIUS_PORT=$((PORT + 3))
for p in "${KDCBIN%/sbin/krb5kdc}/lib/krb5/plugins/preauth/otp.so" \
         /usr/lib/*/krb5/plugins/preauth/otp.so /usr/lib*/krb5/plugins/preauth/otp.so; do
    if [ -f "$p" ] && command -v python3 >/dev/null; then OTP=1; fi
done
# ECDH: MIT 1.22 and later.
ECDH=
if [ -n "$PKINIT" ]; then
    KLIST="${KDCBIN%/sbin/krb5kdc}/bin/klist"
    [ -x "$KLIST" ] || KLIST=klist
    v=$("$KLIST" -V 2>/dev/null | sed -n 's/^Kerberos 5 version \([0-9]*\)\.\([0-9]*\).*/\1 \2/p')
    if [ -n "$v" ] && [ "${v% *}" -ge 1 ] && { [ "${v% *}" -gt 1 ] || [ "${v#* }" -ge 22 ]; }; then
        ECDH=1
    fi
fi
if [ -n "$PKINIT" ]; then
    P="$DIR/pki"
    mkdir -p "$P"
    cat >"$P/ext.cnf" <<EXT
[kdc_cert]
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.5
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name,otherName:1.3.6.1.5.2.2;SEQUENCE:xkdc_princ_name
[kdc_princ_name]
realm=EXP:0,GeneralString:$REALM
principal_name=EXP:1,SEQUENCE:kdc_principal_seq
[kdc_principal_seq]
name_type=EXP:0,INTEGER:2
name_string=EXP:1,SEQUENCE:kdc_principals
[kdc_principals]
princ1=GeneralString:krbtgt
princ2=GeneralString:$REALM
[xkdc_princ_name]
realm=EXP:0,GeneralString:$XREALM
principal_name=EXP:1,SEQUENCE:xkdc_principal_seq
[xkdc_principal_seq]
name_type=EXP:0,INTEGER:2
name_string=EXP:1,SEQUENCE:xkdc_principals
[xkdc_principals]
princ1=GeneralString:krbtgt
princ2=GeneralString:$XREALM
[client_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.4
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name
[princ_name]
realm=EXP:0,GeneralString:$REALM
principal_name=EXP:1,SEQUENCE:principal_seq
[principal_seq]
name_type=EXP:0,INTEGER:1
name_string=EXP:1,SEQUENCE:principals
[principals]
princ1=GeneralString:alice
EXT
    o() { openssl "$@" 2>/dev/null; }
    o req -x509 -newkey rsa:2048 -nodes -keyout "$P/ca-key.pem" -out "$P/ca.pem" \
        -days 3650 -subj "/CN=Test PKINIT CA"
    if [ -n "${KRB5_TEST_PKINIT_EC_KDC:-}" ]; then
        kdckey=(-newkey ec -pkeyopt ec_paramgen_curve:P-256)
    else
        kdckey=(-newkey rsa:2048)
    fi
    o req "${kdckey[@]}" -nodes -keyout "$P/kdc-key.pem" -out "$P/kdc.req" -subj "/CN=kdc"
    o x509 -req -in "$P/kdc.req" -CA "$P/ca.pem" -CAkey "$P/ca-key.pem" \
        -CAcreateserial -out "$P/kdc.pem" -days 365 -extfile "$P/ext.cnf" -extensions kdc_cert
    o req -newkey rsa:2048 -nodes -keyout "$P/alice-key.pem" -out "$P/alice.req" -subj "/CN=alice"
    o x509 -req -in "$P/alice.req" -CA "$P/ca.pem" -CAkey "$P/ca-key.pem" \
        -CAcreateserial -out "$P/alice.pem" -days 365 -extfile "$P/ext.cnf" -extensions client_cert
    o req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$P/alice-ec-key.pem" \
        -out "$P/alice-ec.req" -subj "/CN=alice"
    o x509 -req -in "$P/alice-ec.req" -CA "$P/ca.pem" -CAkey "$P/ca-key.pem" \
        -CAcreateserial -out "$P/alice-ec.pem" -days 365 -extfile "$P/ext.cnf" -extensions client_cert
    # alice's certificate and key as PKCS #12, pass phrase "alicep12":
    # OpenSSL 3's default encryption, and (where OpenSSL has its legacy
    # provider) the RC2/3DES of older tools.
    o pkcs12 -export -in "$P/alice.pem" -inkey "$P/alice-key.pem" -certfile "$P/ca.pem" \
        -passout pass:alicep12 -out "$P/alice.p12"
    o pkcs12 -export -legacy -in "$P/alice.pem" -inkey "$P/alice-key.pem" \
        -passout pass:alicep12 -out "$P/alice-legacy.p12" || rm -f "$P/alice-legacy.p12"
    cat >>"$DIR/krb5.conf" <<EOF
[realms]
    $REALM = {
        pkinit_anchors = FILE:$P/ca.pem
    }
    $XREALM = {
        pkinit_anchors = FILE:$P/ca.pem
    }
EOF
fi

# The PKINIT lines of a realm's kdc.conf entry.
pkinit_kdc_conf() {
    [ -n "$PKINIT" ] || return 0
    case $1 in
        "$REALM" | "$XREALM") ;;
        *) return 0 ;;
    esac
    printf '        pkinit_identity = FILE:%s/pki/kdc.pem,%s/pki/kdc-key.pem\n' "$DIR" "$DIR"
    printf '        pkinit_anchors = FILE:%s/pki/ca.pem\n' "$DIR"
    if [ "$1" = "$XREALM" ]; then
        printf '        pkinit_dh_min_bits = %s\n' "$([ -n "$ECDH" ] && echo P-384 || echo 4096)"
    fi
}

cat >"$DIR/kdc.conf" <<EOF
[libdefaults]
    # SPAKE pre-authentication, as MIT deploys it: no optimistic challenge,
    # the client's support message first. P-521 is left out so a client
    # offering only it falls back to encrypted timestamps.
    spake_preauth_groups = edwards25519 P-256 P-384
[kdcdefaults]
    kdc_ports = $PORT
    kdc_tcp_ports = $PORT
[realms]
$(for r in $REALM $XREALM $FREALM; do cat <<REALM
    $r = {
        database_name = $DIR/principal.$r
        key_stash_file = $DIR/stash.$r
        acl_file = $DIR/kadm5.acl
        supported_enctypes = $(for e in $ENCTYPES; do printf '%s:normal ' "$e"; done)
        default_principal_flags = +preauth
        max_life = 1d
        max_renewable_life = 7d
        kadmind_port = $KADMIN_PORT
        kpasswd_port = $KPASSWD_PORT
$(pkinit_kdc_conf "$r")
    }
REALM
done)
$(if [ -n "$S4UREALM" ]; then cat <<S4U
    $S4UREALM = {
        database_module = s4u
        supported_enctypes = aes256-cts-hmac-sha1-96:normal
        max_life = 1d
        max_renewable_life = 7d
    }
[dbmodules]
    # proxy may delegate to target (traditional constrained delegation,
    # and protocol transition); constrained may too, but without protocol
    # transition; rb accepts delegation from impersonator (resource-based);
    # sensitive may not be delegated at all.
    s4u = {
        db_library = test
        princs = {
            krbtgt/$S4UREALM = {
                keys = aes256-cts
            }
            user = {
                keys = aes256-cts
            }
            sensitive = {
                keys = aes256-cts
                flags = +disallow_forwardable
            }
            proxy = {
                keys = aes256-cts
                flags = +ok-to-auth-as-delegate
            }
            constrained = {
                keys = aes256-cts
            }
            target = {
                keys = aes256-cts
            }
            impersonator = {
                keys = aes256-cts
            }
            rb = {
                keys = aes256-cts
            }
        }
        delegation = {
            proxy = target
            constrained = target
        }
        rbcd = {
            rb@$S4UREALM = impersonator@$S4UREALM
        }
    }
S4U
fi)
$(if [ -n "$OTP" ]; then cat <<OTPCONF
[otp]
    radius = {
        server = 127.0.0.1:$RADIUS_PORT
        secret = $DIR/radius.secret
        timeout = 2
    }
OTPCONF
fi)
[logging]
    kdc = FILE:$DIR/kdc.log
EOF
cat >"$DIR/kadm5.acl" <<EOF
admin/admin@$REALM admcilmpse
limited@$REALM il
EOF

export KRB5_CONFIG=$DIR/krb5.conf KRB5_KDC_PROFILE=$DIR/kdc.conf
for r in $REALM $XREALM $FREALM; do
    kdb5_util create -s -r "$r" -P masterpw >/dev/null
done
# kadmin.local exits 0 even when a query fails, so check what it printed.
# kr REALM query..., or k query... for the main realm.
kr() {
    local out realm=$1
    shift
    out=$(kadmin.local -r "$realm" -q "$*" 2>&1)
    if grep -qiE 'error|cannot|failed|usage' <<<"$out"; then
        echo "kadmin.local -r $realm -q '$*' failed:" >&2; echo "$out" >&2; exit 1
    fi
}
k() { kr "$REALM" "$@"; }

# Password principals: one with every enctype (the KDC picks), one that
# does not require pre-authentication, and one per enctype so each
# string-to-key path is exercised.
k addprinc -pw alicepw alice
k addprinc -pw adminpw admin/admin
k addprinc -pw limitedpw limited
k addprinc -pw bobpw -requires_preauth bob
# A function, not $(case ...): bash 3.2 (macOS) cannot parse ;; inside $().
enctype_number() {
    case $1 in
        aes128-cts-hmac-sha1-96) echo 17 ;; aes256-cts-hmac-sha1-96) echo 18 ;;
        aes128-cts-hmac-sha256-128) echo 19 ;; aes256-cts-hmac-sha384-192) echo 20 ;;
    esac
}
for e in $ENCTYPES; do
    n=$(enctype_number "$e")
    k addprinc -pw "pw$n" -e "$e:normal" "u$n"
    k addprinc -randkey -e "$e:normal" "svc$n/svc.krb5.test"
    k ktadd -k "$DIR/service.keytab" -e "$e:normal" "svc$n/svc.krb5.test"
done

# A service with every enctype, and a keytab-only client.
k addprinc -randkey host/svc.krb5.test
k ktadd -k "$DIR/service.keytab" host/svc.krb5.test
k addprinc -randkey robot
k ktadd -k "$DIR/robot.keytab" robot
# A service that may act for users (S4U2Self giving forwardable tickets).
k addprinc -randkey +ok_to_auth_as_delegate s4u/svc.krb5.test
k ktadd -k "$DIR/service.keytab" s4u/svc.krb5.test
# A user whose KDC wants a one-time password (checked by RADIUS).
if [ -n "$OTP" ]; then
    k addprinc -pw otpuserpw +requires_preauth otpuser
    out=$(kadmin.local -r "$REALM" setstr otpuser otp '[{"type": "radius"}]' 2>&1)
    if [ -n "$out" ]; then echo "setstr otp: $out" >&2; exit 1; fi
fi
# The realm's krbtgt key, for checking the KDC's PAC signatures.
# (lockdown_keys keeps it from kadmind, not from kadmin.local.)
k ktadd -norandkey -k "$DIR/krbtgt.keytab" "krbtgt/$REALM"

if [ -n "$PKINIT" ]; then
    k addprinc -randkey WELLKNOWN/ANONYMOUS
    kr "$XREALM" addprinc -randkey WELLKNOWN/ANONYMOUS
fi

# Cross-realm trust: the same krbtgt/B@A, with the same password (so the
# same keys), in both realms' databases.
trust() {
    kr "$1" addprinc -pw "trust-$2-$1" "krbtgt/$2@$1"
    kr "$2" addprinc -pw "trust-$2-$1" "krbtgt/$2@$1"
}
trust "$REALM" "$XREALM"
trust "$XREALM" "$FREALM"
kr "$XREALM" addprinc -randkey host/server.cross.test
kr "$XREALM" ktadd -k "$DIR/cross.keytab" host/server.cross.test
kr "$FREALM" addprinc -randkey host/server.far.test
kr "$FREALM" ktadd -k "$DIR/far.keytab" host/server.far.test
kr "$FREALM" addprinc -randkey host/other.far.test
kr "$FREALM" ktadd -k "$DIR/far.keytab" host/other.far.test

if [ -n "$S4UREALM" ]; then
    # The test module derives every key from the principal's name; read
    # them out as MIT's own tests do.
    kr "$S4UREALM" ktadd -norandkey -k "$DIR/s4u.keytab" user sensitive proxy constrained target impersonator rb "krbtgt/$S4UREALM"
fi

if [ -n "$OTP" ]; then
    echo otptest >"$DIR/radius.secret"
    : >"$DIR/radius.log"
    python3 "$(dirname "$0")/radius-test.py" "$RADIUS_PORT" "$DIR/radius.secret" \
        "$DIR/radius.log" 424242 >"$DIR/radius.out" 2>&1 &
    RADIUS_PID=$!
fi
krb5kdc -n -r "$REALM" -r "$XREALM" -r "$FREALM" ${S4UREALM:+-r "$S4UREALM"} >"$DIR/kdc.out" 2>&1 &
echo $! >"$DIR/kdc.pid"
kadmind -nofork -r "$REALM" >"$DIR/kadmind.out" 2>&1 &
echo $! >>"$DIR/kdc.pid"
if [ -n "$OTP" ]; then echo "$RADIUS_PID" >>"$DIR/kdc.pid"; fi
for p in "$PORT" "$KADMIN_PORT" "$KPASSWD_PORT"; do
    for _ in $(seq 50); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then break; fi
        sleep 0.1
    done
done

cat >"$DIR/test.env" <<EOF
KRB5_TEST_KDC=$HOST:$PORT
KRB5_TEST_REALM=$REALM
KRB5_TEST_DIR=$DIR
KRB5_TEST_CROSS_REALMS="$XREALM $FREALM"
KRB5_TEST_PKINIT=$PKINIT
KRB5_TEST_PKINIT_ECDH=$ECDH
KRB5_TEST_KADMIN=$HOST:$KADMIN_PORT
KRB5_TEST_KPASSWD=$HOST:$KPASSWD_PORT
KRB5_TEST_S4U_REALM=$S4UREALM
KRB5_TEST_OTP=$OTP
EOF
echo "KDC for $REALM on port $PORT, kadmind on $KADMIN_PORT and $KPASSWD_PORT (pids $(tr '\n' ' ' <"$DIR/kdc.pid")); env in $DIR/test.env"
