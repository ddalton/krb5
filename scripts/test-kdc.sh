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
# Writes <dir>/test.env with the KRB5_TEST_* variables the tests read.
# The keys are random and the passwords are fixed strings: nothing here
# protects anything.
set -euo pipefail

DIR=$(mkdir -p "$1" && cd "$1" && pwd)
PORT=${2:-18888}
REALM=${KRB5_TEST_REALM:-KRB5.TEST}
HOST=${KRB5_TEST_HOST:-127.0.0.1}
PATH=$PATH:/usr/sbin:/usr/local/sbin

if [ -f "$DIR/kdc.pid" ]; then kill "$(cat "$DIR/kdc.pid")" 2>/dev/null || true; fi
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
    }
EOF

cat >"$DIR/kdc.conf" <<EOF
[kdcdefaults]
    kdc_ports = $PORT
    kdc_tcp_ports = $PORT
[realms]
    $REALM = {
        database_name = $DIR/principal
        key_stash_file = $DIR/stash
        acl_file = $DIR/kadm5.acl
        supported_enctypes = $(for e in $ENCTYPES; do printf '%s:normal ' "$e"; done)
        default_principal_flags = +preauth
    }
[logging]
    kdc = FILE:$DIR/kdc.log
EOF
: >"$DIR/kadm5.acl"

export KRB5_CONFIG=$DIR/krb5.conf KRB5_KDC_PROFILE=$DIR/kdc.conf
kdb5_util create -s -r "$REALM" -P masterpw >/dev/null
# kadmin.local exits 0 even when a query fails, so check what it printed.
k() {
    local out
    out=$(kadmin.local -r "$REALM" -q "$*" 2>&1)
    if grep -qiE 'error|cannot|failed|usage' <<<"$out"; then
        echo "kadmin.local -q '$*' failed:" >&2; echo "$out" >&2; exit 1
    fi
}

# Password principals: one with every enctype (the KDC picks), one that
# does not require pre-authentication, and one per enctype so each
# string-to-key path is exercised.
k addprinc -pw alicepw alice
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

krb5kdc -n -P "$DIR/kdc.pid" >"$DIR/kdc.out" 2>&1 &
echo $! >"$DIR/kdc.pid"
for _ in $(seq 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then break; fi
    sleep 0.1
done

cat >"$DIR/test.env" <<EOF
KRB5_TEST_KDC=$HOST:$PORT
KRB5_TEST_REALM=$REALM
KRB5_TEST_DIR=$DIR
EOF
echo "KDC for $REALM listening on port $PORT (pid $(cat "$DIR/kdc.pid")); env in $DIR/test.env"
