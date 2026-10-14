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
# Writes <dir>/test.env with the KRB5_TEST_* variables the tests read.
# The keys are random and the passwords are fixed strings: nothing here
# protects anything.
set -euo pipefail

DIR=$(mkdir -p "$1" && cd "$1" && pwd)
PORT=${2:-18888}
REALM=${KRB5_TEST_REALM:-KRB5.TEST}
XREALM=CROSS.TEST
FREALM=FAR.TEST
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

cat >"$DIR/kdc.conf" <<EOF
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
    }
REALM
done)
[logging]
    kdc = FILE:$DIR/kdc.log
EOF
: >"$DIR/kadm5.acl"

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

krb5kdc -n -P "$DIR/kdc.pid" -r "$REALM" -r "$XREALM" -r "$FREALM" >"$DIR/kdc.out" 2>&1 &
echo $! >"$DIR/kdc.pid"
for _ in $(seq 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then break; fi
    sleep 0.1
done

cat >"$DIR/test.env" <<EOF
KRB5_TEST_KDC=$HOST:$PORT
KRB5_TEST_REALM=$REALM
KRB5_TEST_DIR=$DIR
KRB5_TEST_CROSS_REALMS="$XREALM $FREALM"
EOF
echo "KDC for $REALM listening on port $PORT (pid $(cat "$DIR/kdc.pid")); env in $DIR/test.env"
