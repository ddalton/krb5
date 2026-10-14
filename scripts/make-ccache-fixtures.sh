#!/usr/bin/env bash
# Record credential caches written by MIT krb5 for src/ccache.rs's tests.
#
#   scripts/make-ccache-fixtures.sh <kdc-dir> <out-dir>
#
# <kdc-dir> is a realm started by scripts/test-kdc.sh. For each file format
# version MIT can write (ccache_type 1-4) this runs kinit for alice and kvno
# for one service, then klist, so each cache holds a TGT, a service ticket
# and MIT's config entries, with klist's view of it alongside. The keys
# belong to a throwaway realm and protect nothing.
set -euo pipefail

KDC_DIR=$(cd "$1" && pwd)
OUT=$(mkdir -p "$2" && cd "$2" && pwd)
. "$KDC_DIR/test.env"
PATH=$PATH:/usr/sbin:/usr/local/sbin

for v in 1 2 3 4; do
    conf="$OUT/krb5.conf.v$v"
    awk -v v="$v" '{ print } /^\[libdefaults\]/ { print "    ccache_type = " v }' \
        "$KDC_DIR/krb5.conf" >"$conf"
    cache="$OUT/mit-v$v.ccache"
    rm -f "$cache"
    export KRB5_CONFIG=$conf KRB5CCNAME=FILE:$cache
    echo alicepw | kinit -f -r 2d alice >/dev/null
    kvno svc18/svc.krb5.test >/dev/null
    # Drop the absolute path so the recording does not depend on where it ran.
    klist -e -f | sed "s|FILE:$OUT/|FILE:|" >"$OUT/mit-v$v.klist"
    rm -f "$conf"
done
echo "wrote $OUT/mit-v{1,2,3,4}.ccache"
