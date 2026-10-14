#!/usr/bin/env bash
# Record MIT krb5's own reading of duration and enctype-list strings into
# testdata/mit-settings.tsv, which src/config.rs's tests compare against.
#
#   scripts/record-mit-settings.sh [path to MIT's krb5-config]
#
# Needs MIT's headers and libkrb5 (Debian: libkrb5-dev; Homebrew: krb5,
# whose krb5-config is /opt/homebrew/opt/krb5/bin/krb5-config).
set -euo pipefail
cd "$(dirname "$0")/.."
KRB5CONFIG=${1:-krb5-config}
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
# shellcheck disable=SC2046
cc -o "$OUT/rec" scripts/record-mit-settings.c $("$KRB5CONFIG" --cflags krb5) $("$KRB5CONFIG" --libs krb5)
{
    for d in 0 1 3600 86400 2147483647 2147483648 -5 "  42" "10s" "90s" "1m" "2h" \
        "1d" "1d2h3m4s" "1d 2h 3m 4s" "2h30m" "1h30" "1d4s" "1d 4s" "10h " " 10h" \
        "1m2h" "1s2m" "1h1h" "h" "d1" "1x" "1:30" "1:30:15" "36:00" "1:300" "1:3:5" \
        "100:00" "42 " "5 " "1:30 " "1-02:00:00 " "1d " "1d2" "1d 2" "1:30x" "1d2x" "1dx" \
        "1-02:00:00x" "1x2" "1d\x" "1-02:00:00" "1-2:3:4" "1-02:00" "1-002:00:00" "1d-2h" "1d -2h" \
        "-1d" "1.5h" "1 h" "24855d" "24856d" "596523h" "596524h" "1 2" "" "1:" \
        ":30" "1::30" "1:30:" "0d0h0m0s" "7d" "10H" "10h\t"; do
        printf 'D %s\n' "$d"
    done
    for e in "DEFAULT" "default" "aes" "aes256-cts-hmac-sha1-96" "aes256-cts" \
        "AES256-CTS" "aes256-sha1" "aes128-sha2 aes256-sha2" \
        "aes256-cts-hmac-sha384-192,aes128-cts-hmac-sha256-128" "aes -aes128-cts" \
        "DEFAULT -des3 -rc4 -camellia" "des3 rc4" "camellia" "+aes256-cts" \
        "aes256-cts aes256-cts" "bogus aes128-cts" "bogus" "-aes" "aes -aes +aes128-sha1" \
        "rc4-hmac arcfour-hmac-md5" "des3-cbc-sha1-kd des3-hmac-sha1" \
        "camellia128-cts camellia256-cts-cmac" "  aes256-cts ,, aes128-cts  " "DEFAULT aes" \
        "aes DEFAULT" "-DEFAULT" "aes256-cts -DEFAULT aes128-cts"; do
        printf 'E %s\n' "$e"
    done
} | "$OUT/rec" > testdata/mit-settings.tsv
echo "wrote testdata/mit-settings.tsv ($(wc -l < testdata/mit-settings.tsv) cases)"
