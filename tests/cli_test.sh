#!/usr/bin/env bash
# End-to-end test of the shamir command-line tool.
# Usage: cli_test.sh <path-to-shamir-binary>
set -euo pipefail

bin="$1"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# Private key 1 has a well-known address.
key="0000000000000000000000000000000000000000000000000000000000000001"
address="0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"

# address
"$bin" address <<<"$key" | grep -q "$address" || fail "address of key 1"

# split from stdin, combine from arguments (shares 2, 4, 5)
"$bin" split -t 3 -n 5 <<<"$key" >"$tmp/shares" 2>"$tmp/split.err"
[[ "$(wc -l <"$tmp/shares")" -eq 5 ]] || fail "split should print 5 shares"
grep -q "$address" "$tmp/split.err" || fail "split should print the address to stderr"
mapfile -t shares <"$tmp/shares"
[[ "$("$bin" combine "${shares[1]}" "${shares[3]}" "${shares[4]}")" == "$key" ]] || fail "combine from args"

# combine from stdin
[[ "$(head -n 3 "$tmp/shares" | "$bin" combine)" == "$key" ]] || fail "combine from stdin"

# too few shares give a different value (or an error), never the key
out="$(head -n 2 "$tmp/shares" | "$bin" combine 2>/dev/null || true)"
[[ "$out" != "$key" ]] || fail "two of three shares must not recover the key"

# --generate: the combined key has the same address that split printed
"$bin" split -t 2 -n 3 --generate >"$tmp/gen" 2>"$tmp/gen.err"
generated_address="$(grep '^address:' "$tmp/gen.err" | awk '{print $2}')"
recovered_address="$(tail -n 2 "$tmp/gen" | "$bin" combine | "$bin" address | grep '^address:' | awk '{print $2}')"
[[ -n "$generated_address" && "$generated_address" == "$recovered_address" ]] || fail "generated key round trip"

# --verifiable: verify and combine with commitments
"$bin" split -t 3 -n 5 --verifiable <<<"$key" >"$tmp/vss" 2>/dev/null
commitments="$(grep '^commitments:' "$tmp/vss" | cut -d: -f2)"
[[ -n "$commitments" ]] || fail "verifiable split should print commitments"
mapfile -t vss_shares < <(grep -v '^commitments:' "$tmp/vss")
"$bin" verify --commitments "$commitments" "${vss_shares[@]}" >/dev/null || fail "verify valid shares"
[[ "$("$bin" combine --commitments "$commitments" "${vss_shares[0]}" "${vss_shares[2]}" "${vss_shares[4]}" 2>/dev/null)" == "$key" ]] \
  || fail "combine with commitments"
# stdin form: shares plus the commitments line
[[ "$(sed -n '2,4p;6p' "$tmp/vss" | "$bin" combine 2>/dev/null)" == "$key" ]] || fail "combine with commitments from stdin"

# a corrupted share is detected
bad="${vss_shares[0]%?}0"
[[ "$bad" != "${vss_shares[0]}" ]] || bad="${vss_shares[0]%?}1"
if "$bin" verify --commitments "$commitments" "$bad" >/dev/null; then fail "verify must reject a corrupted share"; fi
if "$bin" combine --commitments "$commitments" "$bad" "${vss_shares[1]}" "${vss_shares[2]}" >/dev/null 2>&1; then
  fail "combine must reject a corrupted share"
fi
if "$bin" combine --commitments "$commitments" "${vss_shares[0]}" "${vss_shares[1]}" >/dev/null 2>&1; then
  fail "combine with commitments must reject too few shares"
fi

# invalid input -> non-zero exit codes
expect_exit() {
  local code="$1"; shift
  set +e
  "$@" >/dev/null 2>&1 </dev/null
  local actual=$?
  set -e
  [[ "$actual" -eq "$code" ]] || fail "expected exit $code, got $actual: $*"
}
expect_exit 2 "$bin"
expect_exit 2 "$bin" unknown
expect_exit 2 "$bin" split -t 3
expect_exit 2 "$bin" split -t 3 -n 5 --bogus
expect_exit 2 "$bin" split -t x -n 5 --generate
expect_exit 1 "$bin" split -t 6 -n 5 --generate
expect_exit 1 "$bin" split -t 2 -n 256 --generate
expect_exit 1 "$bin" combine "1:abc" "1:abd"
expect_exit 1 "$bin" combine "0:abc"
expect_exit 1 "$bin" combine "not-a-share"
expect_exit 2 "$bin" combine
expect_exit 1 "$bin" address
zero="0000000000000000000000000000000000000000000000000000000000000000"
order="fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
set +e
"$bin" split -t 2 -n 3 <<<"$zero" >/dev/null 2>&1; [[ $? -eq 1 ]] || fail "zero key must be rejected"
"$bin" split -t 2 -n 3 <<<"$order" >/dev/null 2>&1; [[ $? -eq 1 ]] || fail "key = n must be rejected"
set -e

echo "cli: all checks passed"
