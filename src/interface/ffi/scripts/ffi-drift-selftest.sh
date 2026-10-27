#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
#
# Self-test for tests/ffi_drift.zig: inject known drifts into src/c.zig and
# require the build to fail with an "FFI drift" / constant error each time.
set -uo pipefail
cd "$(dirname "$0")/.."
orig="$(mktemp)"; cp src/c.zig "$orig"
trap 'cp "$orig" src/c.zig; rm -f "$orig"' EXIT
bad=0
drift() {
  local id="$1" from="$2" to="$3"
  cp "$orig" src/c.zig
  local content; content="$(cat src/c.zig)"
  [[ "$content" == *"$from"* ]] || { echo "[$id] ERROR: pattern not found" >&2; bad=$((bad+1)); return; }
  printf '%s\n' "${content/"$from"/"$to"}" > src/c.zig
  local out; out="$(zig build test 2>&1)"   # (pipefail would mask grep's result)
  if grep -q -E "FFI drift|constant .*: ours|not in headers" <<<"$out"; then
    echo "[$id] caught"
  else
    echo "[$id] NOT CAUGHT" >&2; bad=$((bad+1))
  fi
}
drift "param int type"   'SSL_read(ssl: ?*SSL, buf: ?*anyopaque, num: c_int)' 'SSL_read(ssl: ?*SSL, buf: ?*anyopaque, num: usize)'
drift "constant value"   'X509_V_ERR_CERT_HAS_EXPIRED: c_long = 10;' 'X509_V_ERR_CERT_HAS_EXPIRED: c_long = 11;'
drift "const-ness"       'SSL_get_verify_result(ssl: ?*const SSL)' 'SSL_get_verify_result(ssl: ?*SSL)'
drift "nullability"      'SSL_new(ctx: ?*SSL_CTX) ?*SSL;' 'SSL_new(ctx: ?*SSL_CTX) *SSL;'
drift "wrong handle"     'X509_free(x509: ?*X509) void;' 'X509_free(x509: ?*SSL) void;'
drift "[*c] narrowed"    'ASN1_TIME_to_posix(t: ?*const ASN1_TIME, out: [*c]i64)' 'ASN1_TIME_to_posix(t: ?*const ASN1_TIME, out: *i64)'
drift "callback arity"   'callback: ?*const fn (?*SSL, [*c]u8) callconv(.c) c_uint' 'callback: ?*const fn (?*SSL) callconv(.c) c_uint'
drift "arity"            'SSL_set_alpn_protos(ssl: ?*SSL, protos: [*c]const u8, protos_len: usize)' 'SSL_set_alpn_protos(ssl: ?*SSL, protos: [*c]const u8)'
echo; if [[ "$bad" -eq 0 ]]; then echo "all injected drifts caught"; else echo "$bad drift(s) not caught"; fi
exit "$bad"
