#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
#
# Mutation check for the security-relevant choices in src/root.zig.
# Each mutation deliberately re-introduces one misuse listed in docs/security/TLS-WRAPPER-SECURITY.adoc §3.
# Every mutation must make `zig build test` FAIL ("killed"), except one that
# is expected to survive for a stated reason (a redundant backstop).
# Anything else is reported as UNEXPECTED.
#
# Restores src/root.zig after each mutation (and on exit).
set -uo pipefail
cd "$(dirname "$0")/.."
orig="$(mktemp)"
cp src/root.zig "$orig"
trap 'cp "$orig" src/root.zig; rm -f "$orig"' EXIT

survivors=0
# mutate <id> <expect: killed|survives> <from> <to> [<from> <to> ...]
mutate() {
  local id="$1" expect="$2"; shift 2
  cp "$orig" src/root.zig
  local content; content="$(cat src/root.zig)"
  while [ "$#" -ge 2 ]; do
    if [[ "$content" != *"$1"* ]]; then
      echo "[$id] ERROR: pattern not found; mutation script out of date"; survivors=$((survivors+1)); return
    fi
    content="${content/"$1"/"$2"}"   # literal, first occurrence
    shift 2
  done
  printf '%s\n' "$content" > src/root.zig
  local outcome=killed
  if zig build test >/dev/null 2>&1; then outcome=survives; fi
  if [ "$outcome" = "$expect" ]; then
    echo "[$id] $outcome (as expected)"
  else
    echo "[$id] $outcome  <-- UNEXPECTED (expected $expect)"
    survivors=$((survivors+1))
  fi
}

VERIFY_PEER='c.SSL_set_verify(ssl, c.SSL_VERIFY_PEER, null);'
VERIFY_NONE='c.SSL_set_verify(ssl, c.SSL_VERIFY_NONE, null);'
RECHECK='if (vr != c.X509_V_OK) {
                    self.fail("post-handshake verify result not OK");'
NO_RECHECK='if (false) {
                    self.fail("post-handshake verify result not OK");'

mutate "MISUSE-1 ignore roots load result" killed \
  'if (c.SSL_CTX_load_verify_locations(ctx, w.roots_pem_file.ptr, null) != 1) {' \
  'if (c.SSL_CTX_load_verify_locations(ctx, w.roots_pem_file.ptr, null) == 12345) {'
# With VERIFY_NONE the post-handshake recheck still refuses the Session, but
# only AFTER the handshake has completed on both sides (the client may already
# have sent its certificate). Tests assert the server never completes, so this
# is killed: the recheck is a backstop, not a substitute for VERIFY_PEER.
mutate "MISUSE-3a verify mode NONE (recheck still present)" killed "$VERIFY_PEER" "$VERIFY_NONE"
# Survives by design: VERIFY_PEER already aborts the handshake, so the recheck
# is redundant while VERIFY_PEER is set. It exists for MISUSE-3a above.
mutate "post-handshake recheck removed (VERIFY_PEER still set)" survives "$RECHECK" "$NO_RECHECK"
mutate "MISUSE-3a + recheck removed" killed "$VERIFY_PEER" "$VERIFY_NONE" "$RECHECK" "$NO_RECHECK"
mutate "MISUSE-2 accept IP-like / trailing-dot server_name (RFC 1123 check only)" killed \
  'try validateServerName(config.server_name);' \
  'std.Io.net.HostName.validate(config.server_name) catch return error.InvalidServerName;'
mutate "MISUSE-11 default (ALL) TLS 1.2 cipher list" killed \
  'if (c.SSL_CTX_set_strict_cipher_list(ctx, tls12_ciphers) != 1) return error.LibraryFailure;' ''
mutate "MISUSE-4 TOFU context not attached" killed \
  'if (c.SSL_set_ex_data(ssl, exDataIndex(), &self.tofu) != 1) {' \
  'if (c.SSL_set_ex_data(ssl, exDataIndex(), null) != 1) {'
mutate "MISUSE-8 INVALID_CALL treated as a certificate failure" killed \
  'if (vr != c.X509_V_OK and vr != c.X509_V_ERR_INVALID_CALL) return mapVerifyResult(vr);' \
  'if (vr != c.X509_V_OK) return mapVerifyResult(vr);'
mutate "MISUSE-3b no SSL_set1_host" killed \
  'if (c.SSL_set1_host(ssl, name_c) != 1) return error.LibraryFailure;' ''
mutate "MISUSE-3c CN fallback re-enabled" killed \
  'c.SSL_set_hostflags(ssl, c.X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);' ''
mutate "MISUSE-5 skip expiry check in TOFU" killed \
  'if (na <= 0) return error.CertificateExpired;' ''
# A peer-controlled certificate (CN tagged OCTET STRING, no SAN) makes
# X509_check_host return a negative value; fixture gemini_cn_octet.pem.
mutate "MISUSE-6 check_host: treat any nonzero as match" killed \
  'st.name_flags, null) != 1)' 'st.name_flags, null) == 0)'
mutate "MISUSE-7 truncation reported as clean EOF" killed \
  'c.SSL_ERROR_SYSCALL => if (rc == 0) error.Truncated else error.TransportError,' \
  'c.SSL_ERROR_SYSCALL => if (rc == 0) 0 else error.TransportError,'
mutate "TOFU: accept on pin mismatch" killed \
  'if (!known.eql(pin)) return error.PinMismatch;' ''
mutate "TOFU: callback returns ok after refusing" killed \
  'else => c.SSL_AD_CERTIFICATE_UNKNOWN,
        };
        return c.ssl_verify_invalid;' \
  'else => c.SSL_AD_CERTIFICATE_UNKNOWN,
        };
        return c.ssl_verify_ok;'
mutate "min version lowered to TLS 1.2" killed \
  '.tls1_3 => c.TLS1_3_VERSION,
        .tls1_2 => c.TLS1_2_VERSION,' \
  '.tls1_3 => c.TLS1_2_VERSION,
        .tls1_2 => c.TLS1_2_VERSION,'

echo
if [ "$survivors" -eq 0 ]; then echo "all mutations behaved as expected"; else echo "$survivors unexpected outcome(s)"; fi
exit "$survivors"
