#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
#
# Generates the TLS test fixtures (CA, leaves, keys, pins) into OUT_DIR.
#
#   gen-fixtures.sh OUT_DIR [PATCH_CN_TAG_EXE]
#
# build.zig runs this for every `zig build test` and points the tests at the
# result, so no private key is ever committed: nothing for the secret scanner
# to suppress, and nothing anyone could mistake for real key material.
# PATCH_CN_TAG_EXE is the compiled scripts/patch-cn-tag.zig (build.zig passes
# it); without it the script falls back to `zig run`.
#
# Needs bash, OpenSSL (any 3.x) and coreutils (base64, sha256sum).
#
# Uses `openssl ca` so validity windows can be set explicitly (OpenSSL 3.0
# has no -not_before/-not_after on `x509`). "Valid" certificates run
# 2026-01-01 .. 2126-01-01 so the suite does not rot; the expired ones ended
# in 2001; the not-yet-valid one starts in 2125.
set -euo pipefail
script_dir="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${1:?usage: gen-fixtures.sh OUT_DIR [PATCH_CN_TAG_EXE]}"
out="$(cd "$1" && pwd)"
patch_exe="${2:-}"
# Resolve before cd-ing into the scratch directory (build.zig passes a relative path).
[[ -z "$patch_exe" ]] || patch_exe="$(cd "$(dirname "$patch_exe")" && pwd)/$(basename "$patch_exe")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

VALID_FROM=20260101000000Z
VALID_TO=21260101000000Z

cat > ca.cnf <<'EOF'
[ ca ]
default_ca = test_ca
[ test_ca ]
dir = .
database = index.txt
new_certs_dir = newcerts
serial = serial
default_md = sha256
policy = any
copy_extensions = none
unique_subject = no
[ any ]
commonName = supplied
[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[ server_san ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @san_localhost
[ san_localhost ]
DNS.1 = localhost
DNS.2 = test.example
[ server_rsa_kx ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @san_localhost
[ server_other ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:other.example
[ server_cn_only ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
[ client ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
[ leaf_signed_san ]
subjectAltName = DNS:evil.example
[ gemini_self ]
basicConstraints = critical,CA:FALSE
subjectAltName = DNS:localhost
[ gemini_self_cn_only ]
basicConstraints = critical,CA:FALSE
EOF
mkdir newcerts; : > index.txt; echo 1000 > serial

q() { "$@" >/dev/null 2>&1 || { echo "failed: $*" >&2; "$@"; exit 1; }; }
key() {
  local key_path=$1
  q openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$key_path"
}
csr() {
  local key_path=$1 common_name=$2 csr_path=$3
  q openssl req -new -key "$key_path" -subj "/CN=$common_name" -out "$csr_path"
}
# sign <csr> <out> <ext> <start> <end> [issuer-cert issuer-key | selfsign-key]
sign() {
  local csr_path=$1 cert_path=$2 ext=$3 start=$4 end=$5
  local issuer_or_mode=${6:-} issuer_key=${7:-}
  if [[ "$issuer_or_mode" == "-selfsign" ]]; then
    q openssl ca -batch -config ca.cnf -selfsign -keyfile "$issuer_key" -in "$csr_path" -out "$cert_path" \
      -extensions "$ext" -startdate "$start" -enddate "$end" -notext
  else
    q openssl ca -batch -config ca.cnf -cert "$issuer_or_mode" -keyfile "$issuer_key" -in "$csr_path" -out "$cert_path" \
      -extensions "$ext" -startdate "$start" -enddate "$end" -notext
  fi
}

# Root CA
key ca.key; csr ca.key "boringtls Test Root" ca.csr
sign ca.csr ca.pem v3_ca $VALID_FROM $VALID_TO -selfsign ca.key

# WebPKI-style leaves signed by the root
key server.key;      csr server.key localhost server.csr
sign server.csr server.pem server_san $VALID_FROM $VALID_TO ca.pem ca.key
key other.key;       csr other.key other.example other.csr
sign other.csr wrong_host.pem server_other $VALID_FROM $VALID_TO ca.pem ca.key
key expired.key;     csr expired.key localhost expired.csr
sign expired.csr expired.pem server_san 20000101000000Z 20010101000000Z ca.pem ca.key
key future.key;      csr future.key localhost future.csr
sign future.csr not_yet_valid.pem server_san 21250101000000Z $VALID_TO ca.pem ca.key
key cnonly.key;      csr cnonly.key localhost cnonly.csr
sign cnonly.csr cn_only.pem server_cn_only $VALID_FROM $VALID_TO ca.pem ca.key
key client.key;      csr client.key "boringtls test client" client.csr
sign client.csr client.pem client $VALID_FROM $VALID_TO ca.pem ca.key

# ziglang/zig#35877 shape: a leaf signed by the (CA:FALSE) server leaf.
key evil.key;        csr evil.key evil.example evil.csr
sign evil.csr evil_leaf.pem leaf_signed_san $VALID_FROM $VALID_TO server.pem server.key
cat evil_leaf.pem server.pem > evil_chain.pem

# Gemini-style self-signed certificates
key gemini.key;      csr gemini.key localhost gemini.csr
sign gemini.csr gemini_self.pem gemini_self $VALID_FROM $VALID_TO -selfsign gemini.key
key gemini2.key;     csr gemini2.key localhost gemini2.csr
sign gemini2.csr gemini_self_rekeyed.pem gemini_self $VALID_FROM $VALID_TO -selfsign gemini2.key
key gemcn.key;       csr gemcn.key localhost gemcn.csr
sign gemcn.csr gemini_cn_only.pem gemini_self_cn_only $VALID_FROM $VALID_TO -selfsign gemcn.key
key gemexp.key;      csr gemexp.key localhost gemexp.csr
sign gemexp.csr gemini_expired.pem gemini_self 20000101000000Z 20010101000000Z -selfsign gemexp.key

# Hostile-encoding fixture: CN tagged OCTET STRING and no SAN, so
# X509_check_host returns a negative value (error) rather than 0.
# OpenSSL refuses to re-encode it, so PEM-wrap the DER directly.
openssl x509 -in gemini_cn_only.pem -outform DER -out gemcn.der
if [[ -n "$patch_exe" ]]; then
  "$patch_exe" gemcn.der gemcn_octet.der
else
  zig run "$script_dir/patch-cn-tag.zig" -- gemcn.der gemcn_octet.der
fi
{ echo "-----BEGIN CERTIFICATE-----"; base64 -w 64 gemcn_octet.der; echo "-----END CERTIFICATE-----"; } > gemini_cn_octet.pem

# RSA leaf, for TLS 1.2 key-exchange tests (TLS_RSA_* needs an RSA key).
q openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_server.key
csr rsa_server.key localhost rsa_server.csr
# keyEncipherment is set so that BoringSSL's own leaf key-usage check does
# NOT block static-RSA key exchange; only the wrapper's cipher list does.
sign rsa_server.csr rsa_server.pem server_rsa_kx $VALID_FROM $VALID_TO ca.pem ca.key

for f in gemini_cn_octet.pem rsa_server.pem rsa_server.key ca.pem server.pem server.key wrong_host.pem other.key expired.pem expired.key \
         not_yet_valid.pem future.key cn_only.pem cnonly.key client.pem client.key \
         evil_chain.pem evil.key gemini_self.pem gemini.key gemini_self_rekeyed.pem gemini2.key \
         gemini_cn_only.pem gemcn.key gemini_expired.pem gemexp.key; do
  cp "$f" "$out/$f"
done

# Expected SPKI pins (SHA-256 of DER SubjectPublicKeyInfo), for the tests.
pin() {
  local cert_path=$1
  openssl x509 -in "$cert_path" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1
}
{
  echo "gemini_self $(pin gemini_self.pem)"
  echo "gemini_self_rekeyed $(pin gemini_self_rekeyed.pem)"
  echo "gemini_cn_only $(pin gemini_cn_only.pem)"
  echo "server $(pin server.pem)"
} > "$out/pins.txt"
echo "fixtures written to $out" >&2
