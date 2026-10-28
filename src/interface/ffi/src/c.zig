// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
//
// Hand-written FFI surface for the subset of BoringSSL this wrapper uses.
//
// Why hand-written: Zig 0.17 removed @cImport, and a narrow, explicit list
// is easier to audit than a translated header with ~4,000 declarations.
// Every type is opaque, so there are no struct layouts to get wrong.
// The risk is signature drift when the BoringSSL pin moves; tests/ffi_drift.zig
// compares each declaration below against translate-c output from the
// pinned headers and fails the build on any mismatch.
//
// Header references are to BoringSSL tag 0.20260929.0.

pub const SSL = opaque {};
pub const SSL_CTX = opaque {};
pub const SSL_METHOD = opaque {};
pub const SSL_CIPHER = opaque {};
pub const X509 = opaque {};
pub const X509_NAME = opaque {};
pub const X509_PUBKEY = opaque {};
pub const ASN1_TIME = opaque {};
pub const CRYPTO_BUFFER = opaque {};
pub const OPENSSL_STACK = opaque {};
/// STACK_OF(CRYPTO_BUFFER). C code passes it to OPENSSL_sk_* through an
/// inline cast; Zig callers must @ptrCast it the same way.
pub const STACK_OF_CRYPTO_BUFFER = opaque {};
pub const X509_STORE_CTX = opaque {};
pub const X509_VERIFY_PARAM = opaque {};

// --- ssl.h: context and connection lifecycle -------------------------------
pub extern fn TLS_client_method() ?*const SSL_METHOD;
pub extern fn TLS_server_method() ?*const SSL_METHOD;
pub extern fn SSL_CTX_new(method: ?*const SSL_METHOD) ?*SSL_CTX;
pub extern fn SSL_CTX_free(ctx: ?*SSL_CTX) void;
pub extern fn SSL_CTX_set_min_proto_version(ctx: ?*SSL_CTX, version: u16) c_int;
pub extern fn SSL_CTX_set_max_proto_version(ctx: ?*SSL_CTX, version: u16) c_int;
pub extern fn SSL_CTX_set_strict_cipher_list(ctx: ?*SSL_CTX, str: [*c]const u8) c_int;
pub extern fn SSL_new(ctx: ?*SSL_CTX) ?*SSL;
pub extern fn SSL_free(ssl: ?*SSL) void;
pub extern fn SSL_set_fd(ssl: ?*SSL, fd: c_int) c_int;
pub extern fn SSL_connect(ssl: ?*SSL) c_int;
pub extern fn SSL_accept(ssl: ?*SSL) c_int;
pub extern fn SSL_read(ssl: ?*SSL, buf: ?*anyopaque, num: c_int) c_int;
pub extern fn SSL_write(ssl: ?*SSL, buf: ?*const anyopaque, num: c_int) c_int;
pub extern fn SSL_shutdown(ssl: ?*SSL) c_int;
pub extern fn SSL_get_error(ssl: ?*const SSL, ret_code: c_int) c_int;
pub extern fn SSL_version(ssl: ?*const SSL) c_int;
pub extern fn SSL_get_current_cipher(ssl: ?*const SSL) ?*const SSL_CIPHER;
pub extern fn SSL_CIPHER_get_name(cipher: ?*const SSL_CIPHER) [*c]const u8;

// --- ssl.h: server identity / hostname / SNI -------------------------------
pub extern fn SSL_set_tlsext_host_name(ssl: ?*SSL, name: [*c]const u8) c_int;
pub extern fn SSL_set1_host(ssl: ?*SSL, hostname: [*c]const u8) c_int;
pub extern fn SSL_set_hostflags(ssl: ?*SSL, flags: c_uint) void;

// --- ssl.h: verification ----------------------------------------------------
pub extern fn SSL_CTX_load_verify_locations(ctx: ?*SSL_CTX, ca_file: [*c]const u8, ca_dir: [*c]const u8) c_int;
pub extern fn SSL_set_verify(ssl: ?*SSL, mode: c_int, callback: ?*const fn (c_int, ?*X509_STORE_CTX) callconv(.c) c_int) void;
pub extern fn SSL_CTX_set_verify(ctx: ?*SSL_CTX, mode: c_int, callback: ?*const fn (c_int, ?*X509_STORE_CTX) callconv(.c) c_int) void;
pub extern fn SSL_set_custom_verify(ssl: ?*SSL, mode: c_int, callback: ?*const fn (?*SSL, [*c]u8) callconv(.c) c_uint) void;
pub extern fn SSL_get_verify_result(ssl: ?*const SSL) c_long;
pub extern fn SSL_get0_peer_certificates(ssl: ?*const SSL) ?*const STACK_OF_CRYPTO_BUFFER;

// --- ssl.h: ALPN ------------------------------------------------------------
pub extern fn SSL_set_alpn_protos(ssl: ?*SSL, protos: [*c]const u8, protos_len: usize) c_int;
pub extern fn SSL_get0_alpn_selected(ssl: ?*const SSL, out_data: [*c][*c]const u8, out_len: [*c]c_uint) void;
pub extern fn SSL_CTX_set_alpn_select_cb(
    ctx: ?*SSL_CTX,
    cb: ?*const fn (?*SSL, [*c][*c]const u8, [*c]u8, [*c]const u8, c_uint, ?*anyopaque) callconv(.c) c_int,
    arg: ?*anyopaque,
) void;
pub extern fn SSL_select_next_proto(out: [*c][*c]u8, out_len: [*c]u8, peer: [*c]const u8, peer_len: c_uint, supported: [*c]const u8, supported_len: c_uint) c_int;

// --- ssl.h: own certificate (client identity, and the test server) ---------
pub extern fn SSL_CTX_use_certificate_chain_file(ctx: ?*SSL_CTX, file: [*c]const u8) c_int;
pub extern fn SSL_CTX_use_PrivateKey_file(ctx: ?*SSL_CTX, file: [*c]const u8, @"type": c_int) c_int;
pub extern fn SSL_CTX_check_private_key(ctx: ?*const SSL_CTX) c_int;

// --- ssl.h: ex_data (callback context) -------------------------------------
pub const CRYPTO_EX_DATA = opaque {};
pub const CRYPTO_EX_dup = fn (?*CRYPTO_EX_DATA, ?*const CRYPTO_EX_DATA, [*c]?*anyopaque, c_int, c_long, ?*anyopaque) callconv(.c) c_int;
pub const CRYPTO_EX_free = fn (?*anyopaque, ?*anyopaque, ?*CRYPTO_EX_DATA, c_int, c_long, ?*anyopaque) callconv(.c) void;
pub extern fn SSL_get_ex_new_index(argl: c_long, argp: ?*anyopaque, unused: [*c]c_int, dup_unused: ?*const CRYPTO_EX_dup, free_func: ?*const CRYPTO_EX_free) c_int;
pub extern fn SSL_set_ex_data(ssl: ?*SSL, idx: c_int, data: ?*anyopaque) c_int;
pub extern fn SSL_get_ex_data(ssl: ?*const SSL, idx: c_int) ?*anyopaque;

// --- stack.h / pool.h -------------------------------------------------------
pub extern fn OPENSSL_sk_num(sk: ?*const OPENSSL_STACK) usize;
pub extern fn OPENSSL_sk_value(sk: ?*const OPENSSL_STACK, i: usize) ?*anyopaque;
pub extern fn CRYPTO_BUFFER_data(buf: ?*const CRYPTO_BUFFER) [*c]const u8;
pub extern fn CRYPTO_BUFFER_len(buf: ?*const CRYPTO_BUFFER) usize;

// --- x509.h: certificate inspection ----------------------------------------
pub extern fn X509_parse_from_buffer(buf: ?*CRYPTO_BUFFER) ?*X509;
pub extern fn X509_free(x509: ?*X509) void;
pub extern fn X509_get0_notBefore(x509: ?*const X509) ?*const ASN1_TIME;
pub extern fn X509_get0_notAfter(x509: ?*const X509) ?*const ASN1_TIME;
pub extern fn ASN1_TIME_to_posix(t: ?*const ASN1_TIME, out: [*c]i64) c_int;
pub extern fn X509_cmp_time_posix(s: ?*const ASN1_TIME, t: i64) c_int;
pub extern fn X509_get_subject_name(x509: ?*const X509) ?*X509_NAME;
pub extern fn X509_get_issuer_name(x509: ?*const X509) ?*X509_NAME;
pub extern fn X509_NAME_oneline(name: ?*const X509_NAME, buf: [*c]u8, size: c_int) [*c]u8;
pub extern fn X509_get_X509_PUBKEY(x509: ?*const X509) ?*X509_PUBKEY;
pub extern fn i2d_X509_PUBKEY(key: ?*const X509_PUBKEY, outp: [*c][*c]u8) c_int;
pub extern fn X509_check_host(x509: ?*const X509, chk: [*c]const u8, chklen: usize, flags: c_uint, out_peername: [*c][*c]u8) c_int;
pub extern fn OPENSSL_free(ptr: ?*anyopaque) void;

// --- err.h ------------------------------------------------------------------
pub extern fn ERR_get_error() u32;
pub extern fn ERR_error_string_n(packed_error: u32, buf: [*c]u8, len: usize) [*c]u8;
pub extern fn ERR_clear_error() void;

// --- constants (values checked against the pinned headers; see ffi_drift) ---
pub const TLS1_2_VERSION: u16 = 0x0303;
pub const TLS1_3_VERSION: u16 = 0x0304;
pub const SSL_ERROR_NONE: c_int = 0;
pub const SSL_ERROR_SSL: c_int = 1;
pub const SSL_ERROR_WANT_READ: c_int = 2;
pub const SSL_ERROR_WANT_WRITE: c_int = 3;
pub const SSL_ERROR_SYSCALL: c_int = 5;
pub const SSL_ERROR_ZERO_RETURN: c_int = 6;
pub const SSL_VERIFY_NONE: c_int = 0x00;
pub const SSL_VERIFY_PEER: c_int = 0x01;
pub const SSL_VERIFY_FAIL_IF_NO_PEER_CERT: c_int = 0x02;
pub const SSL_FILETYPE_PEM: c_int = 1;
pub const ssl_verify_ok: c_uint = 0;
pub const ssl_verify_invalid: c_uint = 1;
pub const SSL_AD_BAD_CERTIFICATE: u8 = 42;
pub const SSL_AD_CERTIFICATE_EXPIRED: u8 = 45;
pub const SSL_AD_CERTIFICATE_UNKNOWN: u8 = 46;
pub const SSL_AD_INTERNAL_ERROR: u8 = 80;
pub const SSL_TLSEXT_ERR_OK: c_int = 0;
pub const SSL_TLSEXT_ERR_ALERT_FATAL: c_int = 2;
pub const OPENSSL_NPN_NEGOTIATED: c_int = 1;
pub const X509_CHECK_FLAG_NEVER_CHECK_SUBJECT: c_uint = 0x20;
pub const X509_V_OK: c_long = 0;
pub const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: c_long = 2;
pub const X509_V_ERR_CERT_SIGNATURE_FAILURE: c_long = 7;
pub const X509_V_ERR_CERT_NOT_YET_VALID: c_long = 9;
pub const X509_V_ERR_CERT_HAS_EXPIRED: c_long = 10;
pub const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: c_long = 18;
pub const X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: c_long = 19;
pub const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: c_long = 20;
pub const X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: c_long = 21;
pub const X509_V_ERR_INVALID_CA: c_long = 24;
pub const X509_V_ERR_INVALID_PURPOSE: c_long = 26;
pub const X509_V_ERR_HOSTNAME_MISMATCH: c_long = 62;
pub const X509_V_ERR_APPLICATION_VERIFICATION: c_long = 50;
pub const X509_V_ERR_INVALID_CALL: c_long = 65;
