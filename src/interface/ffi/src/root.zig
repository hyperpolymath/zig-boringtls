// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
//
// boringtls: a thin TLS client wrapper over BoringSSL.
//
// Read docs/security/TLS-WRAPPER-SECURITY.adoc (repo root) before relying on this. In short: cryptography, the TLS
// state machine, X.509 path validation and hostname matching are BoringSSL's.
// This file only chooses which BoringSSL checks run, decides TOFU pins, and
// turns results into Zig errors. Mistakes here can switch off checks that
// BoringSSL would otherwise perform; each such place is marked `MISUSE-n`
// and listed in §3 of that document.
//
// Shape (typestate):
//   connect()/fromFd()  -> Connection   (no read/write methods exist)
//   Connection.handshake() -> HandshakeResult
//      .established -> Session | .first_use -> opaque FirstUseSession (ack required)
//   Session.read/write/close/peerCertificate
// There is deliberately no way to express "skip verification" in Config.

const std = @import("std");
pub const c = @import("c.zig");

// ---------------------------------------------------------------------------
// Errors. Every failure is a named error; nothing is swallowed.
// ---------------------------------------------------------------------------

pub const Error = error{
    // configuration
    InvalidServerName,
    InvalidAlpn,
    RootsLoadFailed,
    ClientIdentityLoadFailed,
    ClientIdentityRequiresKnownPin,
    OutOfMemory,
    LibraryFailure, // BoringSSL allocation/setup call returned failure
    // transport
    ConnectFailed,
    ConnectionClosed, // peer closed the transport mid-handshake or mid-record
    Truncated, // EOF without close_notify after the handshake
    Timeout,
    NonBlockingSocket, // SSL_ERROR_WANT_* cannot be driven without a readiness API
    FirstUseRequiresAcknowledgement,
    TransportError,
    // peer authentication
    CertificateExpired,
    CertificateNotYetValid,
    CertificateSelfSigned,
    CertificateUntrusted, // no path to a configured root
    CertificateHostnameMismatch,
    CertificateInvalid, // any other X.509 verification failure
    NoPeerCertificate,
    PinMismatch, // TOFU: leaf key differs from the stored pin
    // protocol
    HandshakeFailed, // TLS-level failure not attributable to the above
    ProtocolError,
    // state / arguments
    AlreadyConsumed, // Connection.handshake called twice
    Closed, // Session used after close
    EmptyBuffer, // read() into a zero-length buffer (0 is reserved for close_notify)
    BufferTooSmall, // certificate name output was truncated to fit the caller buffer
};

// ---------------------------------------------------------------------------
// Pins (SHA-256 of the leaf's DER SubjectPublicKeyInfo)
// ---------------------------------------------------------------------------

pub const Pin = struct {
    sha256: [32]u8,

    pub fn eql(a: Pin, b: Pin) bool {
        // Constant-time; pins aren't secret, but there's no reason to leak
        // a comparison oracle either.
        return std.crypto.timing_safe.eql([32]u8, a.sha256, b.sha256);
    }

    pub fn toHex(p: Pin) [64]u8 {
        return std.fmt.bytesToHex(p.sha256, .lower);
    }

    pub fn fromHex(hex: []const u8) error{InvalidPin}!Pin {
        if (hex.len != 64) return error.InvalidPin;
        var out: Pin = undefined;
        _ = std.fmt.hexToBytes(&out.sha256, hex) catch return error.InvalidPin;
        return out;
    }
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

pub const MinVersion = enum { tls1_3, tls1_2 };

/// TLS 1.2 suites offered when `min_version = .tls1_2`.
pub const tls12_ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20";

pub const Trust = union(enum) {
    /// WebPKI (DoH and general HTTPS): BoringSSL builds and verifies the chain
    /// to roots in this PEM file and checks `server_name` against the leaf's
    /// subjectAltName. Common-name fallback is disabled.
    webpki: struct { roots_pem_file: [:0]const u8 },

    /// Trust on first use (Gemini). No CA chain is built. The handshake
    /// still proves the server holds the leaf's private key: BoringSSL
    /// checks the TLS 1.3 CertificateVerify, or the TLS 1.2 ECDHE
    /// ServerKeyExchange signature (static-RSA suites are not offered).
    /// This wrapper additionally checks the leaf's validity period and its
    /// name, then compares the SPKI pin.
    tofu: struct {
        /// null means "first visit": handshake returns a `FirstUseSession`,
        /// which cannot perform I/O until the caller acknowledges persistence.
        known_pin: ?Pin,
        /// Self-signed Gemini certificates often carry the host only in CN.
        /// The CN is consulted only when the certificate has no
        /// subjectAltName extension at all.
        name_check: enum { san_only, san_or_common_name } = .san_or_common_name,
    },
};

pub const ClientIdentity = struct {
    /// PEM file: leaf first, then any intermediates.
    chain_pem_file: [:0]const u8,
    /// PEM private key matching the leaf.
    key_pem_file: [:0]const u8,
};

pub const Config = struct {
    /// The identity the peer must prove. Sent as SNI and used for name checks.
    /// This is independent of the address dialled.
    server_name: []const u8,
    trust: Trust,
    /// ALPN protocol IDs in preference order, e.g. &.{"h2", "http/1.1"} for DoH.
    alpn: []const []const u8 = &.{},
    client_identity: ?ClientIdentity = null,
    min_version: MinVersion = .tls1_3,
    /// Applied as SO_RCVTIMEO/SO_SNDTIMEO on the socket. 0 disables (blocks forever).
    /// Descriptors must be blocking; nonblocking fds are rejected by fromFd.
    io_timeout_ms: u32 = 30_000,
};

/// Trust evidence attached to a Session. First-use connections are returned
/// in a separate `FirstUseSession` and cannot perform I/O until the caller
/// acknowledges the persisted pin.
pub const TrustEvidence = union(enum) {
    webpki_verified,
    pin_matched: Pin,
    first_use: Pin,
};

// ---------------------------------------------------------------------------
// Connection (pre-handshake)
// ---------------------------------------------------------------------------

pub const Connection = struct {
    ssl: ?*c.SSL,
    ctx: ?*c.SSL_CTX,
    fd: std.posix.fd_t,
    owns_fd: bool,
    trust_kind: std.meta.Tag(Trust),
    tofu: TofuState,
    /// Human-readable detail for the most recent failure (BoringSSL error
    /// queue or wrapper reason). Valid after a failed handshake.
    diag_buf: [256]u8 = undefined,
    diag_len: usize = 0,

    pub fn diagnostic(self: *const Connection) []const u8 {
        return self.diag_buf[0..self.diag_len];
    }

    /// The pin the server presented, if a TOFU handshake got far enough to
    /// see one (including after `error.PinMismatch`).
    /// UNAUTHENTICATED: the callback runs before the server proves key
    /// possession, so this is only what was claimed. Show it to a user
    /// as "the server now presents X", never store it as a pin.
    pub fn observedPin(self: *const Connection) ?Pin {
        return self.tofu.observed;
    }

    /// Run the TLS handshake. A verified WebPKI or known-pin connection
    /// returns an established Session. A first-use TOFU connection returns a
    /// `FirstUseSession`, which must be explicitly acknowledged before I/O.
    /// On failure all TLS state is freed (and the fd closed if owned).
    pub fn handshake(self: *Connection) Error!HandshakeResult {
        const ssl = self.ssl orelse return error.AlreadyConsumed;

        // MISUSE-4: the TOFU callback reads `self.tofu` through this pointer.
        // `self` must not move during SSL_connect (it can't: we're inside a
        // method on *Connection). The pointer is cleared again below.
        if (self.trust_kind == .tofu) {
            if (c.SSL_set_ex_data(ssl, exDataIndex(), &self.tofu) != 1) {
                self.fail("SSL_set_ex_data failed");
                self.release();
                return error.LibraryFailure;
            }
        }

        c.ERR_clear_error();
        const rc = c.SSL_connect(ssl);
        if (self.trust_kind == .tofu) _ = c.SSL_set_ex_data(ssl, exDataIndex(), null);

        if (rc != 1) {
            const err = self.classifyHandshakeFailure(ssl, rc);
            self.release();
            return err;
        }

        // Belt and braces for WebPKI: SSL_VERIFY_PEER already aborts the
        // handshake on failure; re-read the result so a configuration slip
        // elsewhere (MISUSE-1) cannot silently yield an unverified Session.
        const evidence: TrustEvidence = switch (self.trust_kind) {
            .webpki => blk: {
                const vr = c.SSL_get_verify_result(ssl);
                if (vr != c.X509_V_OK) {
                    self.fail("post-handshake verify result not OK");
                    self.release();
                    return mapVerifyResult(vr);
                }
                break :blk .webpki_verified;
            },
            .tofu => blk: {
                // The callback must have reached a positive decision.
                const decision = self.tofu.decision orelse {
                    self.fail("TOFU callback did not run");
                    self.release();
                    return error.HandshakeFailed;
                };
                break :blk decision;
            },
        };

        var s = Session{
            .ssl = ssl,
            .ctx = self.ctx,
            .fd = self.fd,
            .owns_fd = self.owns_fd,
            .evidence = evidence,
        };
        // Moved-from: further handshake() calls return AlreadyConsumed and
        // nothing here frees what the result now owns.
        self.ssl = null;
        self.ctx = null;
        self.owns_fd = false;
        return switch (evidence) {
            .first_use => |pin| blk: {
                const pending = std.heap.page_allocator.create(FirstUseState) catch {
                    s.release();
                    return error.OutOfMemory;
                };
                pending.* = .{ .session = s, .pin = pin };
                break :blk .{ .first_use = @ptrCast(pending) };
            },
            else => .{ .established = s },
        };
    }

    /// Abandon a Connection without handshaking.
    pub fn deinit(self: *Connection) void {
        self.release();
    }

    fn release(self: *Connection) void {
        if (self.ssl) |s| c.SSL_free(s);
        if (self.ctx) |x| c.SSL_CTX_free(x);
        if (self.owns_fd) closeFd(self.fd);
        self.ssl = null;
        self.ctx = null;
        self.owns_fd = false;
    }

    fn fail(self: *Connection, msg: []const u8) void {
        const n = @min(msg.len, self.diag_buf.len);
        @memcpy(self.diag_buf[0..n], msg[0..n]);
        self.diag_len = n;
    }

    fn captureErrQueue(self: *Connection) void {
        const e = c.ERR_get_error();
        if (e == 0) return;
        _ = c.ERR_error_string_n(e, &self.diag_buf, self.diag_buf.len);
        self.diag_len = std.mem.indexOfScalar(u8, &self.diag_buf, 0) orelse self.diag_buf.len;
        c.ERR_clear_error();
    }

    fn classifyHandshakeFailure(self: *Connection, ssl: *c.SSL, rc: c_int) Error {
        const ssl_err = c.SSL_get_error(ssl, rc);
        self.captureErrQueue();
        // TOFU: our callback recorded why it refused, if it did.
        if (self.trust_kind == .tofu) {
            if (self.tofu.failure) |f| return f;
        }
        // WebPKI: BoringSSL's verify result explains a verification abort.
        // MISUSE-8: before verification has run, SSL_get_verify_result
        // returns X509_V_ERR_INVALID_CALL (not X509_V_OK). Treating that as a
        // certificate failure would mislabel e.g. a TCP reset.
        if (self.trust_kind == .webpki) {
            const vr = c.SSL_get_verify_result(ssl);
            if (vr != c.X509_V_OK and vr != c.X509_V_ERR_INVALID_CALL) return mapVerifyResult(vr);
        }
        return switch (ssl_err) {
            c.SSL_ERROR_ZERO_RETURN => error.ConnectionClosed,
            c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => error.Timeout,
            c.SSL_ERROR_SYSCALL => if (rc == 0) error.ConnectionClosed else error.TransportError,
            else => error.HandshakeFailed,
        };
    }
};

/// Dial `host:port` over TCP (via std.Io), then prepare a TLS client.
/// `host` is only where to connect; `config.server_name` is what gets verified.
pub fn connect(io: std.Io, host: []const u8, port: u16, config: Config) Error!Connection {
    const hn = std.Io.net.HostName.init(host) catch return error.ConnectFailed;
    const stream = hn.connect(io, port, .{ .mode = .stream }) catch return error.ConnectFailed;
    return fromFdInner(stream.socket.handle, true, false, config) catch |e| {
        // fromFdInner closes owned fds on failure.
        return e;
    };
}

/// Wrap an already-connected blocking stream socket. On Linux, nonblocking
/// descriptors are rejected with `error.NonBlockingSocket`; the caller keeps
/// ownership of `fd` and must keep it open until the Session is closed.
pub fn fromFd(fd: std.posix.fd_t, config: Config) Error!Connection {
    return fromFdInner(fd, false, true, config);
}

fn fromFdInner(fd: std.posix.fd_t, owns_fd: bool, reject_nonblocking: bool, config: Config) Error!Connection {
    var conn = Connection{
        .ssl = null,
        .ctx = null,
        .fd = fd,
        .owns_fd = owns_fd,
        .trust_kind = config.trust,
        .tofu = .{},
    };
    errdefer conn.release();
    try configure(&conn, config, reject_nonblocking);
    return conn;
}

// BoringSSL's socket BIO is driven synchronously here. Do not accept an
// O_NONBLOCK fd and later misreport WANT_READ/WANT_WRITE as a timeout.
extern "c" fn fcntl(fd: c_int, cmd: c_int, ...) c_int;

fn requireBlockingSocket(fd: std.posix.fd_t, reject_nonblocking: bool) Error!void {
    const flags = fcntl(@intCast(fd), std.posix.F.GETFL, @as(c_int, 0));
    if (flags < 0) return error.TransportError;
    var nonblocking: std.posix.O = .{};
    nonblocking.NONBLOCK = true;
    const nonblock: c_int = @bitCast(nonblocking);
    if (flags & nonblock != 0) {
        if (reject_nonblocking) return error.NonBlockingSocket;
        // connect() owns this new descriptor, so normalizing it cannot change
        // another owner's view of an open-file description.
        if (fcntl(@intCast(fd), std.posix.F.SETFL, flags & ~nonblock) < 0) return error.TransportError;
    }
}

fn configure(conn: *Connection, config: Config, reject_nonblocking: bool) Error!void {
    // Server name: must be a DNS name (RFC 1123, no NUL) since it crosses
    // into C as a C string and is matched against dNSName SANs.
    // MISUSE-2: an IP literal would be matched as a DNS name by SSL_set1_host
    // (IP SANs need X509_VERIFY_PARAM_set1_ip), and RFC 6066 forbids IPs in
    // SNI. IP-addressed servers are out of scope, so reject them explicitly.
    try validateServerName(config.server_name);
    if (config.client_identity != null) {
        switch (config.trust) {
            .tofu => |tofu| if (tofu.known_pin == null) return error.ClientIdentityRequiresKnownPin,
            .webpki => {},
        }
    }
    var name_z: [std.Io.net.HostName.max_len + 1]u8 = undefined;
    @memcpy(name_z[0..config.server_name.len], config.server_name);
    name_z[config.server_name.len] = 0;
    const name_c: [*c]const u8 = &name_z;

    const ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.OutOfMemory;
    conn.ctx = ctx;
    const min: u16 = switch (config.min_version) {
        .tls1_3 => c.TLS1_3_VERSION,
        .tls1_2 => c.TLS1_2_VERSION,
    };
    if (c.SSL_CTX_set_min_proto_version(ctx, min) != 1) return error.LibraryFailure;
    if (c.SSL_CTX_set_max_proto_version(ctx, c.TLS1_3_VERSION) != 1) return error.LibraryFailure;
    // MISUSE-11: BoringSSL's default TLS 1.2 list is "ALL", which includes
    // static-RSA key exchange (no forward secrecy; no server signature over
    // the handshake). Restrict TLS 1.2 to ECDHE + AEAD. TLS 1.3 suites are
    // not governed by this list.
    if (c.SSL_CTX_set_strict_cipher_list(ctx, tls12_ciphers) != 1) return error.LibraryFailure;

    switch (config.trust) {
        .webpki => |w| {
            // MISUSE-1: the return value is the only signal the roots loaded.
            // Ignoring it would leave an empty store: every handshake would
            // fail closed, but for the wrong reason.
            if (c.SSL_CTX_load_verify_locations(ctx, w.roots_pem_file.ptr, null) != 1) {
                conn.captureErrQueue();
                return error.RootsLoadFailed;
            }
        },
        .tofu => {},
    }

    if (config.client_identity) |id| {
        if (c.SSL_CTX_use_certificate_chain_file(ctx, id.chain_pem_file.ptr) != 1 or
            c.SSL_CTX_use_PrivateKey_file(ctx, id.key_pem_file.ptr, c.SSL_FILETYPE_PEM) != 1 or
            c.SSL_CTX_check_private_key(ctx) != 1)
        {
            conn.captureErrQueue();
            return error.ClientIdentityLoadFailed;
        }
    }

    const ssl = c.SSL_new(ctx) orelse return error.OutOfMemory;
    conn.ssl = ssl;
    try requireBlockingSocket(conn.fd, reject_nonblocking);
    if (c.SSL_set_fd(ssl, @intCast(conn.fd)) != 1) return error.LibraryFailure;
    if (c.SSL_set_tlsext_host_name(ssl, name_c) != 1) return error.LibraryFailure;

    switch (config.trust) {
        .webpki => {
            // MISUSE-3: hostname verification only happens if SSL_set1_host
            // succeeds AND verification mode is PEER. Both are checked.
            if (c.SSL_set1_host(ssl, name_c) != 1) return error.LibraryFailure;
            // BoringSSL still falls back to the subject CN when a certificate
            // has no subjectAltName extension at all, unless told not to
            // (x509.h, crbug.com/boringssl/464; crypto/x509/v3_utl.cc).
            c.SSL_set_hostflags(ssl, c.X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
            c.SSL_set_verify(ssl, c.SSL_VERIFY_PEER, null);
        },
        .tofu => |t| {
            conn.tofu = .{
                .known_pin = t.known_pin,
                .host_len = config.server_name.len,
                .name_flags = switch (t.name_check) {
                    .san_only => c.X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,
                    .san_or_common_name => 0,
                },
            };
            @memcpy(conn.tofu.host[0..config.server_name.len], config.server_name);
            c.SSL_set_custom_verify(ssl, c.SSL_VERIFY_PEER, tofuVerifyCallback);
        },
    }

    if (config.alpn.len > 0) {
        var wire: [512]u8 = undefined;
        var n: usize = 0;
        for (config.alpn) |p| {
            if (p.len == 0 or p.len > 255 or n + 1 + p.len > wire.len) return error.InvalidAlpn;
            wire[n] = @intCast(p.len);
            @memcpy(wire[n + 1 ..][0..p.len], p);
            n += 1 + p.len;
        }
        // MISUSE-9: SSL_set_alpn_protos returns 0 on success, unlike almost
        // every other SSL_* setter. Checking `!= 1` would reject every list.
        if (c.SSL_set_alpn_protos(ssl, &wire, n) != 0) return error.InvalidAlpn;
    }

    if (config.io_timeout_ms != 0) setTimeouts(conn.fd, config.io_timeout_ms) catch return error.TransportError;
}

/// RFC 1123 host name that is not an IPv4 address in any spelling and has no
/// trailing dot (RFC 6066 forbids one in SNI). The IPv4 test follows the
/// WHATWG URL "ends in a number" rule, so `127.1`, `0x7f.0.0.1` and
/// `127.0.0.1.` are all refused, not only the canonical dotted quad.
fn validateServerName(name: []const u8) Error!void {
    std.Io.net.HostName.validate(name) catch return error.InvalidServerName;
    if (name[name.len - 1] == '.') return error.InvalidServerName;
    const last = if (std.mem.lastIndexOfScalar(u8, name, '.')) |i| name[i + 1 ..] else name;
    if (endsInNumber(last)) return error.InvalidServerName;
}

fn endsInNumber(label: []const u8) bool {
    if (label.len == 0) return false;
    var all_digits = true;
    for (label) |ch| if (!std.ascii.isDigit(ch)) {
        all_digits = false;
        break;
    };
    if (all_digits) return true;
    if (label.len > 2 and label[0] == '0' and (label[1] == 'x' or label[1] == 'X')) {
        for (label[2..]) |ch| if (!std.ascii.isHex(ch)) return false;
        return true;
    }
    return false;
}

fn setTimeouts(fd: std.posix.fd_t, ms: u32) !void {
    const tv = std.c.timeval{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
    const bytes = std.mem.asBytes(&tv);
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, bytes);
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, bytes);
}

/// Ignore SIGPIPE for the whole process.
///
/// BoringSSL's socket BIO writes with write(2) on POSIX, so writing to a
/// connection the peer has reset raises SIGPIPE, whose default action
/// terminates the process. In Zig 0.17, `std.Io.Threaded.init` installs a
/// no-op SIGPIPE handler for as long as that Io lives (Threaded.zig, `init`)
/// and restores the old one in `deinit`, so programs using the default Io
/// are already covered. Call this if you use another Io implementation, or
/// use the wrapper outside an Io.Threaded's lifetime. Writes then fail with
/// `error.TransportError`. The wrapper never changes signal dispositions on
/// its own (MISUSE-10).
pub fn ignoreSigpipe() void {
    if (@import("builtin").os.tag == .windows) return;
    const act: std.posix.Sigaction = .{
        .handler = .{ .handler = std.posix.SIG.IGN },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.PIPE, &act, null);
}

extern "c" fn close(fd: c_int) c_int;
extern "c" fn time(t: ?*std.c.time_t) std.c.time_t;

fn closeFd(fd: std.posix.fd_t) void {
    _ = close(@intCast(fd));
}

// ---------------------------------------------------------------------------
// TOFU verification callback
// ---------------------------------------------------------------------------

const TofuState = struct {
    known_pin: ?Pin = null,
    host: [std.Io.net.HostName.max_len]u8 = undefined,
    host_len: usize = 0,
    name_flags: c_uint = c.X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,
    observed: ?Pin = null,
    decision: ?TrustEvidence = null,
    failure: ?Error = null,
};

var ex_index: std.atomic.Value(c_int) = .init(-1);
fn exDataIndex() c_int {
    const cur = ex_index.load(.acquire);
    if (cur >= 0) return cur;
    const fresh = c.SSL_get_ex_new_index(0, null, null, null, null);
    // First writer wins; a losing thread leaks one ex_data slot (harmless)
    // but then uses the winner's index, so set/get always agree.
    // A negative index makes SSL_set_ex_data fail, which handshake()
    // reports as LibraryFailure; the callback is never silently skipped.
    return ex_index.cmpxchgStrong(-1, fresh, .acq_rel, .acquire) orelse fresh;
}

fn tofuVerifyCallback(ssl: ?*c.SSL, out_alert: [*c]u8) callconv(.c) c_uint {
    const raw = c.SSL_get_ex_data(ssl, exDataIndex()) orelse {
        out_alert.* = c.SSL_AD_INTERNAL_ERROR;
        return c.ssl_verify_invalid; // fail closed: no context, no trust
    };
    const st: *TofuState = @ptrCast(@alignCast(raw));
    const result = tofuDecide(ssl, st);
    if (result) |evidence| {
        st.decision = evidence;
        return c.ssl_verify_ok;
    } else |err| {
        st.failure = err;
        out_alert.* = switch (err) {
            error.CertificateExpired => c.SSL_AD_CERTIFICATE_EXPIRED,
            error.NoPeerCertificate, error.CertificateInvalid => c.SSL_AD_BAD_CERTIFICATE,
            else => c.SSL_AD_CERTIFICATE_UNKNOWN,
        };
        return c.ssl_verify_invalid;
    }
}

fn tofuDecide(ssl: ?*c.SSL, st: *TofuState) Error!TrustEvidence {
    // NB: the callback runs before BoringSSL checks CertificateVerify, so
    // `ssl_verify_ok` here is not yet proof of key possession; a forged
    // CertificateVerify still aborts the handshake afterwards.
    const chain = peerChain(ssl) orelse return error.NoPeerCertificate;
    if (c.OPENSSL_sk_num(chain) == 0) return error.NoPeerCertificate;
    const leaf_buf: ?*c.CRYPTO_BUFFER = @ptrCast(c.OPENSSL_sk_value(chain, 0));
    const leaf = c.X509_parse_from_buffer(leaf_buf) orelse return error.CertificateInvalid;
    defer c.X509_free(leaf);

    // Pin first, so `observedPin()` is available for every failure below.
    const pin = try leafSpkiPin(leaf);
    st.observed = pin;

    // MISUSE-5: X509_cmp_time_posix returns 0 on *error*, negative if the
    // time is <= now, positive if after. Treating 0 as "fine" would accept
    // unparseable validity fields.
    const now: i64 = time(null);
    const nb = c.X509_cmp_time_posix(c.X509_get0_notBefore(leaf), now);
    const na = c.X509_cmp_time_posix(c.X509_get0_notAfter(leaf), now);
    if (nb == 0 or na == 0) return error.CertificateInvalid;
    if (nb > 0) return error.CertificateNotYetValid;
    if (na <= 0) return error.CertificateExpired;

    // MISUSE-6: X509_check_host returns 1 on match, 0 on mismatch, and
    // negative values on error. Only exactly 1 is acceptance.
    if (c.X509_check_host(leaf, &st.host, st.host_len, st.name_flags, null) != 1)
        return error.CertificateHostnameMismatch;

    if (st.known_pin) |known| {
        if (!known.eql(pin)) return error.PinMismatch;
        return .{ .pin_matched = pin };
    }
    return .{ .first_use = pin };
}

/// SSL_get0_peer_certificates as a generic stack (the C sk_CRYPTO_BUFFER_*
/// inlines perform the same cast).
fn peerChain(ssl: ?*const c.SSL) ?*const c.OPENSSL_STACK {
    return @ptrCast(c.SSL_get0_peer_certificates(ssl));
}

fn leafSpkiPin(x: *c.X509) Error!Pin {
    const pk = c.X509_get_X509_PUBKEY(x) orelse return error.CertificateInvalid;
    var der: [*c]u8 = null;
    const len = c.i2d_X509_PUBKEY(pk, &der);
    if (len <= 0 or der == null) return error.CertificateInvalid;
    defer c.OPENSSL_free(der);
    var p: Pin = undefined;
    std.crypto.hash.sha2.Sha256.hash(der[0..@intCast(len)], &p.sha256, .{});
    return p;
}

fn mapVerifyResult(vr: c_long) Error {
    return switch (vr) {
        c.X509_V_ERR_CERT_HAS_EXPIRED => error.CertificateExpired,
        c.X509_V_ERR_CERT_NOT_YET_VALID => error.CertificateNotYetValid,
        c.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, c.X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN => error.CertificateSelfSigned,
        c.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
        c.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
        c.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
        => error.CertificateUntrusted,
        c.X509_V_ERR_HOSTNAME_MISMATCH => error.CertificateHostnameMismatch,
        else => error.CertificateInvalid,
    };
}

// ---------------------------------------------------------------------------
// Handshake result and Session (post-handshake)
// ---------------------------------------------------------------------------

pub const HandshakeResult = union(enum) {
    established: Session,
    first_use: *FirstUseSession,
};

const FirstUseState = struct { session: ?Session, pin: Pin };

/// Opaque first-use TOFU handle. Its underlying Session is intentionally not
/// exposed: application I/O is unavailable until acknowledgePersistedPin.
/// The library cannot itself guarantee durable storage, so acknowledgement is
/// the caller's assertion that the presented pin was persisted safely.
pub const FirstUseSession = opaque {
    fn state(self: *FirstUseSession) *FirstUseState {
        return @ptrCast(@alignCast(self));
    }

    pub fn presentedPin(self: *const FirstUseSession) Pin {
        const inner: *const FirstUseState = @ptrCast(@alignCast(self));
        return inner.pin;
    }

    pub fn acknowledgePersistedPin(self: *FirstUseSession, persisted: Pin) Error!Session {
        const inner = self.state();
        if (!inner.pin.eql(persisted)) return error.PinMismatch;
        const session = inner.session orelse return error.AlreadyConsumed;
        inner.session = null;
        return session;
    }

    /// Reject the first-use connection without sending application data.
    pub fn deinit(self: *FirstUseSession) void {
        const inner = self.state();
        if (inner.session) |*session| session.release();
        std.heap.page_allocator.destroy(inner);
    }
};

pub const Session = struct {
    ssl: ?*c.SSL,
    ctx: ?*c.SSL_CTX,
    fd: std.posix.fd_t,
    owns_fd: bool,
    evidence: TrustEvidence,

    pub fn trust(self: *const Session) TrustEvidence {
        return self.evidence;
    }

    /// Read decrypted bytes. Returns 0 only on a clean close_notify from the
    /// peer. A transport EOF without close_notify is `error.Truncated`; an
    /// empty `buf` is `error.EmptyBuffer`. Treat `error.Timeout` as fatal.
    pub fn read(self: *Session, buf: []u8) Error!usize {
        const ssl = self.ssl orelse return error.Closed;
        if (buf.len == 0) return error.EmptyBuffer;
        const n: c_int = @intCast(@min(buf.len, std.math.maxInt(c_int)));
        c.ERR_clear_error();
        const rc = c.SSL_read(ssl, buf.ptr, n);
        if (rc > 0) return @intCast(rc);
        return switch (c.SSL_get_error(ssl, rc)) {
            c.SSL_ERROR_ZERO_RETURN => 0,
            c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => error.Timeout,
            // MISUSE-7: SYSCALL with rc == 0 is EOF *without* close_notify.
            // Returning 0 here would hide a truncation attack.
            c.SSL_ERROR_SYSCALL => if (rc == 0) error.Truncated else error.TransportError,
            else => error.ProtocolError,
        };
    }

    /// Write all of `bytes` or fail. (BoringSSL does not do partial writes
    /// on a blocking socket unless SSL_MODE_ENABLE_PARTIAL_WRITE is set,
    /// which this wrapper never sets.)
    pub fn writeAll(self: *Session, bytes: []const u8) Error!void {
        const ssl = self.ssl orelse return error.Closed;
        var rest = bytes;
        while (rest.len > 0) {
            const n: c_int = @intCast(@min(rest.len, std.math.maxInt(c_int)));
            c.ERR_clear_error();
            const rc = c.SSL_write(ssl, rest.ptr, n);
            if (rc <= 0) return switch (c.SSL_get_error(ssl, rc)) {
                c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => error.Timeout,
                c.SSL_ERROR_ZERO_RETURN => error.ConnectionClosed,
                c.SSL_ERROR_SYSCALL => error.TransportError,
                else => error.ProtocolError,
            };
            rest = rest[@intCast(rc)..];
        }
    }

    fn release(self: *Session) void {
        if (self.ssl) |ssl| c.SSL_free(ssl);
        if (self.ctx) |ctx| c.SSL_CTX_free(ctx);
        if (self.owns_fd) closeFd(self.fd);
        self.ssl = null;
        self.ctx = null;
        self.owns_fd = false;
    }

    /// Send close_notify (without waiting for the peer's) and release
    /// everything. Resources are freed even if this returns an error;
    /// the error only reports that close_notify could not be sent.
    pub fn close(self: *Session) Error!void {
        const ssl = self.ssl orelse return; // idempotent
        c.ERR_clear_error();
        const rc = c.SSL_shutdown(ssl);
        self.release();
        // SSL_shutdown: 0 = close_notify sent, peer's not yet seen; 1 = both.
        if (rc < 0) return error.TransportError;
    }

    pub fn protocolVersion(self: *const Session) Error!enum { tls1_2, tls1_3 } {
        const ssl = self.ssl orelse return error.Closed;
        return switch (c.SSL_version(ssl)) {
            c.TLS1_3_VERSION => .tls1_3,
            c.TLS1_2_VERSION => .tls1_2,
            else => error.ProtocolError, // unreachable given min/max settings
        };
    }

    pub fn cipherName(self: *const Session) Error![]const u8 {
        const ssl = self.ssl orelse return error.Closed;
        const ci = c.SSL_get_current_cipher(ssl) orelse return error.ProtocolError;
        const name = c.SSL_CIPHER_get_name(ci) orelse return error.ProtocolError;
        return std.mem.span(name);
    }

    /// Negotiated ALPN protocol, or null if none was agreed.
    /// The slice is valid until close().
    pub fn alpn(self: *const Session) Error!?[]const u8 {
        const ssl = self.ssl orelse return error.Closed;
        var p: [*c]const u8 = null;
        var len: c_uint = 0;
        c.SSL_get0_alpn_selected(ssl, &p, &len);
        if (p == null or len == 0) return null;
        return p[0..len];
    }

    /// The peer's leaf certificate. Borrowed: valid until close().
    pub fn peerCertificate(self: *const Session) Error!PeerCertificate {
        const ssl = self.ssl orelse return error.Closed;
        const chain = peerChain(ssl) orelse return error.NoPeerCertificate;
        const count = c.OPENSSL_sk_num(chain);
        if (count == 0) return error.NoPeerCertificate;
        const buf: ?*c.CRYPTO_BUFFER = @ptrCast(c.OPENSSL_sk_value(chain, 0));
        const data = c.CRYPTO_BUFFER_data(buf);
        const len = c.CRYPTO_BUFFER_len(buf);
        if (data == null or len == 0) return error.NoPeerCertificate;
        return .{ .buffer = buf.?, .der = data[0..len], .chain_len = count };
    }
};

/// Read-only view of a peer certificate. Inspection only: nothing here
/// re-verifies anything, and none of it should feed a trust decision
/// except via `spkiPin()` in a TOFU store.
pub const PeerCertificate = struct {
    buffer: *c.CRYPTO_BUFFER,
    der: []const u8,
    chain_len: usize,

    pub fn sha256Fingerprint(self: PeerCertificate) [32]u8 {
        var out: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(self.der, &out, .{});
        return out;
    }

    pub fn spkiPin(self: PeerCertificate) Error!Pin {
        const x = c.X509_parse_from_buffer(self.buffer) orelse return error.CertificateInvalid;
        defer c.X509_free(x);
        return leafSpkiPin(x);
    }

    pub const Validity = struct { not_before: i64, not_after: i64 };

    pub fn validity(self: PeerCertificate) Error!Validity {
        const x = c.X509_parse_from_buffer(self.buffer) orelse return error.CertificateInvalid;
        defer c.X509_free(x);
        var v: Validity = undefined;
        if (c.ASN1_TIME_to_posix(c.X509_get0_notBefore(x), &v.not_before) != 1) return error.CertificateInvalid;
        if (c.ASN1_TIME_to_posix(c.X509_get0_notAfter(x), &v.not_after) != 1) return error.CertificateInvalid;
        return v;
    }

    /// One-line subject DN (OpenSSL "/CN=..." format) written into `out`.
    pub fn subject(self: PeerCertificate, out: []u8) Error![]const u8 {
        return self.nameInto(out, .subject);
    }

    pub fn issuer(self: PeerCertificate, out: []u8) Error![]const u8 {
        return self.nameInto(out, .issuer);
    }

    fn nameInto(self: PeerCertificate, out: []u8, which: enum { subject, issuer }) Error![]const u8 {
        if (out.len == 0) return error.BufferTooSmall;
        const x = c.X509_parse_from_buffer(self.buffer) orelse return error.CertificateInvalid;
        defer c.X509_free(x);
        const name = switch (which) {
            .subject => c.X509_get_subject_name(x),
            .issuer => c.X509_get_issuer_name(x),
        } orelse return error.CertificateInvalid;
        // The caller-buffer form of X509_NAME_oneline can silently omit whole
        // trailing entries. Its allocating form grows a complete result.
        const full = c.X509_NAME_oneline(name, null, 0);
        if (full == null) return error.CertificateInvalid;
        defer c.OPENSSL_free(full);
        const text = std.mem.span(full);
        if (text.len > out.len) return error.BufferTooSmall;
        @memcpy(out[0..text.len], text);
        return out[0..text.len];
    }
};

// ---------------------------------------------------------------------------
// Unit tests (no network)
// ---------------------------------------------------------------------------

test "Pin hex round-trip and constant-time equality" {
    const hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const p = try Pin.fromHex(hex);
    try std.testing.expectEqualStrings(hex, &p.toHex());
    var q = p;
    try std.testing.expect(p.eql(q));
    q.sha256[31] ^= 1;
    try std.testing.expect(!p.eql(q));
    try std.testing.expectError(error.InvalidPin, Pin.fromHex("zz"));
    try std.testing.expectError(error.InvalidPin, Pin.fromHex(hex[0..63]));
}

test "mapVerifyResult covers the cases tests rely on" {
    try std.testing.expectEqual(error.CertificateExpired, mapVerifyResult(c.X509_V_ERR_CERT_HAS_EXPIRED));
    try std.testing.expectEqual(error.CertificateSelfSigned, mapVerifyResult(c.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT));
    try std.testing.expectEqual(error.CertificateHostnameMismatch, mapVerifyResult(c.X509_V_ERR_HOSTNAME_MISMATCH));
    try std.testing.expectEqual(error.CertificateUntrusted, mapVerifyResult(c.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY));
    try std.testing.expectEqual(error.CertificateInvalid, mapVerifyResult(c.X509_V_ERR_INVALID_CA));
}

test "Config cannot express 'no verification'" {
    // Compile-time property: Trust has exactly these two variants.
    const names = @typeInfo(Trust).@"union".field_names;
    try std.testing.expectEqual(@as(usize, 2), names.len);
    try std.testing.expectEqualStrings("webpki", names[0]);
    try std.testing.expectEqualStrings("tofu", names[1]);
}

test "server_name: IPv4 in any spelling, and trailing dots, are refused" {
    for ([_][]const u8{ "127.0.0.1", "127.0.0.1.", "127.1", "0x7f.0.0.1", "example.com.", "a.1", "1" }) |n| {
        std.testing.expectError(error.InvalidServerName, validateServerName(n)) catch |e| {
            std.debug.print("accepted: {s}\n", .{n});
            return e;
        };
    }
    for ([_][]const u8{ "localhost", "example.com", "1a.example", "xn--bcher-kva.example", "a.b0", "service.0x", "service.0X" }) |n| try validateServerName(n);
}

test "invalid server names are rejected before any TLS state exists" {
    try std.testing.expectError(error.InvalidServerName, fromFd(-1, .{
        .server_name = "127.0.0.1",
        .trust = .{ .tofu = .{ .known_pin = null } },
        .io_timeout_ms = 0,
    }));
    try std.testing.expectError(error.InvalidServerName, fromFd(-1, .{
        .server_name = "",
        .trust = .{ .tofu = .{ .known_pin = null } },
        .io_timeout_ms = 0,
    }));
    try std.testing.expectError(error.InvalidServerName, fromFd(-1, .{
        .server_name = "bad name",
        .trust = .{ .tofu = .{ .known_pin = null } },
        .io_timeout_ms = 0,
    }));
}
