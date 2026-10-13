// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
//
// Integration tests: real TLS handshakes over loopback TCP against an
// in-process BoringSSL server running on its own thread.
//
// Caveat (also in docs/security/TLS-WRAPPER-SECURITY.adoc): client and server are the same library, so a
// bug shared by both ends could cancel out. These tests check that the
// wrapper turns on the right checks and reports the right errors; they are
// not an interoperability or conformance suite.

const std = @import("std");
const tls = @import("boringtls");
const c = tls.c;
const fixtures = @import("fixtures");

const io = std.testing.io;

fn fx(comptime name: []const u8) [:0]const u8 {
    return fixtures.dir ++ "/" ++ name;
}

fn expectedPin(comptime name: []const u8) tls.Pin {
    // Pins computed independently by OpenSSL in scripts/gen-fixtures.sh,
    // which build.zig runs into a fresh directory for each test build.
    var buf: [4096]u8 = undefined;
    const pins = std.Io.Dir.cwd().readFile(io, fx("pins.txt"), &buf) catch @panic("cannot read pins.txt");
    var it = std.mem.tokenizeScalar(u8, pins, '\n');
    while (it.next()) |line| {
        var parts = std.mem.tokenizeScalar(u8, line, ' ');
        const k = parts.next().?;
        const v = parts.next().?;
        if (std.mem.eql(u8, k, name)) return tls.Pin.fromHex(v) catch unreachable;
    }
    @panic("no pin for " ++ name);
}

// ---------------------------------------------------------------------------
// Test server
// ---------------------------------------------------------------------------

const ServerOpts = struct {
    cert: [:0]const u8,
    key: [:0]const u8,
    require_client_cert: bool = false,
    alpn_h2: bool = false,
    max_tls12: bool = false,
    /// Send the payload, then drop TCP without close_notify.
    abrupt_close: bool = false,
    /// Complete the handshake, then close TCP immediately.
    close_after_handshake: bool = false,
    /// TLS 1.2 cipher list for the server (implies max TLS 1.2 when set).
    tls12_cipher_list: ?[:0]const u8 = null,
};

const ServerResult = struct {
    handshake_ok: bool = false,
    got_client_cert: bool = false,
    bytes_echoed: usize = 0,
};

const TestServer = struct {
    listener: std.Io.net.Server,
    port: u16,
    thread: std.Thread,
    result: ServerResult = .{},
    opts: ServerOpts,

    fn start(self: *TestServer, opts: ServerOpts) !void {
        const addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        self.* = .{
            .listener = try addr.listen(io, .{ .reuse_address = true }),
            .port = 0,
            .thread = undefined,
            .opts = opts,
        };
        self.port = self.listener.socket.address.getPort();
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn join(self: *TestServer) ServerResult {
        self.thread.join();
        self.listener.deinit(io);
        return self.result;
    }

    fn alpnSelect(ssl: ?*c.SSL, out: [*c][*c]const u8, out_len: [*c]u8, in: [*c]const u8, in_len: c_uint, arg: ?*anyopaque) callconv(.c) c_int {
        _ = ssl;
        _ = arg;
        const ours = "\x02h2";
        var sel: [*c]u8 = null;
        if (c.SSL_select_next_proto(&sel, out_len, ours, ours.len, in, in_len) != c.OPENSSL_NPN_NEGOTIATED)
            return c.SSL_TLSEXT_ERR_ALERT_FATAL;
        out.* = sel;
        return c.SSL_TLSEXT_ERR_OK;
    }

    fn run(self: *TestServer) void {
        const stream = self.listener.accept(io) catch return;
        defer stream.close(io);
        const fd = stream.socket.handle;
        const tv = std.c.timeval{ .sec = 5, .usec = 0 };
        std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};

        const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return;
        defer c.SSL_CTX_free(ctx);
        if (c.SSL_CTX_use_certificate_chain_file(ctx, self.opts.cert.ptr) != 1) @panic("server cert");
        if (c.SSL_CTX_use_PrivateKey_file(ctx, self.opts.key.ptr, c.SSL_FILETYPE_PEM) != 1) @panic("server key");
        if (self.opts.max_tls12 or self.opts.tls12_cipher_list != null) _ = c.SSL_CTX_set_max_proto_version(ctx, c.TLS1_2_VERSION);
        if (self.opts.tls12_cipher_list) |cl| {
            if (c.SSL_CTX_set_strict_cipher_list(ctx, cl.ptr) != 1) @panic("server cipher list");
        }
        if (self.opts.require_client_cert) {
            if (c.SSL_CTX_load_verify_locations(ctx, fx("ca.pem").ptr, null) != 1) @panic("server CA");
            c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER | c.SSL_VERIFY_FAIL_IF_NO_PEER_CERT, null);
        }
        if (self.opts.alpn_h2) c.SSL_CTX_set_alpn_select_cb(ctx, alpnSelect, null);

        const ssl = c.SSL_new(ctx) orelse return;
        defer c.SSL_free(ssl);
        _ = c.SSL_set_fd(ssl, @intCast(fd));
        if (c.SSL_accept(ssl) != 1) return;
        self.result.handshake_ok = true;
        if (c.SSL_get0_peer_certificates(ssl)) |chain| {
            self.result.got_client_cert = c.OPENSSL_sk_num(@ptrCast(chain)) > 0;
        }

        if (self.opts.close_after_handshake) return;
        // Echo one message back prefixed with "pong:".
        var buf: [256]u8 = undefined;
        const n = c.SSL_read(ssl, &buf, buf.len);
        if (n <= 0) return;
        var reply: [300]u8 = undefined;
        const msg = std.fmt.bufPrint(&reply, "pong:{s}", .{buf[0..@intCast(n)]}) catch return;
        if (c.SSL_write(ssl, msg.ptr, @intCast(msg.len)) != msg.len) return;
        self.result.bytes_echoed = msg.len;
        if (self.opts.abrupt_close) return; // no close_notify; stream closes in defer
        _ = c.SSL_shutdown(ssl);
    }
};

fn webpki(roots: [:0]const u8) tls.Trust {
    return .{ .webpki = .{ .roots_pem_file = roots } };
}

const default_ca = fx("ca.pem");

/// Connect to the test server and run the handshake.
fn dial(srv: *TestServer, cfg: tls.Config, conn_out: *tls.Connection) tls.Error!tls.Session {
    conn_out.* = try tls.connect(io, "127.0.0.1", srv.port, cfg);
    return conn_out.handshake();
}

fn pingPong(s: *tls.Session) !void {
    try s.writeAll("ping");
    var buf: [64]u8 = undefined;
    var got: usize = 0;
    while (got < "pong:ping".len) {
        const n = try s.read(buf[got..]);
        if (n == 0) break;
        got += n;
    }
    try std.testing.expectEqualStrings("pong:ping", buf[0..got]);
}

// ---------------------------------------------------------------------------
// WebPKI path (DoH-style)
// ---------------------------------------------------------------------------

test "webpki: valid chain + matching SAN succeeds over TLS 1.3" {
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("server.pem"), .key = fx("server.key") });
    var conn: tls.Connection = undefined;
    var s = try dial(&srv, .{ .server_name = "localhost", .trust = webpki(default_ca) }, &conn);
    try std.testing.expect(s.trust() == .webpki_verified);
    try std.testing.expectEqual(.tls1_3, try s.protocolVersion());
    try pingPong(&s);

    // Certificate inspection
    const cert = try s.peerCertificate();
    var name_buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("/CN=localhost", try cert.subject(&name_buf));
    try std.testing.expectEqualStrings("/CN=boringtls Test Root", try cert.issuer(&name_buf));
    try std.testing.expect((try cert.spkiPin()).eql(expectedPin("server")));
    const v = try cert.validity();
    try std.testing.expectEqual(@as(i64, 1767225600), v.not_before); // 2026-01-01T00:00:00Z
    try std.testing.expectEqual(@as(i64, 4922899200), v.not_after); // 2126-01-01T00:00:00Z
    try std.testing.expectEqual(@as(usize, 1), cert.chain_len);

    try s.close();
    try std.testing.expectError(error.Closed, s.read(&name_buf)); // use-after-close is an error
    try s.close(); // idempotent
    const r = srv.join();
    try std.testing.expect(r.handshake_ok);
}

test "webpki: second SAN also matches" {
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("server.pem"), .key = fx("server.key") });
    var conn: tls.Connection = undefined;
    var s = try dial(&srv, .{ .server_name = "test.example", .trust = webpki(default_ca) }, &conn);
    try pingPong(&s);
    try s.close();
    _ = srv.join();
}

fn expectWebpkiFailure(expected: tls.Error, opts: ServerOpts, server_name: []const u8, roots: [:0]const u8) !void {
    var srv: TestServer = undefined;
    try srv.start(opts);
    var conn: tls.Connection = undefined;
    const res = dial(&srv, .{ .server_name = server_name, .trust = webpki(roots) }, &conn);
    try std.testing.expectError(expected, res);
    const r = srv.join();
    try std.testing.expect(!r.handshake_ok); // the server never got an established session
}

test "webpki: hostname mismatch is rejected" {
    try expectWebpkiFailure(error.CertificateHostnameMismatch, .{ .cert = fx("wrong_host.pem"), .key = fx("other.key") }, "localhost", default_ca);
}

test "webpki: subject CN is not used as a fallback name" {
    // cn_only.pem has CN=localhost and no SAN. BoringSSL would accept it by
    // default; the wrapper sets X509_CHECK_FLAG_NEVER_CHECK_SUBJECT.
    try expectWebpkiFailure(error.CertificateHostnameMismatch, .{ .cert = fx("cn_only.pem"), .key = fx("cnonly.key") }, "localhost", default_ca);
}

test "webpki: expired certificate is rejected" {
    try expectWebpkiFailure(error.CertificateExpired, .{ .cert = fx("expired.pem"), .key = fx("expired.key") }, "localhost", default_ca);
}

test "webpki: not-yet-valid certificate is rejected" {
    try expectWebpkiFailure(error.CertificateNotYetValid, .{ .cert = fx("not_yet_valid.pem"), .key = fx("future.key") }, "localhost", default_ca);
}

test "webpki: self-signed certificate is rejected" {
    try expectWebpkiFailure(error.CertificateSelfSigned, .{ .cert = fx("gemini_self.pem"), .key = fx("gemini.key") }, "localhost", default_ca);
}

test "webpki: chain to an unconfigured root is rejected" {
    // Valid server chain, but the client trusts a different (self-signed) root.
    try expectWebpkiFailure(error.CertificateUntrusted, .{ .cert = fx("server.pem"), .key = fx("server.key") }, "localhost", fx("gemini_self.pem"));
}

test "webpki: leaf signed by a non-CA leaf is rejected (zig#35877 shape)" {
    // BoringSSL never considers a CA:FALSE certificate as an issuer, so path
    // building finds no issuer for the forged leaf: UNABLE_TO_GET_ISSUER_*.
    try expectWebpkiFailure(error.CertificateUntrusted, .{ .cert = fx("evil_chain.pem"), .key = fx("evil.key") }, "evil.example", default_ca);
}

test "webpki: unreadable roots file is a configuration error, not a silent empty store" {
    try std.testing.expectError(error.RootsLoadFailed, tls.fromFd(-1, .{
        .server_name = "localhost",
        .trust = webpki(fx("does-not-exist.pem")),
        .io_timeout_ms = 0,
    }));
}

test "webpki: TLS 1.2-only server is refused when min_version is tls1_3" {
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("server.pem"), .key = fx("server.key"), .max_tls12 = true });
    var conn: tls.Connection = undefined;
    try std.testing.expectError(error.HandshakeFailed, dial(&srv, .{ .server_name = "localhost", .trust = webpki(default_ca) }, &conn));
    try std.testing.expect(conn.diagnostic().len > 0);
    _ = srv.join();
}

test "ALPN: h2 is negotiated (DoH prerequisite)" {
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("server.pem"), .key = fx("server.key"), .alpn_h2 = true });
    var conn: tls.Connection = undefined;
    var s = try dial(&srv, .{ .server_name = "localhost", .trust = webpki(default_ca), .alpn = &.{ "h2", "http/1.1" } }, &conn);
    try std.testing.expectEqualStrings("h2", (try s.alpn()).?);
    try pingPong(&s);
    try s.close();
    _ = srv.join();
}

test "read: EOF without close_notify is reported as Truncated, not as end of stream" {
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("server.pem"), .key = fx("server.key"), .abrupt_close = true });
    var conn: tls.Connection = undefined;
    var s = try dial(&srv, .{ .server_name = "localhost", .trust = webpki(default_ca) }, &conn);
    try pingPong(&s);
    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.Truncated, s.read(&buf));
    s.close() catch {};
    _ = srv.join();
}

test "read: clean close_notify yields 0" {
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("server.pem"), .key = fx("server.key") });
    var conn: tls.Connection = undefined;
    var s = try dial(&srv, .{ .server_name = "localhost", .trust = webpki(default_ca) }, &conn);
    try pingPong(&s);
    var buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try s.read(&buf));
    try s.close();
    _ = srv.join();
}

test "handshake: a Connection cannot be handshaken twice" {
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("server.pem"), .key = fx("server.key") });
    var conn: tls.Connection = undefined;
    var s = try dial(&srv, .{ .server_name = "localhost", .trust = webpki(default_ca) }, &conn);
    try std.testing.expectError(error.AlreadyConsumed, conn.handshake());
    try pingPong(&s);
    try s.close();
    _ = srv.join();
}

// ---------------------------------------------------------------------------
// TOFU path (Gemini)
// ---------------------------------------------------------------------------

fn tofu(pin: ?tls.Pin) tls.Trust {
    return .{ .tofu = .{ .known_pin = pin } };
}

test "tofu: first use accepts a self-signed cert and reports the pin to store" {
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("gemini_self.pem"), .key = fx("gemini.key") });
    var conn: tls.Connection = undefined;
    var s = try dial(&srv, .{ .server_name = "localhost", .trust = tofu(null), .min_version = .tls1_2 }, &conn);
    switch (s.trust()) {
        .first_use => |p| try std.testing.expect(p.eql(expectedPin("gemini_self"))),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect((try (try s.peerCertificate()).spkiPin()).eql(expectedPin("gemini_self")));
    try pingPong(&s);
    try s.close();
    _ = srv.join();
}

test "tofu: matching stored pin is accepted as pin_matched" {
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("gemini_self.pem"), .key = fx("gemini.key") });
    var conn: tls.Connection = undefined;
    var s = try dial(&srv, .{ .server_name = "localhost", .trust = tofu(expectedPin("gemini_self")) }, &conn);
    try std.testing.expect(s.trust() == .pin_matched);
    try pingPong(&s);
    try s.close();
    _ = srv.join();
}

test "tofu: changed key is rejected with PinMismatch before any application data" {
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("gemini_self_rekeyed.pem"), .key = fx("gemini2.key") });
    var conn: tls.Connection = undefined;
    try std.testing.expectError(error.PinMismatch, dial(&srv, .{ .server_name = "localhost", .trust = tofu(expectedPin("gemini_self")) }, &conn));
    // The caller can show the user what the server now presents.
    try std.testing.expect(conn.observedPin().?.eql(expectedPin("gemini_self_rekeyed")));
    const r = srv.join();
    try std.testing.expect(!r.handshake_ok);
    try std.testing.expectEqual(@as(usize, 0), r.bytes_echoed);
}

test "tofu: expired self-signed cert is rejected even on first use" {
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("gemini_expired.pem"), .key = fx("gemexp.key") });
    var conn: tls.Connection = undefined;
    try std.testing.expectError(error.CertificateExpired, dial(&srv, .{ .server_name = "localhost", .trust = tofu(null) }, &conn));
    _ = srv.join();
}

test "tofu: name must match the certificate" {
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("gemini_self.pem"), .key = fx("gemini.key") });
    var conn: tls.Connection = undefined;
    try std.testing.expectError(error.CertificateHostnameMismatch, dial(&srv, .{ .server_name = "other.example", .trust = tofu(null) }, &conn));
    _ = srv.join();
}

test "tofu: CN encoded as OCTET STRING (X509_check_host error) is refused, not matched" {
    // Peer-controlled encoding makes X509_check_host return a negative value
    // (UNKNOWN_TAG). Only a return of exactly 1 may count as a match.
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("gemini_cn_octet.pem"), .key = fx("gemcn.key") });
    var conn: tls.Connection = undefined;
    try std.testing.expectError(error.CertificateHostnameMismatch, dial(&srv, .{ .server_name = "victim.example", .trust = tofu(null) }, &conn));
    const r = srv.join();
    try std.testing.expect(!r.handshake_ok);
}

test "tofu: CN-only cert accepted under san_or_common_name, refused under san_only" {
    {
        var srv: TestServer = undefined;
        try srv.start(.{ .cert = fx("gemini_cn_only.pem"), .key = fx("gemcn.key") });
        var conn: tls.Connection = undefined;
        var s = try dial(&srv, .{ .server_name = "localhost", .trust = tofu(null) }, &conn);
        try std.testing.expect(s.trust().first_use.eql(expectedPin("gemini_cn_only")));
        try pingPong(&s);
        try s.close();
        _ = srv.join();
    }
    {
        var srv: TestServer = undefined;
        try srv.start(.{ .cert = fx("gemini_cn_only.pem"), .key = fx("gemcn.key") });
        var conn: tls.Connection = undefined;
        const cfg: tls.Config = .{ .server_name = "localhost", .trust = .{ .tofu = .{ .known_pin = null, .name_check = .san_only } } };
        try std.testing.expectError(error.CertificateHostnameMismatch, dial(&srv, cfg, &conn));
        _ = srv.join();
    }
}

test "tofu: pin is of the key, so a CA-issued cert can also be pinned" {
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("server.pem"), .key = fx("server.key") });
    var conn: tls.Connection = undefined;
    var s = try dial(&srv, .{ .server_name = "localhost", .trust = tofu(expectedPin("server")) }, &conn);
    try std.testing.expect(s.trust() == .pin_matched);
    try s.close();
    _ = srv.join();
}

// ---------------------------------------------------------------------------
// Client certificates
// ---------------------------------------------------------------------------

test "client cert: presented when configured and accepted by the server" {
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("server.pem"), .key = fx("server.key"), .require_client_cert = true });
    var conn: tls.Connection = undefined;
    var s = try dial(&srv, .{
        .server_name = "localhost",
        .trust = webpki(default_ca),
        .client_identity = .{ .chain_pem_file = fx("client.pem"), .key_pem_file = fx("client.key") },
    }, &conn);
    try pingPong(&s);
    try s.close();
    const r = srv.join();
    try std.testing.expect(r.handshake_ok and r.got_client_cert);
}

test "client cert: server rejection surfaces on first read under TLS 1.3" {
    // In TLS 1.3 the client finishes its side of the handshake before the
    // server judges the client certificate, so SSL_connect succeeds and
    // the rejection alert arrives on the first read.
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("server.pem"), .key = fx("server.key"), .require_client_cert = true });
    var conn: tls.Connection = undefined;
    var s = try dial(&srv, .{ .server_name = "localhost", .trust = webpki(default_ca) }, &conn);
    s.writeAll("ping") catch {};
    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.ProtocolError, s.read(&buf));
    s.close() catch {};
    const r = srv.join();
    try std.testing.expect(!r.handshake_ok);
}

test "client cert: unreadable identity files are a configuration error" {
    try std.testing.expectError(error.ClientIdentityLoadFailed, tls.fromFd(-1, .{
        .server_name = "localhost",
        .trust = webpki(default_ca),
        .client_identity = .{ .chain_pem_file = fx("nope.pem"), .key_pem_file = fx("nope.key") },
        .io_timeout_ms = 0,
    }));
    // Mismatched cert/key pair.
    try std.testing.expectError(error.ClientIdentityLoadFailed, tls.fromFd(-1, .{
        .server_name = "localhost",
        .trust = webpki(default_ca),
        .client_identity = .{ .chain_pem_file = fx("client.pem"), .key_pem_file = fx("server.key") },
        .io_timeout_ms = 0,
    }));
}

test "write to a reset peer is an explicit error, not process death" {
    // std.testing.io (Io.Threaded) already installs a no-op SIGPIPE handler;
    // ignoreSigpipe() is called too so the test does not depend on that.
    tls.ignoreSigpipe();
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("server.pem"), .key = fx("server.key"), .close_after_handshake = true });
    var conn: tls.Connection = undefined;
    var s = try dial(&srv, .{ .server_name = "localhost", .trust = webpki(default_ca) }, &conn);
    _ = srv.join(); // server has closed its socket
    const chunk: [1024]u8 = @splat('x');
    var i: usize = 0;
    const err = while (i < 1000) : (i += 1) {
        s.writeAll(&chunk) catch |e| break e;
    } else return error.TestUnexpectedResult;
    try std.testing.expect(err == error.TransportError or err == error.ConnectionClosed);
    s.close() catch {};
}

test "TLS 1.2: static-RSA key exchange is never accepted (TOFU path)" {
    // rsa_server.pem carries keyEncipherment, so BoringSSL's leaf key-usage
    // check permits RSA key exchange; only the wrapper's TLS 1.2 cipher list
    // (MISUSE-11) prevents it. Checked by mutation.
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("rsa_server.pem"), .key = fx("rsa_server.key"), .tls12_cipher_list = "kRSA" });
    var conn: tls.Connection = undefined;
    try std.testing.expectError(error.HandshakeFailed, dial(&srv, .{ .server_name = "localhost", .trust = tofu(null), .min_version = .tls1_2 }, &conn));
    const r = srv.join();
    try std.testing.expect(!r.handshake_ok);
}

test "TLS 1.2: ECDHE-RSA with AEAD works when tls1_2 is allowed" {
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("rsa_server.pem"), .key = fx("rsa_server.key"), .tls12_cipher_list = "ECDHE-RSA-AES128-GCM-SHA256" });
    var conn: tls.Connection = undefined;
    var s = try dial(&srv, .{ .server_name = "localhost", .trust = webpki(default_ca), .min_version = .tls1_2 }, &conn);
    try std.testing.expectEqual(.tls1_2, try s.protocolVersion());
    try std.testing.expectEqualStrings("ECDHE-RSA-AES128-GCM-SHA256", try s.cipherName()); // OpenSSL-style name
    try pingPong(&s);
    try s.close();
    _ = srv.join();
}

test "read: a zero-length buffer is an error, so 0 always means close_notify" {
    var srv: TestServer = undefined;
    try srv.start(.{ .cert = fx("server.pem"), .key = fx("server.key") });
    var conn: tls.Connection = undefined;
    var s = try dial(&srv, .{ .server_name = "localhost", .trust = webpki(default_ca) }, &conn);
    var empty: [0]u8 = .{};
    try std.testing.expectError(error.EmptyBuffer, s.read(&empty));
    try pingPong(&s);
    try s.close();
    _ = srv.join();
}
