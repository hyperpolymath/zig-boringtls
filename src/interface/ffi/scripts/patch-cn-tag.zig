// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
//
// Test-fixture helper: rewrites every commonName attribute's string tag in a
// DER certificate to OCTET STRING (0x04). The signature becomes invalid,
// which does not matter for the TOFU path (it never checks it). Used to make
// X509_check_host return a negative value (UNKNOWN_TAG) from a certificate
// the peer controls. Usage: zig run patch-cn-tag.zig -- in.der out.der
const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.Usage;
    const io = init.io;
    var buf: [16 * 1024]u8 = undefined;
    const der = try std.Io.Dir.cwd().readFile(io, args[1], &buf);
    const pat = [_]u8{ 0x06, 0x03, 0x55, 0x04, 0x03 }; // OID 2.5.4.3 (commonName)
    var n: usize = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, der, i, &pat)) |at| : (i = at + pat.len) {
        const tag = &der[at + pat.len];
        if (tag.* == 0x0c or tag.* == 0x13) { // UTF8String or PrintableString
            tag.* = 0x04;
            n += 1;
        }
    }
    if (n == 0) return error.NoCommonNameFound;
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = args[2], .data = der });
}
