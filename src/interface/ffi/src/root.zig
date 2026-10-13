// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
//
// boringtls — build milestone. The wrapper lands in the next change; this
// file only proves the pinned BoringSSL compiles and links from build.zig.

const std = @import("std");

extern fn TLS_client_method() ?*const anyopaque;

test "BoringSSL links and its client method is available" {
    try std.testing.expect(TLS_client_method() != null);
}
