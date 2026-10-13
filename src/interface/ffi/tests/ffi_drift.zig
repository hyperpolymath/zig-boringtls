// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
//
// Compares every declaration in src/c.zig with translate-c's rendering of the
// pinned BoringSSL headers. Functions are compared structurally: arity,
// varargs, calling convention, integer width/signedness, pointer const-ness,
// nullability (ours must admit NULL wherever the header does), single-item
// vs C pointers for data, nested callback signatures, and handle identity
// (our opaque `SSL` must be the header's `SSL`). Constants are compared by
// value. NOT checked: ownership/lifetime (get0 vs get1, who frees), and
// declarations outside src/c.zig (libc `close`/`time` in root.zig).
const std = @import("std");
const t = @import("translated");
const ours = @import("boringtls").c;

fn isPtrLike(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => true,
        .optional => |o| @typeInfo(o.child) == .pointer,
        else => false,
    };
}

fn ptrInfo(comptime T: type) std.builtin.Type.Pointer {
    return switch (@typeInfo(T)) {
        .pointer => |p| p,
        .optional => |o| @typeInfo(o.child).pointer,
        else => unreachable,
    };
}

fn nullable(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .optional => true,
        .pointer => |p| p.size == .c,
        else => false,
    };
}

fn lastSegment(comptime n: []const u8) []const u8 {
    const i = std.mem.lastIndexOfScalar(u8, n, '.') orelse return n;
    return n[i + 1 ..];
}

/// Our opaque names that have no same-named typedef in the headers.
fn handleAlias(comptime ours_name: []const u8) []const u8 {
    if (std.mem.eql(u8, ours_name, "STACK_OF_CRYPTO_BUFFER")) return "struct_stack_st_CRYPTO_BUFFER";
    return ours_name;
}

fn intLike(comptime T: type) ?std.builtin.Type.Int {
    return switch (@typeInfo(T)) {
        .int => |i| i,
        .@"enum" => |e| @typeInfo(e.tag_type).int,
        else => null,
    };
}

fn shapeEq(comptime A: type, comptime B: type, comptime path: []const u8) ?[]const u8 {
    if (A == B) return null;
    if (intLike(A)) |ia| {
        const ib = intLike(B) orelse return path ++ ": int vs " ++ @typeName(B);
        if (ia.bits != ib.bits or ia.signedness != ib.signedness)
            return path ++ ": " ++ @typeName(A) ++ " vs " ++ @typeName(B);
        return null;
    }
    if (isPtrLike(A)) {
        if (!isPtrLike(B)) return path ++ ": pointer vs " ++ @typeName(B);
        const pa = ptrInfo(A);
        const pb = ptrInfo(B);
        if (pa.attrs.@"const" != pb.attrs.@"const") return path ++ ": const-ness differs (" ++ @typeName(A) ++ " vs " ++ @typeName(B) ++ ")";
        // Nullability: if C may pass/return NULL, our type must admit it.
        if (nullable(B) and !nullable(A)) return path ++ ": header pointer is nullable, ours is not (" ++ @typeName(A) ++ ")";
        const ca = pa.child;
        const cb = pb.child;
        // void* must match void* exactly.
        if ((ca == anyopaque) != (cb == anyopaque)) return path ++ ": void* vs typed pointer (" ++ @typeName(ca) ++ " vs " ++ @typeName(cb) ++ ")";
        if (ca == anyopaque) return null;
        if (@typeInfo(ca) == .@"opaque") {
            // Handle identity: our opaque `c.X` must stand for the header's `X`
            // (or an explicitly listed alias), which may be opaque or a struct.
            const name = comptime lastSegment(@typeName(ca));
            const their_name = comptime handleAlias(name);
            if (!@hasDecl(t, their_name)) return path ++ ": no header type named " ++ their_name;
            if (@field(t, their_name) != cb) return path ++ ": handle " ++ name ++ " is not " ++ @typeName(cb);
            return null;
        }
        // Data pointers: a C pointer in the header may be one-or-many; ours
        // must not narrow it to a single-item pointer unless it is a function.
        if (pb.size == .c and pa.size == .one and @typeInfo(ca) != .@"fn")
            return path ++ ": header [*c] narrowed to single-item pointer (" ++ @typeName(A) ++ ")";
        return shapeEq(ca, cb, path ++ ".*");
    }
    switch (@typeInfo(A)) {
        .@"fn" => |fa| {
            const fb = switch (@typeInfo(B)) {
                .@"fn" => |f| f,
                else => return path ++ ": fn vs " ++ @typeName(B),
            };
            if (fa.param_types.len != fb.param_types.len) return path ++ ": arity differs";
            if (fa.attrs.varargs != fb.attrs.varargs) return path ++ ": varargs differs";
            if (!std.meta.eql(fa.attrs.@"callconv", fb.attrs.@"callconv")) return path ++ ": calling convention differs";
            if (shapeEq(fa.return_type.?, fb.return_type.?, path ++ " return")) |m| return m;
            for (fa.param_types, fb.param_types, 0..) |x, y, i| {
                if (shapeEq(x.?, y.?, std.fmt.comptimePrint("{s} param {d}", .{ path, i }))) |m| return m;
            }
            return null;
        },
        .void => return if (B == void) null else path ++ ": void vs " ++ @typeName(B),
        else => return path ++ ": unhandled " ++ @typeName(A) ++ " vs " ++ @typeName(B),
    }
}

test "every extern fn in src/c.zig matches the pinned headers" {
    @setEvalBranchQuota(200_000);
    comptime var checked: usize = 0;
    inline for (@typeInfo(ours).@"struct".decl_names) |name| {
        const v = @field(ours, name);
        const V = @TypeOf(v);
        if (V == type) continue;
        if (@typeInfo(V) == .@"fn") {
            if (!@hasDecl(t, name)) @compileError("not in headers: " ++ name);
            const m = comptime shapeEq(V, @TypeOf(@field(t, name)), name);
            if (m) |msg| @compileError("FFI drift: " ++ msg);
            checked += 1;
        }
    }
    try std.testing.expect(checked >= 50);
}

test "every constant in src/c.zig equals the header value" {
    @setEvalBranchQuota(200_000);
    comptime var checked: usize = 0;
    inline for (@typeInfo(ours).@"struct".decl_names) |name| {
        const v = @field(ours, name);
        const V = @TypeOf(v);
        if (V == type or @typeInfo(V) == .@"fn") continue;
        if (!@hasDecl(t, name)) @compileError("constant not in headers: " ++ name);
        const hv = @field(t, name);
        if (@as(i128, v) != @as(i128, hv)) @compileError(std.fmt.comptimePrint("constant {s}: ours {d}, header {d}", .{ name, v, hv }));
        checked += 1;
    }
    try std.testing.expect(checked >= 30);
}
