// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
//
// Builds BoringSSL (pinned in build.zig.zon) from source with Zig's toolchain,
// using BoringSSL's pre-generated gen/sources.json, so neither CMake, Go nor
// Perl is needed. Then builds the `boringtls` Zig module and its tests.
//
//   zig build test     (from this directory, or `just test` from the repo root)

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const boringssl = buildBoringSsl(b, target, optimize);

    const mod = b.addModule("boringtls", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.linkLibrary(boringssl.ssl);
    mod.linkLibrary(boringssl.crypto);

    // ---- tests -------------------------------------------------------------
    const test_step = b.step("test", "Run all tests");

    // Build smoke test: links BoringSSL and calls into it.
    const unit = b.addTest(.{ .root_module = mod });
    test_step.dependOn(&b.addRunArtifact(unit).step);
}

const BoringSsl = struct {
    crypto: *std.Build.Step.Compile,
    ssl: *std.Build.Step.Compile,
    include: std.Build.LazyPath,
};

fn buildBoringSsl(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) BoringSsl {
    const dep = b.dependency("boringssl", .{});
    const io = b.graph.io;
    const json_path = dep.builder.root.joinString(b.allocator, "gen/sources.json") catch @panic("OOM");
    const json_bytes = std.Io.Dir.cwd().readFileAlloc(io, json_path, b.allocator, .limited(4 << 20)) catch |err|
        std.debug.panic("boringssl: cannot read gen/sources.json: {t}", .{err});
    const Sources = struct {
        srcs: []const []const u8 = &.{},
        asm_files: []const []const u8 = &.{},
    };
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, b.allocator, json_bytes, .{}) catch |err|
        std.debug.panic("boringssl: bad gen/sources.json: {t}", .{err});
    const get = struct {
        fn set(v: std.json.Value, name: []const u8, alloc: std.mem.Allocator) Sources {
            const obj = v.object.get(name) orelse std.debug.panic("boringssl: sources.json lacks '{s}'", .{name});
            return .{
                .srcs = strings(obj, "srcs", alloc),
                .asm_files = strings(obj, "asm", alloc),
            };
        }
        fn strings(obj: std.json.Value, key: []const u8, alloc: std.mem.Allocator) []const []const u8 {
            const arr = (obj.object.get(key) orelse return &.{}).array;
            const out = alloc.alloc([]const u8, arr.items.len) catch @panic("OOM");
            for (arr.items, out) |item, *o| o.* = item.string;
            return out;
        }
    };
    const bcm = get.set(parsed, "bcm", b.allocator);
    const crypto_srcs = get.set(parsed, "crypto", b.allocator);
    const ssl_srcs = get.set(parsed, "ssl", b.allocator);

    const cxx_flags: []const []const u8 = &.{ "-std=c++17", "-fno-strict-aliasing", "-fno-common", "-fvisibility=hidden" };
    const asm_flags: []const []const u8 = &.{};
    const include = dep.path("include");

    const is_linux = target.result.os.tag == .linux;
    // Assembly is only wired for ELF x86_64/aarch64 here; elsewhere fall back to portable C.
    const use_asm = target.result.ofmt == .elf and
        (target.result.cpu.arch == .x86_64 or target.result.cpu.arch == .aarch64);

    const crypto_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });
    crypto_mod.addIncludePath(include);
    if (is_linux) crypto_mod.addCMacro("_XOPEN_SOURCE", "700");
    if (!use_asm) crypto_mod.addCMacro("OPENSSL_NO_ASM", "1");
    crypto_mod.addCSourceFiles(.{ .root = dep.path(""), .files = bcm.srcs, .flags = cxx_flags });
    crypto_mod.addCSourceFiles(.{ .root = dep.path(""), .files = crypto_srcs.srcs, .flags = cxx_flags });
    if (use_asm) {
        crypto_mod.addCSourceFiles(.{ .root = dep.path(""), .files = bcm.asm_files, .flags = asm_flags });
        crypto_mod.addCSourceFiles(.{ .root = dep.path(""), .files = crypto_srcs.asm_files, .flags = asm_flags });
    }
    const crypto = b.addLibrary(.{ .name = "crypto", .root_module = crypto_mod });

    const ssl_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });
    ssl_mod.addIncludePath(include);
    if (is_linux) ssl_mod.addCMacro("_XOPEN_SOURCE", "700");
    if (!use_asm) ssl_mod.addCMacro("OPENSSL_NO_ASM", "1");
    ssl_mod.addCSourceFiles(.{ .root = dep.path(""), .files = ssl_srcs.srcs, .flags = cxx_flags });
    ssl_mod.linkLibrary(crypto);
    const ssl = b.addLibrary(.{ .name = "ssl", .root_module = ssl_mod });

    b.installArtifact(crypto);
    b.installArtifact(ssl);
    return .{ .crypto = crypto, .ssl = ssl, .include = include };
}
