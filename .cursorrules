# SPDX-License-Identifier: MPL-2.0
# Copyright (c) {{CURRENT_YEAR}} {{AUTHOR}} ({{OWNER}}) <{{AUTHOR_EMAIL}}>
# Authoritative source: docs/practice/AI-CONVENTIONS.adoc

# Read the repo deed (*_chora.deed in the repo root) FIRST: canonical file locations
# live in its (ply ...) canonical-locations clauses.

# LICENSE
# All original code: MPL-2.0 (SPDX header required on every file).
# Copyright: {{AUTHOR}} ({{OWNER}}) <{{AUTHOR_EMAIL}}>

# STATE FILES
# No .a2ml file may exist anywhere: the format is retired. State, metadata,
# (neurosym) and (playbook) are clauses of the repo deed (*_chora.deed);
# the journal is docs/status/ROADMAP.adoc. Never recreate them as files.

# BANNED PATTERNS
# Idris2: believe_me, assert_total, assert_smaller, unsafePerformIO
# Haskell: unsafeCoerce, unsafePerformIO, undefined, error
# OCaml: Obj.magic, Obj.repr, Obj.obj
# Coq: Admitted
# Lean: sorry
# Rust: transmute (unless FFI with // SAFETY: comment)

# JS RUNTIME — Bun (standards/3-practice/LANGUAGE-POLICY.adoc section 1)
# 1. Bun    the JavaScript runtime: package.json + bun.lock, run with bun / bunx
# 2. pnpm   only where an upstream toolchain needs a node_modules layout
# 3. npm    last resort; permitted, never preferred — a noted decision
# Deno is RETIRED, not grandfathered (owner ruling 2026-08-26, standards#655):
# existing Deno projects migrate to Bun. TypeScript and ReScript are banned
# too; they migrate to AffineScript. Use plain JavaScript where JS is needed.

# BANNED LANGUAGES
# Go -> use Rust
# Python -> use Julia or Rust

# CONTAINERS
# Runtime: Podman (never Docker)
# File: Containerfile (never Dockerfile)
# Base: cgr.dev/chainguard/wolfi-base:latest

# ABI/FFI STANDARD
# ABI definitions: Idris2 with dependent types (src/interface/abi/)
# FFI implementation: Zig with C ABI (src/interface/ffi/)
# Generated C headers: src/interface/generated/

# BUILD SYSTEM
# Use just (Justfile) for all build, test, lint, and format tasks.

# CODE STYLE
# Use descriptive variable names.
# Annotate and document all files.
# Add SPDX-License-Identifier headers to every source file.
