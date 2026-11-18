-- SPDX-License-Identifier: MPL-2.0
-- Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
||| The zig-boringtls handle lifecycle as linear types (issue #11).
|||
||| `src/interface/ffi/src/root.zig` enforces its lifecycle with typestate: a
||| `Connection` has no I/O, a first TOFU visit yields a `FirstUseSession`
||| that has no I/O until the caller acknowledges the persisted pin, and a
||| `Session` is closed once. Zig has no affine or linear types, so a *copy*
||| of a handle escapes all of that (security notes §3, misuse row 13).
|||
||| This module states the lifecycle as an interface contract (PROOF-POLICY
||| §1: Idris2 carries the contract that stands apart from any one
||| implementation). A `Tls` value is an implementation of the operations over
||| abstract handle types. Every operation takes its handle at quantity 1, and
||| `withConnection` hands a new connection to a continuation at quantity 1
||| that can return only an `Ur` (unrestricted) value. So client code never
||| holds an unrestricted handle it could use twice, inside the scope or by
||| carrying one out of it.
|||
||| What this module does NOT establish: that the Zig wrapper is an
||| implementation of this record. That binding needs the C ABI that issue #11
||| still has to decide, and its correspondence is a separate, open row in
||| docs/status/PROOF-STATUS.adoc.
module Abi.Tls

import Data.Vect

%default total

--------------------------------------------------------------------------------
-- Configuration (mirrors `Pin`, `Trust` and `Config` in root.zig)
--------------------------------------------------------------------------------

||| A SHA-256 SPKI pin: exactly 32 bytes, as `Pin` in root.zig.
public export
record Pin where
  constructor MkPin
  bytes : Vect 32 Bits8

||| Where the TOFU name check may look (`name_check` in root.zig).
public export
data NameCheck = SanOnly | SanOrCommonName

||| How the peer must prove its identity.
|||
||| There are exactly two constructors and both verify the peer: there is no
||| "accept anything" mode to select by mistake (security notes §3, row 3a).
public export
data Trust : Type where
  ||| Build and verify a chain to the roots in this PEM file, and match the
  ||| server name against the leaf's subjectAltName.
  WebPKI : (rootsPemFile : String) -> Trust
  ||| Trust on first use. `Nothing` means a first visit: the handshake then
  ||| yields a first-use handle, never an ordinary session.
  Tofu : (knownPin : Maybe Pin) -> (nameCheck : NameCheck) -> Trust

||| A client certificate and its key (`ClientIdentity` in root.zig).
public export
record ClientIdentity where
  constructor MkClientIdentity
  chainPemFile : String
  keyPemFile : String

||| Connection settings (`Config` in root.zig, minus the I/O timeout and the
||| minimum version, which do not affect the lifecycle).
public export
record Config where
  constructor MkConfig
  host : String
  port : Bits16
  serverName : String
  trust : Trust
  alpn : List String
  clientIdentity : Maybe ClientIdentity

||| The error an operation reports. It carries the name of the member of
||| root.zig's `Error` set; mapping that set into a closed Idris2 type is part
||| of the binding work in issue #11.
public export
data TlsError = MkTlsError String

||| What a session's trust rests on (`TrustEvidence` in root.zig, minus
||| `first_use`, which only a first-use handle carries).
public export
data Evidence = WebPKIVerified | PinMatched Pin

--------------------------------------------------------------------------------
-- Results that carry a handle
--------------------------------------------------------------------------------

||| An operation's result together with the handle it hands back. The handle
||| field is linear, so it can be neither dropped nor duplicated.
public export
data Step : (result, handle : Type) -> Type where
  Then : (result : a) -> (1 h : handle) -> Step a handle

||| What a scope hands back across its boundary (Linear Haskell's `Ur`). The
||| field is unrestricted, so wrapping a linear handle in it, directly or
||| inside any other data, puts the handle in a non-linear position, which is
||| a type error. Only handle-free results, such as the results of operations
||| after their handles were consumed, can leave a scope.
public export
data Ur : Type -> Type where
  MkUr : (x : a) -> Ur a

||| The outcome of `handshake`. The connection is consumed in every case:
||| root.zig releases its resources on every error path, so `Failed` carries
||| no handle.
public export
data Handshaken : (session, firstUse : Type) -> Type where
  Established : (1 s : session) -> Handshaken session firstUse
  FirstUse : (1 f : firstUse) -> Handshaken session firstUse
  Failed : TlsError -> Handshaken session firstUse

||| The outcome of acknowledging a first-use pin. On a mismatch root.zig
||| returns `PinMismatch` and leaves the first-use handle alive, so the handle
||| comes back and must still be acknowledged or rejected.
public export
data Acked : (session, firstUse : Type) -> Type where
  Acknowledged : (1 s : session) -> Acked session firstUse
  Mismatch : (1 f : firstUse) -> Acked session firstUse

--------------------------------------------------------------------------------
-- The contract
--------------------------------------------------------------------------------

||| An implementation of the wrapper's operations over abstract handles.
|||
||| A client written against `Tls` cannot inspect, forge or copy a handle: the
||| handle types are erased fields, and every operation consumes its handle
||| exactly once and returns at most one handle.
public export
record Tls where
  constructor MkTls
  ||| Before the handshake (`Connection`).
  0 Connection : Type
  ||| After a verified handshake (`Session`).
  0 Session : Type
  ||| After a first TOFU visit, before acknowledgement (`FirstUseSession`).
  0 FirstUseSession : Type

  ||| Open a connection and hand it to the continuation at quantity 1
  ||| (`connect` or `fromFd`). The continuation must dispose of it, and can
  ||| return only an `Ur` value, so no handle can leave the scope: returning
  ||| the connection, or any data holding a handle, does not typecheck.
  withConnection : {0 r : Type} -> Config -> ((1 c : Connection) -> Ur r) -> Either TlsError r
  ||| Abandon a connection without a handshake (`Connection.deinit`).
  abandon : (1 c : Connection) -> ()
  ||| Run the handshake (`Connection.handshake`). Consumes the connection.
  handshake : (1 c : Connection) -> Handshaken Session FirstUseSession

  ||| The pin a first-time server presented (`presentedPin`).
  presentedPin : (1 f : FirstUseSession) -> Step Pin FirstUseSession
  ||| Assert that the presented pin was persisted
  ||| (`acknowledgePersistedPin`).
  acknowledge : (1 f : FirstUseSession) -> (persisted : Pin) -> Acked Session FirstUseSession
  ||| Refuse a first-time server without sending application data
  ||| (`FirstUseSession.deinit`).
  reject : (1 f : FirstUseSession) -> ()

  ||| The evidence the session rests on (`Session.trust`).
  evidence : (1 s : Session) -> Step Evidence Session
  ||| Read up to `max` decrypted bytes (`Session.read`). An empty list is a
  ||| clean close_notify.
  read : (1 s : Session) -> (max : Nat) -> Step (Either TlsError (List Bits8)) Session
  ||| Write every byte or fail (`Session.writeAll`).
  writeAll : (1 s : Session) -> List Bits8 -> Step (Either TlsError ()) Session
  ||| Send close_notify and release everything (`Session.close`). The session
  ||| is consumed even when this reports an error: root.zig releases first.
  close : (1 s : Session) -> Either TlsError ()
