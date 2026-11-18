-- SPDX-License-Identifier: MPL-2.0
-- Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
||| Negative tests for `Abi.Tls`: each `failing` block is a misuse that
||| root.zig cannot prevent for a copied handle (security notes §3, row 13),
||| and each must be REJECTED by the Idris2 typechecker.
|||
||| A `failing` block succeeds only if its body fails to elaborate with an
||| error containing the given text. The text pins each block to the error it
||| exists to show: "There are 2 uses of linear name …" for a handle used
||| twice, "0 uses" for a handle dropped, a type mismatch for a first-use
||| handle passed where a session is required. A block therefore cannot pass
||| by failing for an unrelated reason such as a typo.
|||
||| `Abi.Client` is the positive control: the same operations, used once each,
||| typecheck.
module Abi.Misuse

import Abi.Tls

%default total

||| A pair of linear values, so that both uses of a handle in a misuse sit in
||| linear positions and the checker reports the double use itself.
data Two : Type -> Type -> Type where
  MkTwo : (1 x : a) -> (1 y : b) -> Two a b

-- Row 13: closing the same session twice (a double free in root.zig when the
-- Session was copied by value).
failing "There are 2 uses of linear name s"
  doubleClose : (tls : Tls) -> (1 s : tls.Session) -> Two (Either TlsError ()) (Either TlsError ())
  doubleClose tls s = MkTwo (tls.close s) (tls.close s)

-- Row 13: running the handshake twice, the second time on a stale copy of the
-- connection.
failing "There are 2 uses of linear name c"
  staleHandshake : (tls : Tls) -> (1 c : tls.Connection)
                -> Two (Handshaken tls.Session tls.FirstUseSession) (Handshaken tls.Session tls.FirstUseSession)
  staleHandshake tls c = MkTwo (tls.handshake c) (tls.handshake c)

-- Reading from a session that was closed (root.zig returns `error.Closed`;
-- here the program does not exist).
failing "There are 2 uses of linear name s"
  readAfterClose : (tls : Tls) -> (1 s : tls.Session)
                -> Two (Either TlsError ()) (Step (Either TlsError (List Bits8)) tls.Session)
  readAfterClose tls s = MkTwo (tls.close s) (tls.read s 1)

-- Keeping the first-use handle after acknowledging it, to use both.
failing "There are 2 uses of linear name f"
  reuseAfterAck : (tls : Tls) -> Pin -> (1 f : tls.FirstUseSession)
               -> Two (Acked tls.Session tls.FirstUseSession) ()
  reuseAfterAck tls pin f = MkTwo (tls.acknowledge f pin) (tls.reject f)

-- Sending application data on a first TOFU visit before the pin is
-- acknowledged: a first-use handle is not a session.
failing "Can't solve constraint between: tls .FirstUseSession and tls .Session"
  writeBeforeAck : (tls : Tls) -> (1 f : tls.FirstUseSession) -> Step (Either TlsError ()) tls.Session
  writeBeforeAck tls f = tls.writeAll f []

-- Dropping a session without closing it (a leaked SSL and descriptor).
failing "There are 0 uses of linear name s"
  leakSession : (tls : Tls) -> (1 s : tls.Session) -> ()
  leakSession tls s = ()

-- Smuggling a connection out of `withConnection` inside an unrestricted
-- result, where it could be copied later.
failing "Trying to use linear name c in non-linear context"
  escape : (tls : Tls) -> Config -> Either TlsError (List tls.Connection)
  escape tls config = tls.withConnection config (\c => [c, c])
