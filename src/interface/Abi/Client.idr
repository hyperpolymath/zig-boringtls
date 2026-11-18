-- SPDX-License-Identifier: MPL-2.0
-- Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
||| A complete, well-typed client of `Abi.Tls`: the positive control for the
||| negative tests in `Abi.Misuse`. It covers every branch of the lifecycle,
||| so the contract is shown to be usable, not merely restrictive.
|||
||| Each decision on an ordinary value is a separate function that takes the
||| handle as a linear argument: Idris2 0.7 does not let a `case` on an
||| unrestricted scrutinee consume a captured linear variable in its branches.
module Abi.Client

import Abi.Tls

%default total

||| What a client run produced.
public export
data Outcome : Type where
  ||| The exchange ran. It is built from a consumed session, so its field is
  ||| linear: an unrestricted field would count that session as used many
  ||| times.
  Exchanged : (1 result : Either TlsError (List Bits8)) -> Outcome
  ||| A first-time server was refused because its pin was not persisted.
  PinNotPersisted : Pin -> Outcome
  ||| The handshake failed; the connection is already released.
  HandshakeFailed : TlsError -> Outcome

||| Close after a read; the read's result is reported unless close failed.
closeAfterRead : (tls : Tls) -> (1 r : Step (Either TlsError (List Bits8)) tls.Session) -> Either TlsError (List Bits8)
closeAfterRead tls (Then got s) =
  case tls.close s of
    Left err => Left err
    Right () => got

||| After the write: on failure close and report it, otherwise read.
afterWrite : (tls : Tls) -> Either TlsError () -> (1 s : tls.Session) -> Either TlsError (List Bits8)
afterWrite tls (Left err) s =
  case tls.close s of
    Left _ => Left err
    Right () => Left err
afterWrite tls (Right ()) s = closeAfterRead tls (tls.read s 16384)

||| Send a request, read one response, close. Every handle is disposed of on
||| every path, which the typechecker checks.
exchange : (tls : Tls) -> (1 s : tls.Session) -> List Bits8 -> Either TlsError (List Bits8)
exchange tls s request =
  case tls.writeAll s request of
    Then sent s' => afterWrite tls sent s'

||| Acknowledge the presented pin; on a mismatch refuse the server.
acknowledgeOrReject : (tls : Tls) -> List Bits8 -> Pin -> (1 a : Acked tls.Session tls.FirstUseSession) -> Outcome
acknowledgeOrReject tls request pin (Acknowledged s) = Exchanged (exchange tls s request)
acknowledgeOrReject tls request pin (Mismatch f) =
  case tls.reject f of
    () => PinNotPersisted pin

||| On a first visit: acknowledge only if the pin was persisted.
firstVisit : (tls : Tls) -> List Bits8 -> (persisted : Bool) -> Pin -> (1 f : tls.FirstUseSession) -> Outcome
firstVisit tls request True pin f = acknowledgeOrReject tls request pin (tls.acknowledge f pin)
firstVisit tls request False pin f =
  case tls.reject f of
    () => PinNotPersisted pin

||| Handshake, then either exchange data or handle a first TOFU visit.
||| `persist` stores a presented pin and reports whether that succeeded; the
||| first-use handle is acknowledged only if it did.
export
run : (tls : Tls)
   -> (persist : Pin -> Bool)
   -> (request : List Bits8)
   -> (1 c : tls.Connection)
   -> Outcome
run tls persist request c =
  case tls.handshake c of
    Failed err => HandshakeFailed err
    Established s => Exchanged (exchange tls s request)
    FirstUse f =>
      case tls.presentedPin f of
        Then pin f' => firstVisit tls request (persist pin) pin f'

||| Open a connection and run the client over it.
export
fetch : (tls : Tls) -> Config -> (persist : Pin -> Bool) -> List Bits8 -> Either TlsError Outcome
fetch tls config persist request = tls.withConnection config (run tls persist request)
