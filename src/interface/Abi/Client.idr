-- SPDX-License-Identifier: MPL-2.0
-- Copyright (c) 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
||| A complete, well-typed client of `Abi.Tls`: the positive control for the
||| negative tests in `Abi.Misuse`. It covers every branch of the lifecycle,
||| so the contract is shown to be usable, not merely restrictive.
|||
||| Each decision on an ordinary value is a separate function that takes the
||| handle as a linear argument: Idris2 0.7 does not let a `case` on an
||| unrestricted scrutinee consume a captured linear variable in its branches.
||| Results leave the scope in `Ur`, built only once every handle is consumed.
module Abi.Client

import Abi.Tls

%default total

||| What a client run produced.
public export
data Outcome
  = Exchanged (Either TlsError (List Bits8))
  | PinNotPersisted Pin
  | HandshakeFailed TlsError

||| Close after a read; the read's result is reported unless close failed.
closeAfterRead : (tls : Tls) -> (1 r : Step (Either TlsError (List Bits8)) tls.Session) -> Ur (Either TlsError (List Bits8))
closeAfterRead tls (Then got s) =
  case tls.close s of
    Left err => MkUr (Left err)
    Right () => MkUr got

||| After the write: on failure close and report it, otherwise read.
afterWrite : (tls : Tls) -> Either TlsError () -> (1 s : tls.Session) -> Ur (Either TlsError (List Bits8))
afterWrite tls (Left err) s =
  case tls.close s of
    Left _ => MkUr (Left err)
    Right () => MkUr (Left err)
afterWrite tls (Right ()) s = closeAfterRead tls (tls.read s 16384)

||| Send a request, read one response, close. Every handle is disposed of on
||| every path, which the typechecker checks.
exchange : (tls : Tls) -> (1 s : tls.Session) -> List Bits8 -> Ur Outcome
exchange tls s request =
  case tls.writeAll s request of
    Then sent s' =>
      case afterWrite tls sent s' of
        MkUr result => MkUr (Exchanged result)

||| Acknowledge the presented pin; on a mismatch refuse the server.
acknowledgeOrReject : (tls : Tls) -> List Bits8 -> Pin -> (1 a : Acked tls.Session tls.FirstUseSession) -> Ur Outcome
acknowledgeOrReject tls request pin (Acknowledged s) = exchange tls s request
acknowledgeOrReject tls request pin (Mismatch f) =
  case tls.reject f of
    () => MkUr (PinNotPersisted pin)

||| On a first visit: acknowledge only if the pin was persisted.
firstVisit : (tls : Tls) -> List Bits8 -> (persisted : Bool) -> Pin -> (1 f : tls.FirstUseSession) -> Ur Outcome
firstVisit tls request True pin f = acknowledgeOrReject tls request pin (tls.acknowledge f pin)
firstVisit tls request False pin f =
  case tls.reject f of
    () => MkUr (PinNotPersisted pin)

||| Handshake, then either exchange data or handle a first TOFU visit.
||| `persist` stores a presented pin and reports whether that succeeded; the
||| first-use handle is acknowledged only if it did.
export
run : (tls : Tls)
   -> (persist : Pin -> Bool)
   -> (request : List Bits8)
   -> (1 c : tls.Connection)
   -> Ur Outcome
run tls persist request c =
  case tls.handshake c of
    Failed err => MkUr (HandshakeFailed err)
    Established s => exchange tls s request
    FirstUse f =>
      case tls.presentedPin f of
        Then pin f' => firstVisit tls request (persist pin) pin f'

||| Open a connection and run the client over it.
export
fetch : (tls : Tls) -> Config -> (persist : Pin -> Bool) -> List Bits8 -> Either TlsError Outcome
fetch tls config persist request = tls.withConnection config (run tls persist request)
