"""Separate target evidence from local fixture results."""
from __future__ import annotations
from dataclasses import dataclass
from enum import StrEnum
class EvidenceState(StrEnum): PASS="pass"; FAIL="fail"; PENDING="pending_target"
@dataclass(frozen=True)
class Check:
    requirement:str; state:EvidenceState; detail:str
def acceptance_state(checks:tuple[Check,...])->EvidenceState:
    if any(c.state==EvidenceState.FAIL for c in checks): return EvidenceState.FAIL
    if not checks or any(c.state!=EvidenceState.PASS for c in checks): return EvidenceState.PENDING
    return EvidenceState.PASS
def verify_target(*,unauthorized_http:bool,unauthorized_ws:bool,official_window_seen:bool,
 foreign_window_blocked:bool,sandbox_proven:bool,expiry_closed:bool,
 policy_removal_denied_renewal:bool,owned_recovery:bool,target_identity:str|None,
 explicit_logout_closed:bool|None=None,token_revocation_denied_renewal:bool|None=None,
 user_revocation_denied_renewal:bool|None=None,app_revocation_denied_renewal:bool|None=None)->tuple[Check,...]:
    rows=(("R0201",unauthorized_http,"unauthorized HTTP denied before bytes"),
      ("R0202",unauthorized_ws,"unauthorized WebSocket denied before attach"),
      ("R0203",official_window_seen,"official Hermes Desktop pixels observed"),
      ("R0204",foreign_window_blocked,"foreign windows and command attempts denied"),
      ("R0203",sandbox_proven,"Electron sandbox confirmed"),
      ("R0206",expiry_closed,"active socket closed within lease"),
      ("R0206",policy_removal_denied_renewal,"policy removal blocks renewal; this does not prove token or app revocation"),
      ("RP06-LOGOUT",explicit_logout_closed,"explicit logout closes the user's active session"),
      ("RP06-TOKEN",token_revocation_denied_renewal,"revoked Access token cannot renew"),
      ("RP06-USER",user_revocation_denied_renewal,"revoked user cannot renew"),
      ("RP06-APP",app_revocation_denied_renewal,"revoked Access app or identity provider cannot renew"),
      ("R0207",owned_recovery,"owned-resource recovery verified"))
    if not target_identity: return tuple(Check(i,EvidenceState.PENDING,"authorized Pi/account target not identified") for i,_,_ in rows)
    return tuple(Check(i,EvidenceState.PENDING if ok is None else EvidenceState.PASS if ok else EvidenceState.FAIL,d) for i,ok,d in rows)
