import unittest
from hermes_installer.remote.verify import EvidenceState,acceptance_state,verify_target
class RemoteVerifyTests(unittest.TestCase):
 def test_fixture_does_not_claim_pi_target_acceptance(self):
  c=verify_target(unauthorized_http=True,unauthorized_ws=True,official_window_seen=True,foreign_window_blocked=True,sandbox_proven=True,expiry_closed=True,policy_removal_denied_renewal=True,owned_recovery=True,target_identity=None)
  self.assertEqual(acceptance_state(c),EvidenceState.PENDING)
 def test_required_failed_observation_fails(self):
  c=verify_target(unauthorized_http=True,unauthorized_ws=True,official_window_seen=True,foreign_window_blocked=False,sandbox_proven=True,expiry_closed=True,policy_removal_denied_renewal=True,owned_recovery=True,target_identity="pi/account")
  self.assertEqual(acceptance_state(c),EvidenceState.FAIL)
 def test_policy_edit_does_not_claim_logout_or_token_user_app_revocation(self):
  c=verify_target(unauthorized_http=True,unauthorized_ws=True,official_window_seen=True,foreign_window_blocked=True,sandbox_proven=True,expiry_closed=True,policy_removal_denied_renewal=True,owned_recovery=True,target_identity="pi/account")
  by_requirement={item.requirement:item for item in c}
  self.assertEqual(by_requirement["R0206"].state,EvidenceState.PASS)
  for requirement in ("RP06-LOGOUT","RP06-TOKEN","RP06-USER","RP06-APP"):
   self.assertEqual(by_requirement[requirement].state,EvidenceState.PENDING)
  self.assertEqual(acceptance_state(c),EvidenceState.PENDING)
