import pytest
from hermes_installer.remote.lifecycle import OwnedResource,RemoteJournal,RemotePhase,provision_fail_closed

def test_access_origin_tunnel_precede_route():
 order=[]; j=RemoteJournal("op-1","desk.example.net")
 out=provision_fail_closed(j,prepare_access=lambda:(order.append("access") or OwnedResource("access","a","op-1",True)),
  prepare_origin=lambda:order.append("origin"),
  make_tunnel=lambda:(order.append("tunnel") or OwnedResource("tunnel","t","op-1",True)),
  activate_route=lambda:order.append("route"))
 assert order==["access","origin","tunnel","route"] and out.phase==RemotePhase.ACTIVE

def test_ambiguous_activation_failure_keeps_journal():
 j=RemoteJournal("op-2","desk.example.net")
 def timeout(): raise TimeoutError("ambiguous")
 with pytest.raises(TimeoutError):
  provision_fail_closed(j,prepare_access=lambda:OwnedResource("access","a","op-2",True),
   prepare_origin=lambda:None,make_tunnel=lambda:OwnedResource("tunnel","t","op-2",True),activate_route=timeout)
 assert j.phase==RemotePhase.TUNNEL_READY and j.error_code=="REMOTE_SETUP_INCOMPLETE"
 assert set(j.resources)=={"access","tunnel"}
