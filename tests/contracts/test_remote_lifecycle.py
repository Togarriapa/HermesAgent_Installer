import unittest
from hermes_installer.remote.lifecycle import OwnedResource,RemoteJournal,RemotePhase,provision_fail_closed
from hermes_installer.remote.journal import dump,load,SharedJournalAdapter
class RemoteLifecycleTests(unittest.TestCase):
 def test_access_origin_tunnel_precede_route(self):
  order=[];j=RemoteJournal("op-1","desk.example.net")
  out=provision_fail_closed(j,prepare_access=lambda:(order.append("access") or OwnedResource("access","a","op-1",True)),prepare_origin=lambda:order.append("origin"),make_tunnel=lambda:(order.append("tunnel") or OwnedResource("tunnel","t","op-1",True)),activate_route=lambda:order.append("route"))
  self.assertEqual(order,["access","origin","tunnel","route"]);self.assertEqual(out.phase,RemotePhase.ACTIVE)
 def test_ambiguous_failure_keeps_journal_and_resource_created(self):
  j=RemoteJournal("op-2","desk.example.net")
  def timeout():raise TimeoutError("ambiguous")
  with self.assertRaises(TimeoutError):provision_fail_closed(j,prepare_access=lambda:OwnedResource("access","a","op-2",True),prepare_origin=lambda:None,make_tunnel=lambda:OwnedResource("tunnel","t","op-2",True),activate_route=timeout)
  self.assertEqual(j.phase,RemotePhase.TUNNEL_READY);self.assertEqual(j.error_code,"REMOTE_SETUP_INCOMPLETE");self.assertEqual(set(j.resources),{"access","tunnel"})
 def test_journal_roundtrip_excludes_secrets(self):
  j=RemoteJournal("op-3","desk.example.net");j.record("app",OwnedResource("access_app","id-123","op-3",True));raw=dump(j)
  self.assertNotIn("token",str(raw).casefold());self.assertEqual(load(raw,operation_id="op-3",hostname=j.hostname).resources,j.resources)
  with self.assertRaises(ValueError):load(raw,operation_id="other",hostname=j.hostname)
 def test_shared_adapter_checkpoints_without_owning_lock(self):
  state={};adapter=SharedJournalAdapter(lambda:state,lambda v:state.update(v),operation_id="op-4",hostname="desk.example.net")
  adapter.remote.completed.add("intent:access_app");adapter.checkpoint();self.assertIn("intent:access_app",state["remote_desktop"]["completed"])
