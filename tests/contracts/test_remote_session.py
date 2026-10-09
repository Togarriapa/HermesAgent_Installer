import pytest
from hermes_installer.remote.session import SessionSpec,SessionUnavailable,server_policy,require_sandbox_evidence

@pytest.fixture
def spec():
 return SessionSpec("hermes-remote",":81","/var/lib/hermes-remote",
  "/opt/hermes/bin/hermes-desktop","a"*40,frozenset({"HermesDesktop"}))

def test_server_policy_disables_shell_file_and_host_desktop(spec):
 p=server_policy(spec)
 assert p["mode"]=="seamless" and p["start_new_commands"] is False
 assert p["start_desktop"] is False and p["start_shadow"] is False and p["start_proxy"] is False
 assert p["shell"] is False and p["dbus"] is False and p["file_transfer"] is False
 assert p["clipboard"] is False and p["window_policy"]=="deny_unmatched_server_side"

def test_no_sandbox_fallback_blocks_readiness():
 with pytest.raises(SessionUnavailable): require_sandbox_evidence(renderer_sandboxed=False,no_sandbox_marker=True)
