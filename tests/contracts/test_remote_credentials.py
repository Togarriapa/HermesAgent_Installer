import pytest
from hermes_installer.remote.credentials import RemoteCredentialError,assert_management_token_absent,cloudflared_argv

def test_runtime_argv_uses_token_file_and_not_setup_token(tmp_path):
 argv=cloudflared_argv(executable="/usr/bin/cloudflared",token_file=tmp_path/"runtime-token")
 assert argv[3]=="--token-file" and "setup-secret" not in argv
 assert_management_token_absent(argv=argv,environment={"PATH":"/usr/bin"},token="setup-secret")

def test_management_token_leak_fails():
 with pytest.raises(RemoteCredentialError):
  assert_management_token_absent(argv=("cloudflared","setup-secret"),environment={},token="setup-secret")
