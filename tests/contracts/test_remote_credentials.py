import tempfile
import unittest
from pathlib import Path
from hermes_installer.remote.credentials import RemoteCredentialError,assert_management_token_absent,cloudflared_argv
class RemoteCredentialTests(unittest.TestCase):
 def test_runtime_argv_uses_token_file_and_not_setup_token(self):
  with tempfile.TemporaryDirectory() as d:
   argv=cloudflared_argv(executable="/usr/bin/cloudflared",token_file=Path(d)/"runtime-token")
   self.assertEqual(argv[3],"--token-file");self.assertNotIn("setup-secret",argv)
   assert_management_token_absent(argv=argv,environment={"PATH":"/usr/bin"},token="setup-secret")
 def test_management_token_leak_fails(self):
  with self.assertRaises(RemoteCredentialError):assert_management_token_absent(argv=("cloudflared","setup-secret"),environment={},token="setup-secret")
