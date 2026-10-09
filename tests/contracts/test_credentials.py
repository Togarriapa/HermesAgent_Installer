from __future__ import annotations
import io, os, tempfile, unittest
from unittest.mock import patch
from pathlib import Path
from hermes_installer.credentials import CredentialError, read_hidden_token, resolve_secret

class CredentialTests(unittest.TestCase):
    def test_environment_reference_is_explicit_and_never_printed(self):
        self.assertEqual(resolve_secret("env://CF_TOKEN",environ={"CF_TOKEN":"synthetic"}),"synthetic")
        with self.assertRaises(CredentialError) as e: resolve_secret("env://CF_TOKEN",environ={})
        self.assertNotIn("synthetic",str(e.exception))
    def test_keyring_and_store_use_resolver_callbacks(self):
        self.assertEqual(resolve_secret("keyring://installer/cf",keyring_lookup=lambda key:"secret-value"),"secret-value")
        self.assertEqual(resolve_secret("secret://remote/cf",secret_lookup=lambda key:"another-secret"),"another-secret")
        with self.assertRaises(CredentialError): resolve_secret("keyring://x")
    def test_private_file_required(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"token"; p.write_text("private-token\n"); p.chmod(0o600)
            self.assertEqual(resolve_secret("file://"+str(p)),"private-token")
            p.chmod(0o644)
            with self.assertRaises(CredentialError): resolve_secret("file://"+str(p))
    def test_secret_file_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            secret=Path(td)/"secret"; secret.write_text("private-token\n"); secret.chmod(0o600)
            link=Path(td)/"token-link"; link.symlink_to(secret)
            with self.assertRaises(CredentialError): resolve_secret("file://"+str(link))
    def test_hidden_input_validates_without_echo(self):
        seen=[]
        self.assertEqual(read_hidden_token(reader=lambda prompt:(seen.append(prompt) or "token-value")),"token-value")
        self.assertIn("hidden",seen[0])
        with self.assertRaises(CredentialError): read_hidden_token(reader=lambda prompt:"")
    def test_newline_file_preserves_trailing_r_and_n(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"token"; p.write_text("tokenr\n"); p.chmod(0o600)
            self.assertEqual(resolve_secret("file://"+str(p)),"tokenr")
            p.write_text("tokenn\r\n"); p.chmod(0o600)
            self.assertEqual(resolve_secret("file://"+str(p)),"tokenn")
    def test_encoded_separator_and_nul_are_rejected(self):
        for reference in ("file:///tmp/%2Fetc%2Fpasswd","file:///tmp/%00"):
            with self.assertRaises(CredentialError): resolve_secret(reference)
    def test_default_hidden_input_fails_without_tty(self):
        with patch("hermes_installer.credentials.sys.stdin",io.StringIO("")):
            with self.assertRaisesRegex(CredentialError,"requires a terminal"):
                read_hidden_token()
    def test_inline_values_are_not_secret_references(self):
        with self.assertRaises(CredentialError): resolve_secret("plaintext")

if __name__ == "__main__": unittest.main()
