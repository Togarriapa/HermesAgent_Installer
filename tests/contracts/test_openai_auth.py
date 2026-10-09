from __future__ import annotations

import base64
import json
import time
import threading
from dataclasses import replace
import unittest

from hermes_installer.openai_auth import (
    ChatGPTPlanAuth, DYNAMIC_CLIENT_ID, PLAN_SCOPE, RESOURCE, TOKEN_ENDPOINT,
    OAuthAttemptError, OpenAIIDTokenVerifier,
)


class FakeTransport:
    def __init__(self):
        self.calls = []
        self.revocation_responses = []
        self.response = {
            "access_token": "access-secret", "refresh_token": "refresh-secret",
            "id_token": "identity-token", "token_type": "Bearer",
            "scope": "openid email offline_access resource.invoke " + PLAN_SCOPE,
            "expires_in": 3600,
        }

    def post_form(self, endpoint, values, *, timeout):
        self.calls.append((endpoint, dict(values), timeout))
        if values.get("token_type_hint") == "refresh_token":
            return self.revocation_responses.pop(0) if self.revocation_responses else {}
        return dict(self.response)

    def get_json(self, endpoint, *, timeout):
        self.calls.append((endpoint, {}, timeout))
        return {"revocation_endpoint": "https://auth.openai.com/api/accounts/oauth/revoke"}


class FakeVault:
    def __init__(self):
        self.accounts = {}
        self._locks = {}

    def save(self, reference, account):
        self.accounts[reference] = account

    def load(self, reference):
        return self.accounts[reference]

    def clear_tokens(self, reference):
        self.accounts[reference] = replace(self.accounts[reference],
            access_token="", refresh_token="", id_token="")

    def session_lock(self, reference):
        return self._locks.setdefault(reference, threading.Lock())


class OpenAIAuthTests(unittest.TestCase):
    def make_auth(self):
        transport, vault = FakeTransport(), FakeVault()
        def verify(token, nonce, audience):
            self.assertEqual(token, "identity-token")
            return {"sub": "verified-subject", "iss": "https://auth.openai.com",
                    "aud": [audience], "nonce": nonce, "email": "user@example.test"}
        return ChatGPTPlanAuth(host_id="urn:uuid:6b87b55d-f3a8-4cb9-82b4-f5d28203f066",
            agent_name="Hermes Installer", transport=transport, vault=vault,
            verify_id_token=verify, sleep=lambda _delay: None), transport, vault

    def test_builtin_jwks_verifier_rejects_bad_signature(self):
        def enc(raw):
            return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        header = enc(json.dumps({"alg": "RS256", "kid": "key-1"}).encode())
        claims = enc(json.dumps({"iss": "https://auth.openai.com", "sub": "s",
                                 "aud": "oaiapp_test", "exp": int(time.time()) + 60}).encode())
        token = header + "." + claims + "." + enc(bytes(256))

        class KeyTransport:
            def get_json(self, endpoint, *, timeout):
                if endpoint.endswith("openid-configuration"):
                    return {"issuer": "https://auth.openai.com",
                            "jwks_uri": "https://auth.openai.com/.well-known/jwks.json"}
                return {"keys": [{"kid": "key-1", "kty": "RSA",
                                  "n": enc(bytes([0x80]) + bytes(255)), "e": "AQAB"}]}
            def post_form(self, endpoint, values, *, timeout):
                return {}

        verifier = OpenAIIDTokenVerifier(KeyTransport())
        with self.assertRaisesRegex(OAuthAttemptError, "signature is invalid"):
            verifier(token, "", "oaiapp_test")

    def test_pkce_dynamic_registration_and_callback_identity(self):
        auth, transport, vault = self.make_auth()
        attempt = auth.begin(callback_uri="http://127.0.0.1:1455/auth/callback")
        self.assertEqual(attempt.client_id, DYNAMIC_CLIENT_ID)
        self.assertIn("code_challenge_method=S256", attempt.authorize_url)
        self.assertIn("ext_agent_host_id=urn%3Auuid", attempt.authorize_url)
        callback = (attempt.callback_uri + "?code=one-use-code&state=" + attempt.state
                    + "&client_id=oaiapp_issued")
        account = auth.complete(attempt, callback, credential_ref="host-vault://codex/default")
        self.assertEqual(account.client_id, "oaiapp_issued")
        self.assertEqual(account.subject, "verified-subject")
        self.assertIn(PLAN_SCOPE, account.scopes)
        endpoint, form, timeout = transport.calls[0]
        self.assertEqual(endpoint, TOKEN_ENDPOINT)
        self.assertEqual(form["resource"], RESOURCE)
        self.assertEqual(form["client_id"], "oaiapp_issued")
        self.assertEqual(form["code_verifier"], attempt.verifier)
        self.assertNotIn("client_secret", form)
        self.assertIs(vault.accounts["host-vault://codex/default"], account)
        self.assertNotIn("access-secret", repr(account))
        with self.assertRaisesRegex(OAuthAttemptError, "already consumed"):
            auth.complete(attempt, callback, credential_ref="host-vault://replay")
        self.assertEqual(len(transport.calls), 1)

    def test_callback_state_client_uri_and_scope_fail_before_storage(self):
        auth, transport, vault = self.make_auth()
        attempt = auth.begin(callback_uri="http://127.0.0.1:1455/auth/callback")
        bad = attempt.callback_uri + "?code=one-use-code&state=attacker&client_id=oaiapp_issued"
        with self.assertRaisesRegex(OAuthAttemptError, "state"):
            auth.complete(attempt, bad, credential_ref="host-vault://account")
        self.assertEqual(transport.calls, [])
        callback = (attempt.callback_uri + "?code=one-use-code&state=" + attempt.state
                    + "&client_id=dynamic_agent_client")
        with self.assertRaisesRegex(OAuthAttemptError, "reusable client ID"):
            auth.complete(attempt, callback, credential_ref="host-vault://account")
        self.assertEqual(vault.accounts, {})

        attempt = auth.begin(callback_uri="http://127.0.0.1:1455/auth/callback")
        transport.response["scope"] = "openid profile email"
        callback = (attempt.callback_uri + "?code=one-use-code&state=" + attempt.state
                    + "&client_id=oaiapp_issued")
        with self.assertRaisesRegex(OAuthAttemptError, "permission"):
            auth.complete(attempt, callback, credential_ref="host-vault://account")
        self.assertEqual(vault.accounts, {})

    def test_revoke_uses_issuer_discovery_then_clears_tokens_and_keeps_registration(self):
        auth, transport, vault = self.make_auth()
        attempt = auth.begin(callback_uri="http://127.0.0.1:1455/auth/callback")
        callback = (attempt.callback_uri + "?code=one-use-code&state=" + attempt.state
                    + "&client_id=oaiapp_issued")
        auth.complete(attempt, callback, credential_ref="host-vault://account")
        self.assertTrue(auth.revoke(credential_ref="host-vault://account"))
        account = vault.accounts["host-vault://account"]
        self.assertEqual(account.client_id, "oaiapp_issued")
        self.assertEqual(account.subject, "verified-subject")
        self.assertEqual((account.access_token, account.refresh_token, account.id_token), ("", "", ""))
        self.assertEqual(transport.calls[-2][0],
                         "https://auth.openai.com/.well-known/openid-configuration")
        self.assertEqual(transport.calls[-1][1]["token_type_hint"], "refresh_token")

    def test_revoke_retries_only_transient_failures_and_then_clears(self):
        auth, transport, vault = self.make_auth()
        attempt = auth.begin(callback_uri="http://127.0.0.1:1455/auth/callback")
        callback = (attempt.callback_uri + "?code=one-use-code&state=" + attempt.state
                    + "&client_id=oaiapp_issued")
        auth.complete(attempt, callback, credential_ref="host-vault://account")
        transport.revocation_responses = [{"status_code": 503}, {"status_code": 503}, {}]
        self.assertTrue(auth.revoke(credential_ref="host-vault://account"))
        revoke_calls = [call for call in transport.calls if call[1].get("token_type_hint")]
        self.assertEqual(len(revoke_calls), 3)
        self.assertEqual(vault.accounts["host-vault://account"].refresh_token, "")

    def test_returning_account_reuses_registration_and_refresh_is_host_vault_backed(self):
        auth, transport, vault = self.make_auth()
        attempt = auth.begin(callback_uri="http://127.0.0.1:1455/auth/callback",
                             client_id="oaiapp_existing", id_token_hint="old-id-token")
        self.assertNotIn("agent_name_hint", attempt.authorize_url)
        self.assertIn("id_token_hint=old-id-token", attempt.authorize_url)
        callback = attempt.callback_uri + "?code=code&state=" + attempt.state
        account = auth.complete(attempt, callback, credential_ref="host-vault://existing")
        refreshed = auth.refresh(credential_ref="host-vault://existing")
        self.assertEqual(refreshed.client_id, account.client_id)
        self.assertEqual(refreshed.refresh_token, "refresh-secret")
        self.assertEqual(transport.calls[-1][1]["grant_type"], "refresh_token")
        self.assertNotIn("scope", transport.calls[-1][1])


if __name__ == "__main__":
    unittest.main()
