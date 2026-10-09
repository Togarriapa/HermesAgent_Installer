from __future__ import annotations

import time
import unittest

from hermes_installer.openai_auth import (
    ChatGPTPlanAuth, DYNAMIC_CLIENT_ID, PLAN_SCOPE, RESOURCE, TOKEN_ENDPOINT,
    OAuthAttemptError,
)


class FakeTransport:
    def __init__(self):
        self.calls = []
        self.response = {
            "access_token": "access-secret", "refresh_token": "refresh-secret",
            "id_token": "identity-token", "token_type": "Bearer",
            "scope": "openid email offline_access resource.invoke " + PLAN_SCOPE,
            "expires_in": 3600,
        }

    def post_form(self, endpoint, values, *, timeout):
        self.calls.append((endpoint, dict(values), timeout))
        return dict(self.response)


class FakeVault:
    def __init__(self):
        self.accounts = {}

    def save(self, reference, account):
        self.accounts[reference] = account

    def load(self, reference):
        return self.accounts[reference]

    def delete(self, reference):
        self.accounts.pop(reference, None)


class OpenAIAuthTests(unittest.TestCase):
    def make_auth(self):
        transport, vault = FakeTransport(), FakeVault()
        def verify(token, nonce, audience):
            self.assertEqual(token, "identity-token")
            return {"sub": "verified-subject", "iss": "https://auth.openai.com",
                    "aud": [audience], "nonce": nonce, "email": "user@example.test"}
        return ChatGPTPlanAuth(host_id="urn:uuid:6b87b55d-f3a8-4cb9-82b4-f5d28203f066",
            agent_name="Hermes Installer", transport=transport, vault=vault,
            verify_id_token=verify), transport, vault

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

    def test_callback_state_client_uri_and_scope_fail_before_storage(self):
        auth, transport, vault = self.make_auth()
        attempt = auth.begin(callback_uri="http://127.0.0.1:1455/auth/callback")
        bad = attempt.callback_uri + "?code=one-use-code&state=attacker&client_id=oaiapp_issued"
        with self.assertRaisesRegex(OAuthAttemptError, "state"):
            auth.complete(attempt, bad, credential_ref="host-vault://account")
        self.assertEqual(transport.calls, [])
        callback = (attempt.callback_uri + "?code=one-use-code&state=" + attempt.state
                    + "&client_id=another-client")
        with self.assertRaisesRegex(OAuthAttemptError, "issued client"):
            auth.complete(attempt, callback, credential_ref="host-vault://account")
        self.assertEqual(vault.accounts, {})

        attempt = auth.begin(callback_uri="http://127.0.0.1:1455/auth/callback")
        transport.response["scope"] = "openid profile email"
        callback = (attempt.callback_uri + "?code=one-use-code&state=" + attempt.state
                    + "&client_id=oaiapp_issued")
        with self.assertRaisesRegex(OAuthAttemptError, "permission"):
            auth.complete(attempt, callback, credential_ref="host-vault://account")
        self.assertEqual(vault.accounts, {})

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
