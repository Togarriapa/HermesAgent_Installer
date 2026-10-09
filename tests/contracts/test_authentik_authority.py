from __future__ import annotations

import json
import unittest
from dataclasses import replace

from hermes_installer.authority.authentik import (
    AuthentikEnrollment, AuthentikResponse, AuthentikSystemPolicy,
    PrincipalIdentity,
)
from hermes_installer.authority.service import EffectRule
from hermes_installer.authority.types import AuthorityDenied, HostContext, Sensitivity, canonical_digest


class FakeAuthentik:
    def __init__(self):
        self.user_groups = ["child"]
        self.recipient_groups = ["recipient-child"]
        self.graph = {
            "child": {"pk": "child", "parents": ["system", "writers"]},
            "system": {"pk": "system", "parents": []},
            "writers": {"pk": "writers", "parents": []},
            "recipient-child": {"pk": "recipient-child", "parents": ["system", "deliveries"]},
            "deliveries": {"pk": "deliveries", "parents": []},
        }
        self.calls = []
        self.recipient_count = 1

    def get(self, path, *, bearer_token, timeout):
        self.calls.append((path, bearer_token, timeout))
        if path == "/api/v3/core/users/me/":
            value = {"user": {"pk": "123", "username": "alice", "email": "alice@example.test", "is_active": True,
                              "groups": [{"pk": value} for value in self.user_groups]}}
        elif path.startswith("/api/v3/core/groups/"):
            group_id = path.removeprefix("/api/v3/core/groups/").removesuffix("/")
            value = self.graph.get(group_id)
            if value is None:
                return AuthentikResponse(404, b"{}", {"content-type": "application/json"})
        elif path.startswith("/api/v3/core/users/?"):
            value = {"pagination": {"count": self.recipient_count, "next": None}, "results": []}
            if self.recipient_count == 1:
                value["results"] = [{"pk": "456", "email": "ops@example.test", "is_active": True,
                                     "groups": [{"pk": group} for group in self.recipient_groups]}]
        else:
            return AuthentikResponse(404, b"{}", {"content-type": "application/json"})
        return AuthentikResponse(200, json.dumps(value).encode(), {"content-type": "application/json"})


def make_policy(transport):
    enrollment = AuthentikEnrollment(
        principal_identities={"principal:alice": PrincipalIdentity("alice", "alice@example.test")},
        system_group_id="system",
        write_group_by_target={"homelab:boiler:off": "writers"},
        recipient_group_id="deliveries",
        recipient_email_by_id={"recipient:ops": "ops@example.test"},
        allowed_effects=frozenset({
            ("homelab-write", "homelab:boiler:off"),
            ("alert-deliver", "alert:ops"),
            ("provider-dispatch", "provider://openrouter/fixed-model"),
        }),
        public_profile_purposes=frozenset({("profile:one", "host-write"), ("profile:one", "alarm")}),
        max_sensitivity_by_capability={"homelab-write": Sensitivity.PUBLIC, "alert-deliver": Sensitivity.PUBLIC},
    )
    return AuthentikSystemPolicy(
        enrollment=enrollment, actor_token=lambda principal: "actor-token",
        directory_token=lambda: "directory-token", transport=transport,
    )


def make_context(purpose="host-write"):
    return HostContext(
        principal_id="principal:alice", profile_id="profile:one", namespace_id="ns:one", uid=1001,
        purpose=purpose, intent_id="intent:one", trace_id="trace:one", sensitivity=Sensitivity.PUBLIC,
        lineage_hash=canonical_digest({"source": "fixture"}), policy_revision="authentik-policy-v1",
        capabilities=frozenset({"homelab-write", "alert-deliver"}), issued_at_monotonic=1.0,
        monotonic_expires_at=20.0, nonce="context-nonce", grant_id="context-grant", signature="fixture-signature",
    )


class AuthentikSystemAuthorityContracts(unittest.TestCase):
    def test_subject_id_mismatch_denies_even_when_username_and_email_match(self):
        transport = FakeAuthentik()
        policy = make_policy(transport)
        policy.enrollment = replace(
            policy.enrollment,
            principal_identities={"principal:alice": PrincipalIdentity("alice", "alice@example.test", "different-subject")},
        )
        rule = EffectRule("homelab-write", "host.write", "homelab:boiler:off")
        with self.assertRaises(AuthorityDenied):
            policy.allow_effect(context=make_context(), rule=rule,
                                request_digest="a" * 64, retry_index=0)
        self.assertEqual([call[0] for call in transport.calls], ["/api/v3/core/users/me/"])

    def test_direct_and_indirect_system_membership_authorizes_only_enrolled_target(self):
        transport = FakeAuthentik()
        policy = make_policy(transport)
        rule = EffectRule("homelab-write", "host.write", "homelab:boiler:off")
        self.assertTrue(policy.allow_effect(context=make_context(), rule=rule, request_digest="a" * 64, retry_index=0))
        self.assertEqual({call[0] for call in transport.calls}, {
            "/api/v3/core/users/me/", "/api/v3/core/groups/child/",
            "/api/v3/core/groups/system/", "/api/v3/core/groups/writers/",
        })

        self.assertFalse(policy.allow_effect(
            context=make_context(),
            rule=EffectRule("homelab-write", "host.write", "homelab:other:off"),
            request_digest="a" * 64, retry_index=0,
        ))

    def test_recipient_is_independently_looked_up_and_hierarchy_checked(self):
        transport = FakeAuthentik()
        policy = make_policy(transport)
        rule = EffectRule("alert-deliver", "alert.deliver", "alert:ops", "recipient:ops")
        self.assertTrue(policy.allow_effect(context=make_context("alarm"), rule=rule, request_digest="b" * 64, retry_index=0))
        self.assertIn("/api/v3/core/users/?email=ops%40example.test&include_groups=true&page=1&page_size=2", {call[0] for call in transport.calls})
        self.assertIn("/api/v3/core/groups/deliveries/", {call[0] for call in transport.calls})

        transport.recipient_groups = []
        with self.assertRaises(AuthorityDenied):
            policy.allow_effect(context=make_context("alarm"), rule=rule, request_digest="b" * 64, retry_index=0)

    def test_provider_effect_does_not_use_system_membership_as_a_global_gate(self):
        transport = FakeAuthentik()
        policy = make_policy(transport)
        rule = EffectRule("provider-dispatch", "provider.dispatch", "provider://openrouter/fixed-model")
        self.assertTrue(policy.allow_effect(
            context=make_context("native-hermes-chat"), rule=rule,
            request_digest="c" * 64, retry_index=0,
        ))
        self.assertEqual(transport.calls, [])

    def test_public_identity_snapshot_returns_fresh_direct_and_indirect_groups(self):
        transport = FakeAuthentik()
        policy = make_policy(transport)
        snapshot = policy.principal_snapshot(make_context(), require_system_membership=True)
        self.assertEqual(snapshot.principal_id, "principal:alice")
        self.assertEqual(snapshot.subject_id, "123")
        self.assertEqual(snapshot.direct_group_ids, frozenset({"child"}))
        self.assertEqual(snapshot.effective_group_ids, frozenset({"child", "system", "writers"}))
        self.assertTrue(snapshot.system_member)
        self.assertIn("/api/v3/core/users/me/", {call[0] for call in transport.calls})

    def test_actor_revocation_cycle_ambiguity_and_incomplete_graph_fail_closed(self):
        transport = FakeAuthentik()
        policy = make_policy(transport)
        rule = EffectRule("homelab-write", "host.write", "homelab:boiler:off")
        transport.user_groups = []
        with self.assertRaises(AuthorityDenied):
            policy.allow_effect(context=make_context(), rule=rule, request_digest="a" * 64, retry_index=0)

        transport.user_groups = ["child"]
        transport.graph["system"] = {"pk": "system", "parents": ["child"]}
        with self.assertRaises(AuthorityDenied):
            policy.allow_effect(context=make_context(), rule=rule, request_digest="a" * 64, retry_index=0)

        transport.graph["system"] = {"pk": "system"}
        with self.assertRaises(AuthorityDenied):
            policy.allow_effect(context=make_context(), rule=rule, request_digest="a" * 64, retry_index=0)

        transport.graph["system"] = {"pk": "system", "parents": []}
        transport.recipient_count = 2
        alert = EffectRule("alert-deliver", "alert.deliver", "alert:ops", "recipient:ops")
        with self.assertRaises(AuthorityDenied):
            policy.allow_effect(context=make_context("alarm"), rule=alert, request_digest="b" * 64, retry_index=0)

    def test_empty_sources_remain_unknown_even_for_a_listed_purpose(self):
        transport = FakeAuthentik()
        policy = make_policy(transport)
        binding = type("Binding", (), {"profile_id": "profile:one"})()
        sensitivity, _ = policy.classify(purpose="host-write", intent="caller says public", source_contexts=(), binding=binding)
        self.assertIs(sensitivity, Sensitivity.UNKNOWN)
        sensitivity, _ = policy.classify(purpose="chat", intent="caller says public", source_contexts=(), binding=binding)
        self.assertIs(sensitivity, Sensitivity.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
