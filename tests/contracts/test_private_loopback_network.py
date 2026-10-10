from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from hermes_installer.authority.private_loopback_network import (
    POLICY_ID, POLICY_SHA256, POLICY_PATH, PrivateLoopbackMember,
    compile_nft_transaction, namespace_path_for, unit_network_properties,
    validate_private_loopback_networks,
)
from hermes_installer.authority.types import AuthorityDenied


class PrivateLoopbackNetworkContracts(unittest.TestCase):
    def setUp(self):
        self.services = [
            {"enrollment_id": "display-enrollment", "generation": "display-v1",
             "profile_id": "display", "service_uid": 17001},
            {"enrollment_id": "gateway-enrollment", "generation": "gateway-v1",
             "profile_id": "gateway", "service_uid": 17002},
        ]
        self.row = {
            "id": "remote-loopback", "generation": "network-v1",
            "namespace_identity": "remote-session-a",
            "member_enrollment_ids": ["display-enrollment", "gateway-enrollment"],
            "listener_bindings": [{"enrollment_id": "display-enrollment", "role": "xpra-display",
                                   "ipv4": "127.0.0.1", "port": 14500}],
            "client_bindings": [{"enrollment_id": "gateway-enrollment",
                                 "listener_enrollment_id": "display-enrollment", "port": 14500}],
            "policy_artifact_id": POLICY_ID, "policy_sha256": POLICY_SHA256,
        }
        self.digest = "a" * 64

    def test_installed_policy_bytes_are_exact_v97_artifact(self):
        source = Path(__file__).resolve().parents[2] / "plans/amendments/2026-10-10-private-loopback-enforcement-choice-v97/private-loopback-policy-v1.json"
        installed = POLICY_PATH.read_bytes()
        self.assertEqual(installed, source.read_bytes())
        self.assertEqual(len(installed), 1482)
        self.assertEqual(hashlib.sha256(installed).hexdigest(), POLICY_SHA256)

    def test_exact_selected_role_compiles_default_drop_and_role_uid_rules(self):
        network, = validate_private_loopback_networks([self.row], self.services, self.digest)
        nft = compile_nft_transaction(network).decode("ascii")
        for chain in ("input", "output", "forward"):
            self.assertIn(f"policy drop; }}", nft)
            self.assertIn(f"add chain inet hermes_installer_private {chain}", nft)
        self.assertIn("meta skuid 17002 ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp dport 14500", nft)
        self.assertIn("meta skuid 17001 ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport 14500", nft)
        rules = [line for line in nft.splitlines() if line.startswith("add rule ")]
        self.assertEqual(len(rules), 4)
        self.assertTrue(all('"lo"' in line or '"lo"' in line for line in rules))

    def test_systemd_listener_and_client_have_distinct_bind_authority(self):
        network, = validate_private_loopback_networks([self.row], self.services, self.digest)
        listener = PrivateLoopbackMember(network, "display-enrollment", 17001, self.digest)
        client = PrivateLoopbackMember(network, "gateway-enrollment", 17002, self.digest)
        namespace_path = namespace_path_for(network)
        listener_props = unit_network_properties(listener, namespace_path)
        client_props = unit_network_properties(client, namespace_path)
        self.assertIn("--property=SocketBindDeny=any", listener_props)
        self.assertIn("--property=SocketBindAllow=ipv4:tcp:14500", listener_props)
        self.assertIn("--property=SocketBindDeny=any", client_props)
        self.assertFalse(any("SocketBindAllow=" in prop for prop in client_props))

    def test_desktop_member_is_af_unix_only_with_no_bind_allow(self):
        services = [*self.services, {"enrollment_id": "desktop-enrollment",
                                     "generation": "desktop-v1", "profile_id": "desktop",
                                     "service_uid": 17003}]
        row = {**self.row, "member_enrollment_ids": [*self.row["member_enrollment_ids"],
                                                        "desktop-enrollment"]}
        network, = validate_private_loopback_networks([row], services, self.digest)
        desktop = PrivateLoopbackMember(network, "desktop-enrollment", 17003, self.digest)
        props = unit_network_properties(desktop, namespace_path_for(network))
        self.assertIn("--property=RestrictAddressFamilies=AF_UNIX", props)
        self.assertFalse(any("SocketBindAllow=" in prop for prop in props))

    def test_wrong_role_port_uid_address_or_generation_is_denied(self):
        mutations = (
            {"listener_bindings": [{"enrollment_id": "display-enrollment", "role": "desktop",
                                    "ipv4": "127.0.0.1", "port": 14500}]},
            {"listener_bindings": [{"enrollment_id": "display-enrollment", "role": "xpra-display",
                                    "ipv4": "0.0.0.0", "port": 14500}]},
            {"client_bindings": [{"enrollment_id": "gateway-enrollment",
                                  "listener_enrollment_id": "display-enrollment", "port": 14501}]},
            {"member_enrollment_ids": ["display-enrollment", "unknown"]},
            {"policy_sha256": "0" * 64},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(AuthorityDenied):
                validate_private_loopback_networks([{**self.row, **mutation}], self.services, self.digest)

    def test_uid_cannot_be_shared_across_members_or_networks(self):
        shared = [*self.services]
        shared[1] = {**shared[1], "service_uid": 17001}
        with self.assertRaises(AuthorityDenied):
            validate_private_loopback_networks([self.row], shared, self.digest)
        duplicate = {**self.row, "id": "another-network"}
        with self.assertRaises(AuthorityDenied):
            validate_private_loopback_networks([self.row, duplicate], self.services, self.digest)


if __name__ == "__main__":
    unittest.main()
