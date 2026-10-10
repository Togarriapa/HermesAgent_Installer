from __future__ import annotations

import hashlib
import json
import copy
import unittest
from unittest.mock import patch
from pathlib import Path

from hermes_installer.authority.private_loopback_network import (
    POLICY_ID, POLICY_SHA256, POLICY_PATH, PrivateLoopbackMember,
    compile_nft_transaction, namespace_path_for, unit_network_properties,
    validate_private_loopback_networks, _topology_valid, verify_unit_network_readback,
    RootPrivateLoopbackNetworkLease, RootNetworkMemberProof, RootResolvedHostTool,
    create_root_namespace, renew_root_network_lease, verify_root_network_lease,
    _canonical_link_attributes, _state_digest,
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
        for policy in ("--property=PrivateDevices=yes", "--property=DevicePolicy=closed",
                       "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet="):
            self.assertIn(policy, client_props)
        self.assertFalse(any("SocketBindAllow=" in prop for prop in client_props))
        observed = {part.split("=", 1)[0]: part.split("=", 1)[1]
                    for prop in client_props for part in (prop.removeprefix("--property="),)}
        observed["SocketBindAllow"] = ""
        verify_unit_network_readback(client, namespace_path, observed)
        observed["SocketBindAllow"] = "ipv4:tcp:14500"
        with self.assertRaises(AuthorityDenied):
            verify_unit_network_readback(client, namespace_path, observed)

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

    def test_v122_inert_kernel_template_invariants_and_failures(self):
        template_kinds = {
            "tunl0": "ipip", "gre0": "gre", "gretap0": "gretap",
            "erspan0": "erspan", "ip_vti0": "vti", "ip6_vti0": "vti6",
            "sit0": "sit", "ip6tnl0": "ip6tnl", "ip6gre0": "ip6gre",
        }
        links = [{"ifindex": 1, "name": "lo", "kind": "loopback", "flags": 9,
                  "operstate": 0, "master_ifindex": None, "link_ifindex": None,
                  "link_netnsid": None, "address_hex": "000000000000", "config": []}]
        for index, (name, kind) in enumerate(template_kinds.items(), start=2):
            links.append({"ifindex": index, "name": name, "kind": kind, "flags": 128,
                          "operstate": 2, "master_ifindex": None, "link_ifindex": 0,
                          "link_netnsid": None, "address_hex": "00000000", "config": []})
        state = {
            "links": links,
            "addresses": [{"family": 2, "prefix": 8, "ifindex": 1,
                           "address_hex": "7f000001"}],
            "routes": [{"family": 2, "dst_prefix": 8, "oif": 1,
                        "gateway_hex": "", "dst_hex": "7f000000"}],
            "neighbors": [], "kernel_release": "fixture-kernel",
            "kernel_version_sha256": "a" * 64,
        }
        self.assertTrue(_topology_valid(state))
        mutations = []
        up = copy.deepcopy(state); up["links"][1]["flags"] |= 1; mutations.append(up)
        address = copy.deepcopy(state); address["addresses"].append(
            {"family": 2, "prefix": 24, "ifindex": 2, "address_hex": "0a000001"}); mutations.append(address)
        route = copy.deepcopy(state); route["routes"].append(
            {"family": 2, "dst_prefix": 0, "oif": 2, "gateway_hex": "", "dst_hex": ""}); mutations.append(route)
        key = copy.deepcopy(state); key["links"][1]["config"] = [
            {"type": 4, "value": "01000000"}]; mutations.append(key)
        master = copy.deepcopy(state); master["links"][1]["master_ifindex"] = 1; mutations.append(master)
        linked = copy.deepcopy(state); linked["links"][1]["link_ifindex"] = 1; mutations.append(linked)
        unknown = copy.deepcopy(state); unknown["links"].append(
            {**unknown["links"][1], "ifindex": 20, "name": "veth0", "kind": "veth"}); mutations.append(unknown)
        for mutation in mutations:
            with self.subTest(mutation=mutation["links"][1]):
                self.assertFalse(_topology_valid(mutation))

    def test_link_fingerprint_ignores_only_live_counters(self):
        before = _canonical_link_attributes([
            (1, b"\x02\x00"), (7, b"rx-bytes=100"),
            (23, b"rx-packets=4"), (4, b"stable-link-fact"),
        ])
        after_traffic = _canonical_link_attributes([
            (23, b"rx-packets=44"), (7, b"rx-bytes=900"),
            (4, b"stable-link-fact"), (1, b"\x02\x00"),
        ])
        changed_link = _canonical_link_attributes([
            (1, b"\x02\x00"), (7, b"rx-bytes=900"),
            (23, b"rx-packets=44"), (4, b"changed-link-fact"),
        ])
        self.assertEqual(_state_digest(before), _state_digest(after_traffic))
        self.assertNotEqual(_state_digest(before), _state_digest(changed_link))

    def test_stale_lease_stops_only_retained_owned_units(self):
        network, = validate_private_loopback_networks([self.row], self.services, self.digest)
        lease = RootPrivateLoopbackNetworkLease(
            network, Path("/run/hermes-installer/netns/fixture"), -1, 1, 2,
            object(), "a" * 64, "b" * 32, "fixture-kernel", "c" * 64,
            "d" * 64, "e" * 64, "f" * 64, 1.0, 2.0, {},
        )
        lease.member_processes["display-enrollment"] = RootNetworkMemberProof(
            "display-enrollment", "display", "display-v1", 17001, 100,
            -1, 1, "/system.slice/hermes-installer-" + "1" * 32 + ".service",
            "hermes-installer-" + "1" * 32 + ".service", "a" * 64,
        )
        with patch("hermes_installer.authority.private_loopback_network._stop_owned_network_unit") as stop:
            with self.assertRaises(AuthorityDenied):
                verify_root_network_lease(lease)
        stop.assert_called_once_with("hermes-installer-" + "1" * 32 + ".service")

    def test_host_tool_capability_requires_registry_issued_instance(self):
        from hermes_installer.authority.host_tool_observation import HostToolObservationRegistry

        registry = object.__new__(HostToolObservationRegistry)
        registry._lock = __import__("threading").RLock()
        registry._resolved_tools = {}
        registry._observations = {}
        fake = object.__new__(RootResolvedHostTool)
        object.__setattr__(fake, "observation_handle", "a" * 64)
        object.__setattr__(fake, "observation_registry", registry)
        with self.assertRaises(AuthorityDenied):
            registry.verify_resolved_tool(fake)

    def test_host_tool_accepts_exact_registry_handle_format(self):
        from hermes_installer.authority.host_tool_observation import HostToolObservationRegistry
        import time

        registry = object.__new__(HostToolObservationRegistry)
        common = {
            "variant_id": "nftables-1", "package_name": "nftables", "version": "1.0",
            "distribution": "ubuntu", "release": "noble", "architecture": "amd64",
            "package_sha256": "a" * 64, "executable_artifact_id": "nft-executable:test",
            "executable_sha256": "b" * 64, "dependency_closure_sha256": "c" * 64,
            "package_set_receipt_handle": "d" * 32, "expires_monotonic": time.monotonic() + 30,
            "path": Path("/usr/sbin/nft"), "executable_fd": 0, "device": 1, "inode": 2,
            "observation_registry": registry, "observation_handle": "host-nft-observation:" + "e" * 48,
            "selected_network_key": ("network", "generation", "f" * 64),
        }
        tool = RootResolvedHostTool(**common)
        self.assertEqual(tool.observation_handle, "host-nft-observation:" + "e" * 48)
        with self.assertRaises(ValueError):
            RootResolvedHostTool(**{**common, "observation_handle": "e" * 64})

    def test_namespace_and_renewal_reject_unregistered_nft_before_effect(self):
        network, = validate_private_loopback_networks([self.row], self.services, self.digest)
        forged = object.__new__(RootResolvedHostTool)
        object.__setattr__(forged, "observation_registry", None)
        object.__setattr__(forged, "selected_network_key", (
            network.network_id, network.generation, network.service_generation_digest,
        ))
        with patch("hermes_installer.authority.private_loopback_network._linux_root"):
            with self.assertRaises(AuthorityDenied):
                create_root_namespace(network, forged)

        lease = RootPrivateLoopbackNetworkLease(
            network, Path("/run/hermes-installer/netns/fixture"), -1, 1, 2,
            forged, "a" * 64, "b" * 32, "fixture-kernel", "c" * 64,
            "d" * 64, "e" * 64, "f" * 64, 1.0, 2.0, {},
        )
        with patch("hermes_installer.authority.private_loopback_network.verify_root_network_lease"):
            with patch("hermes_installer.authority.private_loopback_network._linux_root"):
                with self.assertRaises(AuthorityDenied):
                    renew_root_network_lease(lease, forged)


if __name__ == "__main__":
    unittest.main()
