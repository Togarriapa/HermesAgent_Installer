from __future__ import annotations

import hashlib
import inspect
import json
import tempfile
import unittest
from pathlib import Path

from hermes_installer.components.omniroute import (
    NODE_ARTIFACT_SHA256, NODE_VERSION, OMNIROUTE_SOURCE_IDENTITY,
    OMNIROUTE_SOURCE_REVISION, OMNIROUTE_VERSION, OmniRouteError,
    OmniRouteGatewayAdapter, OmniRouteNodeRuntime, OmniRoutePolicy,
    build_omniroute_install_invocations, build_omniroute_service_invocation,
    deduplicate_omniroute_aliases, prepare_omniroute_build, stage_omniroute_build_workspace,
    validate_omniroute_source,
)
from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.policy import PROVIDER_RECIPIENT, canonical_provider_target
from hermes_installer.provider_effect_handlers import OPENROUTER_MODEL, ProviderEnrollment, canonical_provider_request
from hermes_installer.state import OwnedRoot


def _source(*, engine=">=22.22.2 <23 || >=24.0.0 <27"):
    package = json.dumps({
        "name": "omniroute", "version": OMNIROUTE_VERSION,
        "license": "MIT", "engines": {"node": engine},
    }).encode()
    lock = json.dumps({
        "name": "omniroute", "version": OMNIROUTE_VERSION,
        "lockfileVersion": 3,
        "packages": {"": {"name": "omniroute", "version": OMNIROUTE_VERSION}},
    }).encode()
    files = {"package.json": package, "package-lock.json": lock,
             "bin/omniroute.mjs": b"fixture entrypoint\n"}
    modes = {name: 0o100755 if name.endswith(".mjs") else 0o100644 for name in files}
    return VerifiedComponentSource(
        component_id="omniroute", source_identity=OMNIROUTE_SOURCE_IDENTITY,
        revision=OMNIROUTE_SOURCE_REVISION, files=files, file_modes=modes,
        archive_sha256="a" * 64, content_sha256="b" * 64,
        source_tree_sha="c" * 40, license="MIT", license_files=("LICENSE",),
        redistribution_license_review_required=False,
    )


def _node(**overrides):
    values = dict(
        root="/opt/hermes/components/node-26.7.0",
        node_executable="/opt/hermes/components/node-26.7.0/bin/node",
        npm_executable="/opt/hermes/components/node-26.7.0/bin/npm",
        version=NODE_VERSION, architecture="aarch64",
        artifact_sha256=NODE_ARTIFACT_SHA256, executable_sha256="d" * 64,
        generation_id="node-26.7.0-arm64-fixture",
    )
    values.update(overrides)
    return OmniRouteNodeRuntime(**values)


def _policy(**overrides):
    values = dict(alias="hermes-free", target=canonical_provider_target(OPENROUTER_MODEL),
                  recipient=PROVIDER_RECIPIENT, model=OPENROUTER_MODEL)
    values.update(overrides)
    return OmniRoutePolicy(**values)


def _normalization_policy():
    module = Path(inspect.getsourcefile(canonical_provider_request))
    record = {"id": "provider-output-reject-4096-v1", "revision": 1,
              "route_schema_id": "provider-chat-compatible-v1",
              "output_limit_mode": "reject-over-ceiling", "output_limit_ceiling": 4096,
              "canonicalizer_artifact_id": "provider-canonicalizer-v1",
              "canonicalizer_sha256": hashlib.sha256(module.read_bytes()).hexdigest()}
    record["normalization_policy_sha256"] = hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return record


class RecordingBridge:
    def __init__(self):
        self.calls = []

    def dispatch_native_request(self, handle, normalized_payload, *, retry_index, timeout, cancelled=None):
        if cancelled and cancelled():
            raise TimeoutError("cancelled")
        self.calls.append((handle, normalized_payload, retry_index, timeout))
        return {"status": 200, "receipt_id": "synthetic-root-receipt"}


class OmniRouteRuntimeTests(unittest.TestCase):
    def test_exact_pinned_source_and_lock_are_verified(self):
        source = _source()
        result = validate_omniroute_source(source)
        self.assertEqual(result.version, "3.8.52")
        self.assertEqual(result.node_engine, ">=22.22.2 <23 || >=24.0.0 <27")
        self.assertEqual(result.package_lock_sha256,
                         hashlib.sha256(source.files["package-lock.json"]).hexdigest())
        with self.assertRaises(OmniRouteError):
            validate_omniroute_source(_source(engine=">=20"))

    def test_build_workspace_is_private_and_node_invocations_are_fixed_offline(self):
        source = _source()
        with tempfile.TemporaryDirectory() as temp:
            owned = OwnedRoot(Path(temp) / "managed")
            destination = stage_omniroute_build_workspace(source, owned)
            self.assertEqual((Path(destination) / "package.json").read_bytes(), source.files["package.json"])
            self.assertEqual((Path(destination) / "bin/omniroute.mjs").stat().st_mode & 0o777, 0o700)
        evidence = validate_omniroute_source(source)
        install, build = build_omniroute_install_invocations(
            source=evidence, runtime=_node(), source_workspace="/opt/hermes/work/omniroute")
        self.assertEqual(install.argv[1:], ("ci", "--offline", "--ignore-scripts", "--no-audit", "--no-fund"))
        self.assertEqual(build.argv[1:], ("run", "build:backend"))
        self.assertEqual(install.network, "deny")
        self.assertEqual(build.network, "deny")
        self.assertFalse(install.credential_references)
        self.assertFalse(build.credential_references)
        for invalid in (_node(version="20.19.0"), _node(architecture="x86_64"),
                        _node(artifact_sha256="e" * 64),
                        _node(node_executable="/usr/bin/node")):
            with self.subTest(runtime=invalid):
                with self.assertRaises(OmniRouteError):
                    build_omniroute_install_invocations(
                        source=evidence, runtime=invalid, source_workspace="/opt/hermes/work/omniroute")


class OmniRouteManagedBuildTests(unittest.IsolatedAsyncioTestCase):
    async def test_build_runs_only_through_managed_supervisor_and_stops_on_failure(self):
        class Supervisor:
            def __init__(self, exit_codes):
                self.exit_codes = iter(exit_codes)
                self.invocations = []

            async def invoke(self, invocation):
                self.invocations.append(invocation)
                return {"exit_code": next(self.exit_codes)}

        with tempfile.TemporaryDirectory() as temp:
            root = OwnedRoot(Path(temp) / "owned")
            supervisor = Supervisor((0, 0))
            result = await prepare_omniroute_build(
                source=_source(), root=root, runtime=_node(), supervisor=supervisor,
                workspace_id="fixture-generation-1",
            )
            self.assertEqual([item.argv[1] for item in supervisor.invocations], ["ci", "run"])
            self.assertEqual(result.completed_stages, ("offline-dependencies", "backend-build"))
            self.assertIn("functional-probe-pending", result.evidence_state)

        with tempfile.TemporaryDirectory() as temp:
            root = OwnedRoot(Path(temp) / "owned")
            supervisor = Supervisor((1, 0))
            with self.assertRaisesRegex(OmniRouteError, "offline-dependencies"):
                await prepare_omniroute_build(
                    source=_source(), root=root, runtime=_node(), supervisor=supervisor,
                    workspace_id="fixture-generation-2",
                )
            self.assertEqual(len(supervisor.invocations), 1)

    def test_route_policy_aliases_and_service_start_fail_closed(self):
        self.assertEqual(deduplicate_omniroute_aliases(("OmniRoute", "omniroute")), ("omniroute",))
        self.assertEqual(deduplicate_omniroute_aliases(()), ())
        with self.assertRaises(OmniRouteError):
            deduplicate_omniroute_aliases(("another-router",))
        for invalid in (_policy(fallback_models=("openai/gpt-4o",)),
                        _policy(retry_limit=1), _policy(compression_enabled=True),
                        _policy(allowed_sensitivities=frozenset({"public", "private"})),
                        _policy(additional_metered_fee_usd=1)):
            with self.subTest(policy=invalid):
                with self.assertRaises(OmniRouteError):
                    invalid.validate()
        with self.assertRaisesRegex(OmniRouteError, "unavailable"):
            build_omniroute_service_invocation(
                source_root="/opt/hermes/work/omniroute", node_runtime=_node(),
                data_root="/opt/hermes/data/omniroute", policy=None,
                host_network_profile_id=None)
        invocation = build_omniroute_service_invocation(
            source_root="/opt/hermes/work/omniroute", node_runtime=_node(),
            data_root="/opt/hermes/data/omniroute", policy=_policy(),
            host_network_profile_id="root-profile-1")
        env = dict(invocation.environment)
        self.assertEqual(env["HOSTNAME"], "127.0.0.1")
        self.assertEqual(env["REQUIRE_API_KEY"], "true")
        self.assertFalse(invocation.credential_references)
        self.assertEqual(invocation.network, "provider-dispatch")

    def test_synthetic_tool_request_uses_single_root_effect_and_no_fallback(self):
        target = canonical_provider_target(OPENROUTER_MODEL)
        enrollment = ProviderEnrollment(
            provider="openrouter", account_id="fixture-account", principal_id="fixture-principal",
            target=target, recipient=PROVIDER_RECIPIENT,
            credential_ref="vault://fixture", credential_scope="provider:openrouter:inference",
            models=frozenset({OPENROUTER_MODEL}), allowed_sensitivities=frozenset({"public"}),
        )
        eligible = {(target, PROVIDER_RECIPIENT): enrollment}
        bridge = RecordingBridge()
        adapter = OmniRouteGatewayAdapter(
            policy=_policy(), root_selected_enrollments=lambda: eligible,
            normalization_policy=_normalization_policy(),
            authority=bridge)
        payload = json.dumps({
            "model": "hermes-free",
            "messages": [
                {"role": "user", "content": "find the local fixture"},
                {"role": "assistant", "content": None, "tool_calls": [{
                    "id": "call_1", "type": "function",
                    "function": {"name": "lookup", "arguments": "{}"},
                }]},
            ],
            "tools": [{"type": "function", "function": {
                "name": "lookup", "parameters": {"type": "object"},
            }}],
        }).encode()
        result = adapter.dispatch(native_event_handle="opaque-fixture-handle", payload=payload)
        self.assertEqual(result["status"], 200)
        self.assertEqual(len(bridge.calls), 1)
        handle, body, retry, _timeout = bridge.calls[0]
        normalized = json.loads(body)
        self.assertEqual(handle, "opaque-fixture-handle")
        self.assertEqual(retry, 0)
        self.assertEqual(normalized["model"], OPENROUTER_MODEL)
        self.assertEqual(normalized["provider"]["allow_fallbacks"], False)
        self.assertEqual(normalized["tools"][0]["function"]["name"], "lookup")

    def test_route_overrides_and_unenrolled_models_fail_before_authority(self):
        bridge = RecordingBridge()
        target = canonical_provider_target(OPENROUTER_MODEL)
        enrollment = ProviderEnrollment(
            provider="openrouter", account_id="fixture-account", principal_id="fixture-principal",
            target=target, recipient=PROVIDER_RECIPIENT,
            credential_ref="vault://fixture", credential_scope="provider:openrouter:inference",
            models=frozenset({OPENROUTER_MODEL}), allowed_sensitivities=frozenset({"public"}),
        )
        adapter = OmniRouteGatewayAdapter(
            policy=_policy(), root_selected_enrollments=lambda: {(target, PROVIDER_RECIPIENT): enrollment},
            normalization_policy=_normalization_policy(),
            authority=bridge)
        for override in ('"fallbacks":["paid"],', '"compression":true,',
                         '"model":"other/model",'):
            payload = ('{' + override + '"messages":[{"role":"user","content":"x"}]}').encode()
            with self.subTest(override=override), self.assertRaises(OmniRouteError):
                adapter.dispatch(native_event_handle="opaque", payload=payload)
        self.assertEqual(bridge.calls, [])


if __name__ == "__main__":
    unittest.main()
