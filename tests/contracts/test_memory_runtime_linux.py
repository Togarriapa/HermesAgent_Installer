"""Linux/root integration of the complete root memory runtime builder.

This disposable fixture starts one unprivileged HTTP responder in a newly
created network namespace, then exercises the real memory builder, root journal
catalog, durable ledgers, AuthorityService HI12 grant path, serializer/parser,
and namespace connector. It is not a Hermes/native plugin, provider-account, or
target-hardware acceptance test.
"""
from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import platform
import pwd
import signal
import shutil
import socket
import sqlite3
import stat
import struct
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.memory_execution import MemoryExecutionDenied
from hermes_installer.authority.service import AuthorityService, EffectRule, PrincipalBinding
from hermes_installer.authority.types import EffectAuthorization, HostContext, Sensitivity, canonical_digest
from hermes_installer.managed_process_custodian import ManagedNamespaceLease
from hermes_installer.memory.broker import build_memory_handlers, build_memory_runtime, canonical
from hermes_installer.memory.compound import MemoryRouteRecipe
from hermes_installer.memory.enrollment import MemoryServiceEnrollment
from hermes_installer.memory.owner_ledger import _secure_sqlite_files
from hermes_installer.protected_enrollment import (
    OwnedRoots, ProtectedEnrollmentCatalog, ProtectedRootJournalCatalog,
)


class PrivateFixturePolicy:
    revision = "linux-root-memory-fixture-policy"

    def classify(self, *, purpose, intent, source_contexts, binding):
        if source_contexts:
            return source_contexts[0].sensitivity, canonical_digest(
                [source.lineage_hash for source in source_contexts])
        return Sensitivity.PRIVATE, canonical_digest({"purpose": purpose, "intent": intent})

    def allow_effect(self, *, context, rule, request_digest, retry_index):
        return context.sensitivity is Sensitivity.PRIVATE and retry_index == 0


def _enable_loopback() -> None:
    request = struct.pack("16sH", b"lo", 0) + bytes(14)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        current = fcntl.ioctl(probe.fileno(), 0x8913, request)  # SIOCGIFFLAGS
        flags = struct.unpack_from("H", current, 16)[0]
        if not flags & 1:  # IFF_UP
            fcntl.ioctl(probe.fileno(), 0x8914, struct.pack("16sH", b"lo", flags | 1) + bytes(14))


def _spawn_private_namespace_responder(service_uid: int, service_gid: int,
                                      port: int) -> tuple[int, int]:
    """Return (pid, pidfd); only expected capability failures skip CI."""
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read_fd)
            try:
                os.unshare(os.CLONE_NEWNET)
            except OSError as exc:
                os.write(write_fd, f"ERR:{exc.errno}".encode("ascii"))
                os._exit(0)
            _enable_loopback()
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen(1)
            listener.settimeout(10)
            os.write(write_fd, b"OK")
            os.close(write_fd)
            os.setgroups([])
            os.setgid(service_gid)
            os.setuid(service_uid)
            peer, _ = listener.accept()
            with peer:
                peer.settimeout(3)
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    request.extend(peer.recv(4096))
                header_end = request.index(b"\r\n\r\n")
                headers = bytes(request[:header_end])
                length = next(int(line.split(b":", 1)[1]) for line in headers.split(b"\r\n")
                              if line.lower().startswith(b"content-length:"))
                body = bytearray(request[header_end + 4:])
                while len(body) < length:
                    body.extend(peer.recv(length - len(body)))
                if (not headers.startswith(
                        b"POST /agentmemory/smart-search HTTP/1.1\r\nHost: 127.0.0.1:3111\r\n")
                        or b"Authorization: Bearer fake-memory-key-for-loopback-test\r\n" not in headers
                        or b"Transfer-Encoding:" in headers):
                    raise AssertionError("memory request escaped the fixed HTTP/auth framing")
                decoded = json.loads(bytes(body).decode("utf-8"))
                if decoded != {"agentId": "profile-one", "limit": 3,
                               "project": "project-one", "query": "synthetic restart fact"}:
                    raise AssertionError("memory request escaped the enrolled body serializer")
                response = b'{"mode":"compact","results":[]}'
                peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             + f"Content-Length: {len(response)}\r\nConnection: close\r\n\r\n".encode("ascii")
                             + response)
            listener.close()
        except BaseException:
            try:
                os.write(write_fd, b"ERR:unexpected")
            except OSError:
                pass
        finally:
            os._exit(0)
    os.close(write_fd)
    payload = os.read(read_fd, 128)
    os.close(read_fd)
    if payload.startswith(b"ERR:"):
        code = payload.partition(b":")[2].decode("ascii", "replace")
        os.waitpid(pid, 0)
        if code in {str(errno.EPERM), str(errno.EACCES), str(errno.ENOSYS)}:
            raise unittest.SkipTest("Linux CI lacks disposable network-namespace capability")
        raise AssertionError("network namespace responder failed: " + code)
    if payload != b"OK":
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        raise AssertionError("network namespace responder did not publish its bound port")
    if not hasattr(os, "pidfd_open"):
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        raise unittest.SkipTest("Linux pidfd API is unavailable")
    return pid, os.pidfd_open(pid)


@unittest.skipUnless(platform.system() == "Linux" and hasattr(os, "unshare")
                     and hasattr(os, "setns") and hasattr(os, "CLONE_NEWNET"),
                     "root memory runtime fixture requires Linux namespace APIs")
class RootMemoryRuntimeLinuxTests(unittest.TestCase):
    def test_full_builder_root_journal_hi12_namespace_loopback_and_denials(self):
        if os.geteuid() != 0:
            self.skipTest("fixture requires the isolated Linux root CI job")
        service_account = pwd.getpwnam("nobody")
        port = 3111  # exact literal listener port from the selected protected AgentMemory config
        pid, responder_pidfd = _spawn_private_namespace_responder(
            service_account.pw_uid, service_account.pw_gid, port)
        namespace_fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
        namespace_identity = f"netns:{os.fstat(namespace_fd).st_ino}"
        journal_parent: Path | None = None
        runtime: dict | None = None
        try:
            from tests.contracts.test_memory_enrollment import record
            raw = record(port=port)
            raw["namespace_identity"] = namespace_identity
            raw["memory_owner_generation"] = 1
            for selected_route in raw["fixed_route_map"].values():
                selected_route["scope_bindings"]["memory_owner_generation"] = 1
            enrollment = MemoryServiceEnrollment.from_protected_record(raw)
            # The trusted fixture root is shared by both protected service
            # roots and the authority-journal catalog selection.
            journal_parent = Path(tempfile.mkdtemp(
                prefix="memory-root-journal-", dir="/run"))
            recipe = enrollment.fixed_route_map["agentmemory-search"]
            assert isinstance(recipe, MemoryRouteRecipe)
            scope = dict(recipe.scope_bindings)
            scope["memory_owner_generation"] = 1
            recipe = replace(recipe, scope_bindings=scope)
            enrollment = replace(enrollment, memory_owner_generation=1,
                                 fixed_route_map={"agentmemory-search": recipe})
            target_key = (enrollment.profile_id, enrollment.namespace_identity, enrollment.provider)

            class SelectedProfileCatalog(ProtectedEnrollmentCatalog):
                def __init__(self):
                    # ProtectedEnrollmentCatalog intentionally rejects empty
                    # service enrollment. Supply the exact selected profile
                    # identity used by its production memory route join.
                    service_roots = journal_parent / "service-roots"
                    service_roots.mkdir(mode=0o700)
                    root_paths = []
                    for name in ("home", "work", "data"):
                        path = service_roots / name
                        path.mkdir(mode=0o700)
                        os.chown(path, service_account.pw_uid, service_account.pw_gid)
                        os.chmod(path, 0o700)
                        root_paths.append(path)
                    roots = OwnedRoots("home-root", "work-root", enrollment.data_root_id,
                        *root_paths, service_account.pw_uid, service_account.pw_gid)
                    executable = journal_parent / "service-runtime"
                    shutil.copyfile(sys.executable, executable)
                    os.chown(executable, 0, 0)
                    os.chmod(executable, 0o755)
                    selected_profile = SimpleNamespace(
                        enrollment_id=enrollment.service_enrollment_id,
                        generation=enrollment.service_generation,
                        profile_id=enrollment.profile_id,
                        principal_id=enrollment.principal_id,
                        service_uid=service_account.pw_uid,
                        service_gid=service_account.pw_gid,
                        service_user="nobody",
                        executable=executable,
                        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
                        roots=roots,
                        namespace_identity=enrollment.namespace_identity,
                        runtime_artifact_ids=("memory-fixture-runtime",),
                        package_runtime_records={},
                        authority_endpoint_id="memory-fixture-authority",
                        socket_policy_id="memory-fixture-sockets",
                        target_route_ids=(), operation_targets={}, operation_recipes={},
                    )
                    super().__init__({
                        (enrollment.service_enrollment_id, enrollment.service_generation): selected_profile,
                    }, digest="a" * 64, memory_enrollments={
                        (enrollment.service_enrollment_id, enrollment.service_generation): enrollment,
                    })

            service_catalog = SelectedProfileCatalog()
            # Exercise the production catalog's complete profile/provider/
            # route join before the connector uses the same binding.
            service_catalog.resolve_connector_route(
                enrollment.service_enrollment_id, enrollment.service_generation,
                enrollment.target_id, recipe.approved_route_id)

            class ProcessManager:
                def __init__(self):
                    self.lease_requests = 0

                def resolve_namespace_lease(self, binding):
                    self.lease_requests += 1
                    if (binding.target_id != enrollment.target_id
                            or binding.generation != enrollment.service_generation
                            or binding.namespace_identity != enrollment.namespace_identity):
                        raise AssertionError("namespace lease request differs from selected enrollment")
                    return ManagedNamespaceLease(
                        namespace_fd=os.dup(namespace_fd), pidfd=os.dup(responder_pidfd),
                        uid=service_account.pw_uid, cgroup_identity="isolated-memory-fixture",
                        generation=enrollment.service_generation,
                        namespace_identity=namespace_identity,
                    )

            class Vault:
                def resolve_reference(self, reference_id, *, peer_uid, required_scope, principal_id):
                    if (reference_id != enrollment.auth_reference_id
                            or peer_uid != service_account.pw_uid
                            or required_scope != "memory.agentmemory"
                            or principal_id != enrollment.principal_id):
                        raise PermissionError("fixture credential request escaped protected scope")
                    return "fake-memory-key-for-loopback-test"

            # The production catalog rejects a path below world-writable /tmp,
            # including when the final directory itself is root-owned. Model
            # the installer-owned journal beneath /run in this disposable CI.
            journal = journal_parent / "authority-journal"
            journal.mkdir(mode=0o700)
            os.chown(journal, 0, 0)
            os.chmod(journal, 0o700)
            journal_info = journal.stat(follow_symlinks=False)
            active_digest = hashlib.sha256(b"active-memory-runtime-fixture").hexdigest()
            root_catalog = ProtectedRootJournalCatalog.from_protected_records([{
                "root_id": enrollment.authority_state_root_id,
                "absolute_path": str(journal), "owner_uid": 0, "owner_gid": 0,
                "mode": 0o700, "device": journal_info.st_dev, "inode": journal_info.st_ino,
                "generation": "authority-journal-generation-fixture",
                "purpose": "authority-journal",
            }], generation_digest=active_digest)

            outer = EffectRule("memory-retrieval", "memory.search", "memory:agentmemory:search")
            connector_rule = EffectRule("hermes-service-connect", "connector.open", enrollment.target_id)
            uid = service_account.pw_uid
            binding = PrincipalBinding(
                uid, enrollment.principal_id, enrollment.profile_id, namespace_identity,
                frozenset({"memory-retrieval", "hermes-service-connect"}),
            )
            service = AuthorityService(
                signing_key=b"root-memory-integration-fixture-key".ljust(32, b"!"),
                key_id="root-memory-runtime-fixture", bindings_by_uid={uid: binding},
                rules={(rule.capability, rule.operation, rule.target): rule
                       for rule in (outer, connector_rule)},
                handlers={(outer.operation, outer.target): lambda **_kwargs: {
                    "status": 200, "body": b"unused", "headers": {}, "receipt_id": "unused"}},
                policy=PrivateFixturePolicy(),
                profile_generations={enrollment.profile_id: enrollment.service_generation},
                service_generation_digest=active_digest,
            )
            source_payload = canonical({"schema": 1, "query": "synthetic restart fact", "limit": 3})

            def current_source_and_parent():
                source_digest = canonical_digest(source_payload)
                source_context = HostContext.from_wire(service._issue_context(uid, {
                    "purpose": "memory-search", "intent": "linux-root-loopback-fixture",
                    "trace_id": "trace-root-memory-fixture", "lease_seconds": 30,
                    "source_contexts": [], "final_payload_digest": source_digest,
                    "operation": "memory.search",
                }, inherited_process_identity="root-linux-memory-fixture"))
                parent_effect = EffectAuthorization.from_wire(service._authorize_effect(uid, {
                    "context": source_context.to_wire(), "capability": outer.capability,
                    "target": outer.target, "recipient": None,
                    "request_digest": source_digest, "retry_index": 0,
                }))
                return source_context, parent_effect

            runtime = build_memory_runtime(
                {target_key: enrollment}, service,
                root_journal_resolver=root_catalog.resolve,
                expected_active_generation_digest=active_digest,
                vault=Vault(), service_catalog=service_catalog,
                process_manager=(process_manager := ProcessManager()),
                enrollment_resolver=lambda profile, generation: enrollment
                if (profile, generation) == (enrollment.profile_id, enrollment.service_generation)
                else None,
            )
            self.assertTrue(runtime["state_root_ready"])
            self.assertIsNotNone(runtime["step_authority"])
            self.assertIn(enrollment.target_id, runtime["step_authority"]._registered)
            runtime["owner_ledger"].set_owner(enrollment.profile_id, enrollment.provider)
            state = runtime["state_directories"][enrollment.profile_id]
            profile_dir = state.root
            for directory in (journal, journal / "authority", journal / "authority" / "memory",
                              profile_dir):
                info = directory.stat(follow_symlinks=False)
                self.assertTrue(stat.S_ISDIR(info.st_mode))
                self.assertEqual(info.st_uid, 0)
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)

            # Force both production SQLite stores to retain WAL/SHM handles and
            # verify the actual files created by build_memory_runtime.
            owner_db_path = profile_dir / "owner-ledger.sqlite3"
            owner_db = sqlite3.connect(owner_db_path)
            owner_db.execute("PRAGMA journal_mode=WAL")
            compound = runtime["compound_ledger"][enrollment.profile_id]
            compound_db = compound._connect()
            try:
                for database_path in (owner_db_path, compound.path):
                    _secure_sqlite_files(database_path)
                    for suffix in ("", "-wal", "-shm"):
                        path = Path(str(database_path) + suffix)
                        self.assertTrue(path.exists(), f"SQLite sidecar was not created: {path.name}")
                        info = path.stat(follow_symlinks=False)
                        self.assertTrue(stat.S_ISREG(info.st_mode))
                        self.assertEqual(info.st_uid, 0)
                        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)

                request = {"query": "synthetic restart fact", "limit": 3}
                source, parent = current_source_and_parent()
                routed = build_memory_handlers(
                    targets=runtime["targets"], owner_state=runtime["owner_state"],
                    queue=runtime["queue"], ipc=runtime["ipc"], engines=runtime["engines"],
                    eligibility=runtime["eligibility"],
                    compound_executor=runtime["compound_executor"],
                    maximum_timeout=runtime["maximum_timeout"],
                )
                service.handlers[(outer.operation, outer.target)] = routed[(outer.operation, outer.target)]
                import base64
                effect = service._perform_effect(uid, os.getpid(), {
                    "authorization": parent.to_wire(), "operation": outer.operation,
                    "payload": base64.b64encode(source_payload).decode("ascii"), "timeout": 10.0,
                }, cancelled=lambda: False, enforce_peer_identity=False)
                result = json.loads(base64.b64decode(effect["body"], validate=True))
                self.assertEqual(result.get("status"), "ok", result)
                self.assertEqual(result["result"], {"mode": "compact", "results": []})

                def attempt(consent_wire=None):
                    source_context, parent_effect = current_source_and_parent()
                    return runtime["compound_executor"].execute(
                        enrollment=enrollment, recipe=recipe, body=request,
                        source_context_wire=source_context.to_wire(), parent_authorization=parent_effect,
                        parent_request_payload=source_payload, consent_wire=consent_wire)

                consent_source, _unused_parent = current_source_and_parent()
                claims = {
                    "kind": "memory-background-consent-v1", "consent_id": "revoked-linux-fixture",
                    "source_context_digest": canonical_digest(
                        {**consent_source.claims(), "signature": consent_source.signature}),
                    "principal_id": enrollment.principal_id, "profile_id": enrollment.profile_id,
                    "namespace_id": enrollment.namespace_identity, "uid": uid,
                    "provider_id": enrollment.provider, "owner_generation": 1,
                    "policy_revision": service._policy_revision(), "allowed_actions": ["capture"],
                    "issued_at_unix": service.wall_clock(),
                    "expires_at_unix": service.wall_clock() + 300,
                }
                claims["signature"] = service._sign(claims)
                source_digest_before = process_manager.lease_requests
                with self.assertRaises(MemoryExecutionDenied):
                    attempt(canonical(claims))
                self.assertEqual(process_manager.lease_requests, source_digest_before)

                step_authority = runtime["step_authority"]
                selected_resolver = step_authority.enrollment_resolver
                step_authority.enrollment_resolver = lambda *_args: None
                source_digest_before = process_manager.lease_requests
                with self.assertRaises(MemoryExecutionDenied):
                    attempt()
                self.assertEqual(process_manager.lease_requests, source_digest_before)
                step_authority.enrollment_resolver = selected_resolver

                # The current durable owner epoch changes before any new
                # connector request; the enrolled epoch remains one.
                runtime["owner_ledger"].set_owner(enrollment.profile_id, None)
                source_digest_before = process_manager.lease_requests
                with self.assertRaises(MemoryExecutionDenied):
                    attempt()
                self.assertEqual(process_manager.lease_requests, source_digest_before)
                self.assertEqual(process_manager.lease_requests, 1)
            finally:
                compound_db.close()
                owner_db.close()

            self.assertEqual(runtime["owner_state"](enrollment.profile_id), (None, 2))
            journal_files = list((journal / "authority" / "memory").rglob("*.sqlite3"))
            self.assertGreaterEqual(len(journal_files), 2)
            for path in journal_files:
                info = path.stat(follow_symlinks=False)
                self.assertEqual(info.st_uid, 0)
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        finally:
            if runtime is not None:
                for state_directory in runtime.get("state_directories", {}).values():
                    state_directory.close()
            try:
                os.close(namespace_fd)
                os.close(responder_pidfd)
            except OSError:
                pass
            try:
                waited, _ = os.waitpid(pid, os.WNOHANG)
                if waited == 0:
                    os.kill(pid, signal.SIGTERM)
                    os.waitpid(pid, 0)
            except (ChildProcessError, ProcessLookupError):
                pass
            if journal_parent is not None:
                shutil.rmtree(journal_parent, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
