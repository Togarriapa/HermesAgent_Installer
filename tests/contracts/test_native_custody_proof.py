from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import dataclass, replace
from pathlib import Path

from hermes_installer.authority.native_custody_proof import (
    LivePeerProcess,
    _LaunchObservation,
    NativeLoaderSelection,
    RootNativeLoaderObservationStore,
    active_native_catalog_resolver,
    attach_root_source_observers,
    _parse_progress,
    create_native_loader_channel,
    encode_loader_progress,
    native_bridge_source_target_selector,
)
from hermes_installer.authority.source_observers import SourceObserverEnrollment
from hermes_installer.authority.types import AuthorityDenied, HostContext, Sensitivity, canonical_digest
from hermes_installer.managed_process_custodian import LivePeerIdentity, NativePackageMountReceipt


_ENTRY = "d" * 64
_RESOLVER = "e" * 64
_CLOSURE = "a" * 64
_ROLE = "b" * 64
_GENERATION_DIGEST = "c" * 64


@dataclass(frozen=True)
class _Profile:
    owner_uid: int
    owner_gid: int
    artifact_sha256: str
    profile_id: str = "producer-profile"
    generation: str = "generation-1"


@dataclass
class _OwnedHandle:
    process_id: str
    pid: int
    child_pidfd: int
    start_ticks: int
    cgroup: str
    kernel_namespace_id: str
    profile: _Profile
    expires: float


@dataclass
class _MountProof:
    process_id: str
    profile_id: str
    generation: str
    kernel_uid: int
    pid_start_ticks: int
    cgroup_identity: str
    namespace_identity: str
    executable_sha256: str
    mount: NativePackageMountReceipt


@dataclass(frozen=True)
class _SelectedTarget:
    pid: int
    pidfd: int
    uid: int
    profile_id: str
    generation: str
    identity: LivePeerIdentity


@dataclass(frozen=True)
class _PendingPeer:
    role: str
    principal_id: str
    profile_id: str
    generation: str
    pid: int
    pidfd: int
    uid: int
    identity: LivePeerIdentity
    role_artifact_id: str
    role_artifact_sha256: str


@dataclass(frozen=True)
class _DeliveryBinding:
    observer_enrollment_id: str
    delivery_role: str


@dataclass(frozen=True)
class _PendingPair:
    schema: int
    pair_id: str
    bridge_enrollment_id: str
    native_request_handle: str
    parent_context_sha256: str
    parent_grant_id: str
    intent_id: str
    trace_id: str
    parent_closure_digest: str
    service_generation_digest: str
    producer: _PendingPeer
    gateway: _PendingPeer
    observer_delivery_bindings: tuple[_DeliveryBinding, ...]
    expires_monotonic: float


def _observer(**changes):
    fields = dict(
        observer_enrollment_id="observer.test",
        source_kind="native-input",
        origin_id="hermes.primary",
        profile_id="producer-profile",
        principal_id="producer-principal",
        namespace_id="producer-namespace",
        enrollment_id="producer-enrollment",
        generation="generation-1",
        producer_uid=os.getuid() or 1,
        producer_executable_sha256=_ROLE,
        package_id="package-1",
        package_sha256=_CLOSURE,
        role_id="hermes-main",
        role_artifact_id="loader-role",
        role_sha256=_ROLE,
        channel_id="chat.request",
        capture_schema_id="capture.request",
        source_action_id="action.input",
        target_id="fixed.target",
        recipient="public-provider",
        allowed_parent_source_kinds=frozenset({"native-input"}),
        lease_seconds=20,
    )
    fields.update(changes)
    return SourceObserverEnrollment(**fields)


class _Custody:
    def __init__(self, identity: LivePeerIdentity, mount_proof: _MountProof):
        self.identity = identity
        self.mount_proof = mount_proof

    @staticmethod
    def is_owned_active_process_handle(_handle):
        return True

    def resolve_live_peer(self, pid, pidfd, *, profile_id, generation):
        if (RootNativeLoaderObservationStore._pidfd_target(pidfd) != pid
                or RootNativeLoaderObservationStore._pidfd_exited(pidfd)
                or self.identity.profile_id != profile_id
                or self.identity.generation != generation):
            return None
        return self.identity

    def resolve_native_package_for_peer(self, pid, pidfd):
        if (RootNativeLoaderObservationStore._pidfd_target(pidfd) != pid
                or RootNativeLoaderObservationStore._pidfd_exited(pidfd)):
            return None
        return self.mount_proof


def _selection(process_id="owned-process"):
    return NativeLoaderSelection(
        process_id=process_id,
        package_id="package-1",
        profile_id="producer-profile",
        generation="generation-1",
        compiled_closure_sha256=_CLOSURE,
        entrypoint_sha256=_ENTRY,
        resolver_sha256=_RESOLVER,
        service_generation_digest=_GENERATION_DIGEST,
        loader_role_artifact_id="loader-role",
        loader_role_sha256=_ROLE,
        registered_action_ids=("action.input", "tool.invoke"),
        observer_role_action_bindings=(("loader-role", _ROLE, "action.input"),),
    )


def _context(identity):
    return HostContext(
        principal_id="producer-principal", profile_id=identity.profile_id,
        namespace_id="producer-namespace", uid=identity.kernel_uid,
        purpose="native-event", intent_id="intent", trace_id="trace",
        sensitivity=Sensitivity.UNKNOWN, lineage_hash=canonical_digest({"root": True}),
        policy_revision="policy", capabilities=frozenset({"provider-dispatch"}),
        issued_at_monotonic=1.0, monotonic_expires_at=60.0,
        nonce="n" * 32, grant_id="grant", signature="signed",
        enrollment_id="producer-enrollment", generation=identity.generation,
        operation="native.event.prepare", native_process_identity="current",
    )


class ProgressWireContracts(unittest.TestCase):
    def _frame(self, sequence, phase, actions=()):
        return encode_loader_progress(
            launch_nonce="N" * 43, sequence=sequence, phase=phase,
            package_id="package-1", generation="generation-1",
            entrypoint_sha256=_ENTRY, resolver_sha256=_RESOLVER,
            registered_action_ids=actions,
        )[4:]

    def test_canonical_progress_record_parses_and_rejects_duplicate_or_unknown_fields(self):
        record = _parse_progress(self._frame(0, "entrypoint-imported"))
        self.assertEqual(record.sequence, 0)
        self.assertEqual(record.phase, "entrypoint-imported")
        with self.assertRaises(AuthorityDenied):
            _parse_progress(b'{"schema":1,"schema":1}')

    def test_revoked_launch_cleanup_closes_fd_and_unlinks_private_socket(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "launch"
            directory.mkdir(mode=0o700)
            socket_path = directory / "progress.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(socket_path))
            listener.listen(1)
            child_pidfd = os.open("/dev/null", os.O_RDONLY)
            entry = _LaunchObservation(
                handle="test-handle", owned_process_handle=None, selection=None,
                listener_socket=listener, parent_socket=None,
                socket_path=socket_path, socket_directory=directory,
                child_pid=1, child_pidfd=child_pidfd, child_uid=1, child_gid=1,
                child_start_ticks=1, child_cgroup="test", child_namespace="mnt:1;net:1",
                launch_nonce="N" * 43, deadline=1.0,
            )

            RootNativeLoaderObservationStore._close_entry(entry)

            self.assertFalse(socket_path.exists())
            self.assertFalse(directory.exists())
            with self.assertRaises(OSError):
                os.fstat(child_pidfd)
        with self.assertRaises(AuthorityDenied):
            _parse_progress(self._frame(0, "entrypoint-imported")[:-1] + b" ")

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(socket, "SO_PASSCRED"),
                         "requires Linux systemd OpenFile credential transport")
    def test_native_channel_is_a_private_named_openfile_listener_with_root_nonce(self):
        with tempfile.TemporaryDirectory(prefix="h", dir="/tmp") as temp:
            parent = create_native_loader_channel(Path(temp))
            try:
                self.assertEqual(parent.listener.family, socket.AF_UNIX)
                self.assertFalse(parent.listener.get_inheritable())
                self.assertEqual(len(parent.launch_nonce), 43)
                self.assertTrue(parent.socket_path.exists())
                self.assertTrue(parent.systemd_open_file_property.endswith(":hermes-loader-progress"))
            finally:
                parent.close()

    def test_active_root_composition_attaches_only_typed_observers_and_real_resolvers(self):
        identity = LivePeerIdentity("producer-profile", "generation-1", 2001, 7,
                                    _ROLE, "cgroup", "mnt:2;net:3")
        mount = _MountProof(
            "owned", "producer-profile", "generation-1", 2001, 7,
            "cgroup", "mnt:2;net:3", _ROLE,
            NativePackageMountReceipt(
                "package-1", "producer-profile", "generation-1", "mount-1",
                _CLOSURE, _ENTRY, _RESOLVER, "/native", 8, 9, _ENTRY,
            ),
        )
        custody = _Custody(identity, mount)
        selected_target = _SelectedTarget(11, 12, 2001, "producer-profile",
                                          "generation-1", identity)
        loader_store = RootNativeLoaderObservationStore(
            custody, lambda _handle: _selection(),
            source_target_selector=lambda _observer, _context: selected_target,
        )

        class _Service:
            authority_epoch = "epoch-1"
            source_observer_registry = None

            @staticmethod
            def monotonic():
                return 10.0

            @staticmethod
            def issue_observed_source(_observation):
                return "opaque"

            def attach_source_observer_registry(self, registry):
                if self.source_observer_registry is not None:
                    raise AssertionError("registry already attached")
                self.source_observer_registry = registry

        service = _Service()
        observer = _observer(producer_uid=2001)
        registry = attach_root_source_observers(
            service=service,
            observer_enrollments={observer.observer_enrollment_id: observer},
            process_resolver=lambda *_args, **_kwargs: identity,
            package_resolver=lambda *_args: object(),
            loader_observations=loader_store,
        )
        self.assertIs(service.source_observer_registry, registry)
        self.assertIs(service.native_loader_observation_store, loader_store)
        self.assertIs(registry.loaded_package_proof_resolver.__self__, loader_store)
        self.assertIs(registry.target_peer_resolver.__self__, loader_store)
        loader_store.close()

    def test_runtime_metadata_alone_cannot_construct_a_source_proof_resolver(self):
        identity = LivePeerIdentity("producer-profile", "generation-1", 2001, 7,
                                    _ROLE, "cgroup", "mnt:2;net:3")
        custody = _Custody(identity, object())
        with self.assertRaises(ValueError):
            RootNativeLoaderObservationStore(custody, lambda _handle: _selection())

    def test_structural_custody_facade_without_manager_owned_handle_registry_denies(self):
        identity = LivePeerIdentity("producer-profile", "generation-1", 2001, 7,
                                    _ROLE, "cgroup", "mnt:2;net:3")
        custody = type("MountOnlyCustody", (), {
            "resolve_live_peer": lambda *_args, **_kwargs: identity,
            "resolve_native_package_for_peer": lambda *_args, **_kwargs: None,
        })()
        with self.assertRaises(ValueError):
            RootNativeLoaderObservationStore(
                custody, lambda _handle: _selection(),
                source_target_selector=lambda _observer, _context: None,
            )

    def test_active_catalog_resolver_joins_observer_role_to_selected_manifest_action(self):
        observer = _observer(producer_uid=os.getuid() or 1)
        package = type("Package", (), {
            "package_id": "package-1", "profile_id": observer.profile_id,
            "generation": observer.generation, "compiled_closure_sha256": _CLOSURE,
            "entrypoint_sha256": _ENTRY, "resolver_sha256": _RESOLVER,
            "entrypoint_artifact_id": "loader-role",
            "adapter_records": {
                "adapter": type("Adapter", (), {
                    "action_id": "action.input", "adapter_artifact_id": "loader-role",
                    "adapter_sha256": _ROLE,
                    "observer_enrollment_ids": (observer.observer_enrollment_id,),
                })(),
            },
        })()

        class _Bindings:
            source_observer_enrollments = {observer.observer_enrollment_id: observer}

            @staticmethod
            def resolve_native_package(package_id, generation):
                if (package_id, generation) != ("package-1", "generation-1"):
                    return None
                return package

        resolver = active_native_catalog_resolver(
            _Bindings(), service_generation_digest=_GENERATION_DIGEST,
        )
        handle = _OwnedHandle(
            "owned-process", 2, 3, 4, "cgroup", "mnt:5;net:6",
            _Profile(1, 1, _ROLE), 100.0,
        )
        selected = resolver(handle)
        self.assertEqual(selected.package_id, "package-1")
        self.assertEqual(selected.registered_action_ids, ("action.input",))
        self.assertEqual(selected.observer_role_action_bindings,
                         (("loader-role", _ROLE, "action.input"),))


@unittest.skipUnless(sys.platform.startswith("linux")
                     and hasattr(socket, "SO_PASSCRED") and hasattr(os, "pidfd_open"),
                     "requires Linux PIDFD and SCM_CREDENTIALS")
class RootLoaderObservationContracts(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="h", dir="/tmp")
        self.channel = create_native_loader_channel(Path(self.tempdir.name))
        self.nonce = self.channel.launch_nonce
        self.ack_read, self.ack_write = os.pipe()
        actions = ["action.input", "tool.invoke"]
        script = (
            "import os,socket,sys; from hermes_installer.authority.native_custody_proof import encode_loader_progress; "
            "path=sys.argv[1]; ack=int(sys.argv[2]); s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); "
            "s.connect(path); nonce=s.recv(43).decode('ascii'); "
            f"actions={actions!r}; "
            "frames=[(0,'entrypoint-imported',[]),(1,'actions-registered',actions),(2,'ready',actions)]; "
            "[s.sendall(encode_loader_progress(launch_nonce=nonce,sequence=i,phase=p,package_id='package-1',generation='generation-1',entrypoint_sha256='"
            + _ENTRY + "',resolver_sha256='" + _RESOLVER + "',registered_action_ids=a)) for i,p,a in frames]; "
            "s.close(); os.read(ack,1)"
        )
        self.uid = os.getuid() if os.getuid() > 0 else 2001
        self.gid = os.getgid() if os.getgid() > 0 else self.uid
        preexec_fn = None
        if os.getuid() == 0:
            def drop_to_fixture_uid():
                os.setgid(self.uid)
                os.setuid(self.uid)
            preexec_fn = drop_to_fixture_uid
        self.child = subprocess.Popen(
            [sys.executable, "-c", script, str(self.channel.socket_path), str(self.ack_read)],
            pass_fds=(self.ack_read,),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, preexec_fn=preexec_fn,
        )
        self.child_pidfd = os.pidfd_open(self.child.pid)
        self.identity = LivePeerIdentity(
            "producer-profile", "generation-1", self.uid, 123,
            _ROLE, "cgroup-test", "mnt:234;net:345",
        )
        self.mount_receipt = NativePackageMountReceipt(
            package_id="package-1", profile_id="producer-profile", generation="generation-1",
            service_mount_id="mount-1", compiled_closure_sha256=_CLOSURE,
            entrypoint_sha256=_ENTRY, resolver_sha256=_RESOLVER,
            mount_path="/hermes/native/package-1", mount_source_device=8,
            mount_source_inode=99, manifest_sha256=_ENTRY,
        )
        self.mount_proof = _MountProof(
            "owned-process", "producer-profile", "generation-1", self.uid, 123,
            "cgroup-test", "mnt:234;net:345", _ROLE, self.mount_receipt,
        )
        self.custody = _Custody(self.identity, self.mount_proof)
        self.handle = _OwnedHandle(
            "owned-process", self.child.pid, self.child_pidfd, 123,
            "cgroup-test", "mnt:234;net:345", _Profile(self.uid, self.gid, _ROLE),
            time.monotonic() + 30,
        )
        self.selector_calls = []

        def target_selector(observer, context):
            self.selector_calls.append((observer.observer_enrollment_id, context))
            return _SelectedTarget(self.child.pid, os.dup(self.child_pidfd), self.uid,
                                   observer.profile_id, observer.generation, self.identity)

        self.store = RootNativeLoaderObservationStore(
            self.custody, lambda _handle: _selection(), source_target_selector=target_selector,
        )
        self.launch_handle = self.store.register_launch(
            self.handle, self.channel, "loader-role", _ROLE, self.nonce,
            time.monotonic() + 20,
        )

    def tearDown(self):
        self.store.close()
        try:
            os.write(self.ack_write, b"x")
        except OSError:
            pass
        try:
            self.child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.child.kill()
            self.child.wait(timeout=2)
        for fd in (self.child_pidfd, self.ack_read, self.ack_write):
            try:
                os.close(fd)
            except OSError:
                pass
        self.tempdir.cleanup()

    def test_ready_event_joins_live_mount_and_produces_stable_proof(self):
        event_id = self.store.receive_loader_progress(self.launch_handle, lambda: False)
        observer = _observer(producer_uid=self.uid)
        peer = LivePeerProcess(self.child.pid, self.child_pidfd, self.identity)
        first = self.store.resolve_loaded_package_closure(peer, observer)
        second = self.store.resolve_loaded_package_closure(peer, observer)
        self.assertEqual(first.schema, 1)
        self.assertEqual(first.loader_ready_event_id, event_id)
        self.assertEqual(first.observed_entrypoint_action_ids, ("action.input", "tool.invoke"))
        self.assertEqual(first, second)
        with self.assertRaises(AuthorityDenied):
            self.store.receive_loader_progress(self.launch_handle, lambda: False)

    def test_mount_receipt_alone_is_not_a_loader_ready_proof(self):
        observer = _observer(producer_uid=self.uid)
        peer = LivePeerProcess(self.child.pid, self.child_pidfd, self.identity)
        self.assertIsNotNone(self.custody.resolve_native_package_for_peer(
            self.child.pid, self.child_pidfd))
        with self.assertRaises(AuthorityDenied):
            self.store.resolve_loaded_package_closure(peer, observer)

    def test_cancelled_loader_observation_revokes_event_before_proof(self):
        peer = LivePeerProcess(self.child.pid, self.child_pidfd, self.identity)
        observer = _observer(producer_uid=self.uid)
        with self.assertRaises(AuthorityDenied):
            self.store.receive_loader_progress(self.launch_handle, lambda: True)
        with self.assertRaises(AuthorityDenied):
            self.store.resolve_loaded_package_closure(peer, observer)

    def test_changed_mount_and_live_peer_invalidate_proof(self):
        self.store.receive_loader_progress(self.launch_handle, lambda: False)
        observer = _observer(producer_uid=self.uid)
        peer = LivePeerProcess(self.child.pid, self.child_pidfd, self.identity)
        self.store.resolve_loaded_package_closure(peer, observer)
        self.custody.mount_proof = _MountProof(
            "owned-process", "producer-profile", "generation-1", self.uid, 123,
            "cgroup-test", "mnt:234;net:345", _ROLE,
            replace(self.mount_receipt, service_mount_id="mount-replaced"),
        )
        with self.assertRaises(AuthorityDenied):
            self.store.resolve_loaded_package_closure(peer, observer)
        self.custody.identity = LivePeerIdentity(
            "other-profile", "generation-1", self.uid, 123, _ROLE,
            "cgroup-test", "mnt:234;net:345",
        )
        with self.assertRaises(AuthorityDenied):
            self.store.resolve_loaded_package_closure(peer, observer)

    def test_target_peer_is_root_selected_pidfd_duplicate_and_stale_target_denies(self):
        self.store.receive_loader_progress(self.launch_handle, lambda: False)
        observer = _observer(producer_uid=self.uid)
        target = self.store.resolve_source_target_peer(observer, _context(self.identity))
        try:
            self.assertEqual(target.pid, self.child.pid)
            self.assertEqual(target.uid, self.uid)
            self.assertNotEqual(target.pidfd, self.child_pidfd)
            self.assertEqual(len(self.selector_calls), 1)
            self.custody.identity = LivePeerIdentity(
                "other-profile", "generation-1", self.uid, 123, _ROLE,
                "cgroup-test", "mnt:234;net:345",
            )
            with self.assertRaises(AuthorityDenied):
                self.store.resolve_source_target_peer(observer, _context(self.identity))
        finally:
            os.close(target.pidfd)

    def test_hi11_source_target_uses_explicit_observer_pair_role_and_releases_other_pidfd(self):
        observer = _observer(producer_uid=self.uid)
        context = _context(self.identity)
        pair_holder = []

        class _Broker:
            def resolve_pending_pair_for_context(_self, exact_context):
                if exact_context != context:
                    return None
                producer_fd = os.dup(self.child_pidfd)
                gateway_fd = os.dup(self.child_pidfd)
                pair = _PendingPair(
                    1, "pair-id", "bridge-id", "native-request",
                    canonical_digest(context.to_wire()), context.grant_id,
                    context.intent_id, context.trace_id, context.lineage_hash,
                    _GENERATION_DIGEST,
                    _PendingPeer("producer", "principal", observer.profile_id,
                                 observer.generation, self.child.pid, producer_fd,
                                 self.uid, self.identity, "loader-role", _ROLE),
                    _PendingPeer("gateway", "principal", observer.profile_id,
                                 observer.generation, self.child.pid, gateway_fd,
                                 self.uid, self.identity, "loader-role", _ROLE),
                    (_DeliveryBinding(observer.observer_enrollment_id, "gateway"),),
                    time.monotonic() + 5,
                )
                pair_holder.append(pair)
                return pair

        selector = native_bridge_source_target_selector(_Broker())
        selected = selector(observer, context)
        self.assertEqual(selected.pid, self.child.pid)
        self.assertEqual(selected.profile_id, observer.profile_id)
        self.assertNotEqual(selected.pidfd, pair_holder[0].producer.pidfd)
        with self.assertRaises(OSError):
            os.fstat(pair_holder[0].producer.pidfd)
        self.assertGreater(os.fstat(selected.pidfd).st_ino, 0)
        os.close(selected.pidfd)


if __name__ == "__main__":
    unittest.main()
