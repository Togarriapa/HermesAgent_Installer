from __future__ import annotations

import os
import threading
from types import SimpleNamespace

from hermes_installer.authority.native_profile_task_homes import (
    RootNativeProfileTaskHomeRegistry,
    RootSelectedResourceTaskHomeBinding,
)


def test_cancelled_admitted_task_cannot_keep_a_task_home_binding_current() -> None:
    event = object()
    handle = SimpleNamespace(handle_id="admission", job_id="job")
    task = object()
    child = object()

    class Jobs:
        _task_handle_lock = threading.RLock()
        _resolved_controller_evidence = {"admission": ("token", "event", *([None] * 10))}
        _controller_resolved_handles = {"admission"}
        _root_event_by_job = {"job": event}

        def resolve_admitted_task(self, got, node):
            assert got is handle and node == "node"
            return task

        def resolve_task_child_admission(self, got, node):
            assert got is handle and node == "node"
            return child

        def is_admitted_task_current(self, got):
            assert got is task
            return False  # cancelled/revoked after the home binding was minted

    registry = object.__new__(RootNativeProfileTaskHomeRegistry)
    registry.jobs = Jobs()
    registry.service = SimpleNamespace(authority_epoch="epoch")
    registry._source_is_current = lambda *_args: True
    registry.controllers = SimpleNamespace(
        resolve_for_event=lambda *_args: (_ for _ in ()).throw(AssertionError("stale task reached controller")),
    )
    binding = SimpleNamespace(
        _admission_handle=handle, _node_id="node", _task_admission=task,
        _child_admission=child, _admitted_source=object(), _controller_evidence=registry.jobs._resolved_controller_evidence["admission"],
        _root_event=event,
    )

    assert not RootNativeProfileTaskHomeRegistry._task_source_controller_current(registry, binding)


def test_current_crosswalk_stays_open_until_its_caller_finishes() -> None:
    class Proof:
        publication_handle = "publication"
        crosswalk_member_sha256 = "a" * 64
        source_output_claim_sha256 = "b" * 64

        def __init__(self):
            self.close_calls = 0

        def verify_current(self):
            return self

        def close(self):
            self.close_calls += 1

    proof = Proof()
    current_journal = object()

    class Core:
        service_generation_digest = "generation"

        def verify_current(self):
            return self

        def resolve_current_native_profile_home_crosswalk(self):
            return proof

    registry = object.__new__(RootNativeProfileTaskHomeRegistry)
    registry.principals = SimpleNamespace(resolve_root_journal=lambda *_args, **_kwargs: current_journal)
    registry.root_journal = current_journal
    registry.core = Core()
    registry.crosswalk = SimpleNamespace(
        publication_handle=proof.publication_handle,
        crosswalk_member_sha256=proof.crosswalk_member_sha256,
        source_output_claim_sha256=proof.source_output_claim_sha256,
    )

    returned = RootNativeProfileTaskHomeRegistry._current_crosswalk(registry)
    assert returned is proof
    assert proof.close_calls == 0
    returned.close()
    assert proof.close_calls == 1


def test_failed_concurrent_task_releases_only_its_home_fd(tmp_path) -> None:
    shared_home_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    task_fd_one = os.dup(shared_home_fd)
    task_fd_two = os.dup(shared_home_fd)

    class SharedHome:
        close_calls = 0

        def close(self):
            self.close_calls += 1

    class RuntimeProof:
        def __init__(self, *, fail_close=False):
            self.closed = False
            self.fail_close = fail_close

        def close(self):
            self.closed = True
            if self.fail_close:
                raise RuntimeError("fixture close failure")

    shared_home = SharedHome()
    bindings = []
    registry = object.__new__(RootNativeProfileTaskHomeRegistry)
    registry._lock = threading.RLock()
    registry._bindings = {}
    for handle, descriptor in (("one", task_fd_one), ("two", task_fd_two)):
        runtime = RuntimeProof(fail_close=handle == "one")
        binding = object.__new__(RootSelectedResourceTaskHomeBinding)
        object.__setattr__(binding, "binding_handle", handle)
        object.__setattr__(binding, "_home", shared_home)
        object.__setattr__(binding, "_home_fd", descriptor)
        object.__setattr__(binding, "_runtime", runtime)
        registry._bindings[handle] = binding
        bindings.append((binding, runtime, descriptor))

    RootNativeProfileTaskHomeRegistry.revoke(registry, bindings[0][0])
    try:
        assert bindings[0][1].closed
        assert not bindings[1][1].closed
        assert os.fstat(bindings[1][2]).st_ino == os.fstat(shared_home_fd).st_ino
        assert shared_home.close_calls == 0

        RootNativeProfileTaskHomeRegistry.revoke(registry, bindings[1][0])
        assert bindings[1][1].closed
        assert shared_home.close_calls == 0
        assert os.fstat(shared_home_fd).st_ino == os.stat(tmp_path).st_ino
    finally:
        for _binding, _runtime, descriptor in bindings:
            try:
                os.close(descriptor)
            except OSError:
                pass
        os.close(shared_home_fd)
