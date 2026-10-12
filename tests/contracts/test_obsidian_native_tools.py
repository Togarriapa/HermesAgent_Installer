"""Native-call wrapper contracts for the Obsidian storage leaf.

These tests bind synthetic root receipts only to exercise the wrapper. They do
not prove ROOT's middleware issuance, per-call vault binding, or Pi acceptance.
"""
from __future__ import annotations

import hashlib
import json
import time
from unittest.mock import patch

import pytest

from hermes_installer.native_invocations import NativeToolDispatch, canonical_tool_arguments
from hermes_installer.remote.core_native_observer import ObservedNativeToolCall
from hermes_installer.remote.jarvis_final_effects import FinalEffectPermit, review_digest
from hermes_installer.remote.jarvis_mission_executor import MissionBinding
from hermes_installer.remote.obsidian_native_tools import (
    ObsidianNativeToolUnavailable, ObsidianNativeTools, _admit_current_obsidian_call,
)
from hermes_installer.remote.obsidian_native_scope import (
    RootObsidianCallScope, RootObsidianDraftOrigin, RootSelectedObsidianVaultBinding,
    _BINDING_SEAL, _SCOPE_SEAL, _decode_draft_origin, _decode_draft_review,
    _decode_draft_review_proposal,
)
from hermes_installer.remote.obsidian_second_brain import (
    ObsidianVaultConfig, prepare_obsidian_vault,
)

OWNER = "a" * 64


def _write_fixture(path, text):
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


class _PluginContext:
    def __init__(self):
        self.tools = {}

    def register_tool(self, **kwargs):
        self.tools[kwargs["name"]] = kwargs


def _binding(store, name, args, *, mode="master_read", execution_id="D" * 43,
             source="hermes", mission=None, selected=None, with_permit=False):
    canonical = canonical_tool_arguments(args)
    digest = hashlib.sha256(canonical).hexdigest()
    observed = ObservedNativeToolCall(
        handle="B" * 43, attempt_handle="C" * 43, owner_turn_handle="D" * 43,
        tool_call_id="obsidian-native-call", tool_name=name,
        arguments_sha256=digest, expires_monotonic=time.monotonic() + 20,
    )
    issued = time.monotonic()
    binding = RootSelectedObsidianVaultBinding(
        binding_id="G" * 43, registration_sha256="a" * 64,
        owner_subject_sha256=OWNER, core_generation="1" * 64,
        core_source_generation="2" * 64, core_pid=123, core_start_ticks="44",
        selected_owner_uid=1000, vault_root="/home/admin/.hermes/jarvis-second-brain",
        issued_monotonic=issued, expires_monotonic=issued + 20, _seal=_BINDING_SEAL,
    )
    scope = RootObsidianCallScope(
        observed_call_handle=observed.handle, owner_turn_handle=observed.owner_turn_handle,
        tool_call_id=observed.tool_call_id, tool_name=name, arguments_sha256=digest,
        owner_subject_sha256=OWNER, registration_sha256="a" * 64,
        startup_binding_id=binding.binding_id, core_generation="1" * 64,
        core_source_generation="2" * 64, source_generation_sha256="f" * 64,
        mode=mode, execution_id=(observed.owner_turn_handle if mode != "expert_read" else execution_id),
        source_instance_id=source, mission_binding=mission, selected_note_ids=selected,
        issued_monotonic=issued, expires_monotonic=issued + 5, _seal=_SCOPE_SEAL,
    )
    permit = None
    if with_permit:
        permit = FinalEffectPermit(
            pending_id="E" * 43, owner_turn_handle=observed.owner_turn_handle,
            gateway_turn_id="turn-owner", owner_subject_sha256=OWNER,
            core_generation="1" * 64, core_source_generation="2" * 64,
            source_generation_sha256="f" * 64, source_profile_id="hermes",
            tool_call_id=observed.tool_call_id, tool_name=name,
            arguments_sha256=digest, review_sha256=review_digest(name, digest),
            expires_monotonic=time.monotonic() + 10,
        )
    dispatch = NativeToolDispatch(object(), observed.tool_call_id, name, canonical)
    return observed, scope, binding, permit, dispatch, execution_id, source, mission, selected


def _mission():
    return MissionBinding(
        schema=2, mission_id="mission_" + "1" * 24, revision=1, plan_sha256="1" * 64,
        task_sha256="2" * 64, source_profile_id="hermes", execution_mode="oneshot",
        autonomy_mode="approval_required", selected_source_ids=("expert_alpha",),
        scope_sha256="3" * 64, authorization_sha256=None,
    )


class _OriginObserver:
    def __init__(self, store):
        self.store = store
        self.reservation_error = None

    def record_obsidian_draft_origin(self, *, observed_call, binding, draft_id):
        assert observed_call.tool_name == "obsidian_create_private_draft"
        assert binding.owner_subject_sha256 == OWNER
        review = self.store.read_owner_draft(draft_id=draft_id)
        return hashlib.sha256(review.markdown.encode("utf-8")).hexdigest()

    def resolve_obsidian_draft_origin(self, *, observed_call, binding, draft_id,
                                      expected_content_sha256):
        assert observed_call.tool_name == "obsidian_promote_reviewed_draft"
        draft = self.store.read_owner_draft(draft_id=draft_id).draft
        assert draft.content_sha256 == expected_content_sha256
        issued = time.monotonic()
        return _decode_draft_origin({
            "schema": 1, "nonce": "fixture", "ok": True, "draft_id": draft_id,
            "owner_subject_sha256": OWNER, "registration_sha256": binding.registration_sha256,
            "origin_execution_id": draft.execution_id, "origin_source_id": draft.source_instance_id,
            "origin_source_revision": "source-revision",
            "source_generation_sha256": "f" * 64, "mission_sha256": None,
            "content_sha256": draft.content_sha256, "base_sha256": draft.base_sha256,
            "origin_record_sha256": "e" * 64, "state": "private-draft",
            "issued_monotonic": issued, "expires_monotonic": issued + 4,
        })

    def read_obsidian_private_draft(self, *, observed_call, binding, draft_id,
                                    expected_content_sha256):
        assert observed_call.tool_name == "obsidian_read_private_draft"
        assert binding.owner_subject_sha256 == OWNER
        reviewed = self.store.read_owner_draft(draft_id=draft_id)
        draft = reviewed.draft
        issued = time.monotonic()
        byte_length = len(reviewed.markdown.encode("utf-8"))
        delivery = {
            "receipt_id": "R" * 43, "owner_subject_sha256": OWNER,
            "owner_turn_handle": observed_call.owner_turn_handle,
            "draft_id": draft_id, "content_sha256": expected_content_sha256,
            "origin_record_sha256": "e" * 64, "source_generation_sha256": "f" * 64,
            "startup_binding_id": binding.binding_id,
            "observed_call_handle": observed_call.handle,
            "tool_call_id": observed_call.tool_call_id,
            "arguments_sha256": observed_call.arguments_sha256,
            "returned_byte_length": byte_length,
            "returned_content_sha256": expected_content_sha256,
            "complete": True, "covered_byte_length": byte_length,
            "delivered_monotonic": issued, "expires_monotonic": issued + 4,
        }
        delivery["receipt_sha256"] = hashlib.sha256(json.dumps(
            delivery, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False).encode("utf-8")).hexdigest()
        return _decode_draft_review({
            "schema": 1, "nonce": "fixture", "ok": True,
            "draft_id": draft_id, "title": draft.title, "markdown": reviewed.markdown,
            "content_sha256": expected_content_sha256,
            "byte_length": len(reviewed.markdown.encode("utf-8")),
            "review_complete": True, "next_step": None,
            "base_note_id": draft.base_note_id, "base_sha256": draft.base_sha256,
            "origin_source_id": draft.source_instance_id,
            "origin_source_revision": "source-revision",
            "origin_execution_id": draft.execution_id, "mission_sha256": None,
            "source_generation_sha256": "f" * 64,
            "origin_record_sha256": "e" * 64,
            "delivery": delivery,
            "issued_monotonic": issued, "expires_monotonic": issued + 4,
        })

    def resolve_obsidian_review_proposal(self, *, observed_call, binding, draft_id,
                                        expected_content_sha256):
        draft = self.store.read_owner_draft(draft_id=draft_id).draft
        issued = time.monotonic()
        payload = {
            "proposal_id": "Q" * 43, "owner_subject_sha256": OWNER,
            "owner_turn_handle": observed_call.owner_turn_handle,
            "draft_id": draft_id, "content_sha256": expected_content_sha256,
            "destination": "Notes/Final.md", "expected_base_sha256": None,
            "disposition": "approve", "rationale": None,
            "observed_call_handle": observed_call.handle,
            "tool_call_id": observed_call.tool_call_id,
            "arguments_sha256": observed_call.arguments_sha256,
            "source_generation_sha256": "f" * 64,
            "read_delivery_receipt_id": "R" * 43,
            "read_delivery_sha256": "1" * 64,
            "read_delivery_output_sha256": "2" * 64,
            "origin_record_sha256": "e" * 64,
            "created_monotonic": issued, "owner_expires_monotonic": issued + 15,
            "call_expires_monotonic": issued + 15, "expires_monotonic": issued + 15,
        }
        payload["proposal_sha256"] = hashlib.sha256(json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False).encode("utf-8")).hexdigest()
        return _decode_draft_review_proposal({
            "schema": 1, "nonce": "fixture", "ok": True, **payload,
        })

    def reserve_obsidian_draft_completion(self, **_kwargs):
        if self.reservation_error is not None:
            raise self.reservation_error
        return None

    def complete_obsidian_draft_origin(self, **_kwargs):
        return None

    def confirm_obsidian_draft_read_delivery(self, **_kwargs):
        return None


def test_registers_finite_tools_without_identity_or_path_arguments(tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    store = prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER, owner_uid=1000))
    context = _PluginContext()

    names = ObsidianNativeTools(store).register(context)

    assert set(names) == set(context.tools)
    assert all(row["schema"].get("additionalProperties") is False for row in context.tools.values())
    for row in context.tools.values():
        assert not {"owner", "owner_subject_sha256", "execution_id", "source_instance_id",
                    "note_scope", "vault_path", "permit"} & set(row["schema"]["properties"])


def test_lazy_registration_does_not_need_startup_observer_binding(tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    store = prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER, owner_uid=1000))
    args = {"query": "owner"}
    observed, scope, binding, _permit, dispatch, *_ = _binding(
        store, "obsidian_search_notes", args)
    context = _PluginContext()
    tools = ObsidianNativeTools()

    with patch("hermes_installer.remote.obsidian_second_brain.ObsidianVaultStore",
               side_effect=lambda _config: store) as open_store:
        names = tools.register(context)
        assert set(names) == set(context.tools)
        open_store.assert_not_called()
        with patch("hermes_installer.remote.obsidian_native_tools.os.geteuid",
                   return_value=1000), patch(
                "hermes_installer.remote.obsidian_native_tools.current_native_tool_dispatch",
                return_value=dispatch), _admit_current_obsidian_call(
                observed_call=observed, scope=scope, binding=binding):
            result = context.tools["obsidian_search_notes"]["handler"](args)

    assert result["notes"] == []
    open_store.assert_called_once()


def test_master_read_uses_exact_current_call_and_fixed_owner_store(tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    store = prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER, owner_uid=1000))
    _write_fixture(store._root / "Notes" / "Owner.md", "# Owner\nCurrent owner note.\n")
    tool = ObsidianNativeTools(store).handler("obsidian_search_notes")
    args = {"query": "Current owner"}
    observed, scope, binding, _permit, dispatch, execution, source, mission, selected = _binding(
        store, "obsidian_search_notes", args)

    with patch("hermes_installer.remote.obsidian_native_tools.current_native_tool_dispatch",
               return_value=dispatch), _admit_current_obsidian_call(
            observed_call=observed, scope=scope, binding=binding,
            observer_client=_OriginObserver(store)):
        result = tool(args)

    assert [note["title"] for note in result["notes"]] == ["Owner"]


def test_expert_reads_are_restricted_to_root_selected_notes(tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    store = prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER, owner_uid=1000))
    _write_fixture(store._root / "Notes" / "Granted.md", "Private granted research.\n")
    _write_fixture(store._root / "Notes" / "Other.md", "Other private note.\n")
    rows = {row.title: row for row in store.list_notes().notes}
    tool = ObsidianNativeTools(store).handler("obsidian_search_notes")
    args = {"query": "private"}
    observed, scope, binding, _permit, dispatch, execution, source, mission, _ = _binding(
        store, "obsidian_search_notes", args, mode="expert_read",
        execution_id="mission_123", source="expert_alpha", mission=_mission(),
        selected=frozenset({rows["Granted"].note_id}))

    with patch("hermes_installer.remote.obsidian_native_tools.current_native_tool_dispatch",
               return_value=dispatch), _admit_current_obsidian_call(
            observed_call=observed, scope=scope, binding=binding):
        assert [row["title"] for row in tool(args)["notes"]] == ["Granted"]

    assert scope.selected_note_ids == frozenset({rows["Granted"].note_id})


def test_private_draft_identity_comes_from_root_context_and_not_arguments(tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    store = prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER, owner_uid=1000))
    tool = ObsidianNativeTools(store).handler("obsidian_create_private_draft")
    args = {"title": "Proposal", "markdown": "# Proposal\nPrivate text.\n"}
    observed, scope, binding, _permit, dispatch, execution, source, mission, selected = _binding(
        store, "obsidian_create_private_draft", args, mode="expert_read",
        execution_id="mission_123", source="expert_alpha", mission=_mission(),
        selected=frozenset())

    with patch("hermes_installer.remote.obsidian_native_tools.current_native_tool_dispatch",
               return_value=dispatch), _admit_current_obsidian_call(
            observed_call=observed, scope=scope, binding=binding,
            observer_client=_OriginObserver(store)):
        result = tool(args)

    assert result["executionId"] == "mission_123"
    assert result["sourceInstanceId"] == "expert_alpha"
    assert store.read_private_draft(execution_id="mission_123",
                                    draft_id=result["draftId"])["markdown"] == args["markdown"]


def test_current_master_reviews_exact_stored_expert_draft_bytes_and_origin(tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    store = prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER, owner_uid=1000))
    source_markdown = "# Expert proposal\nExact stored bytes.\n"
    draft = store.create_private_draft(
        execution_id="expert_session_123", source_instance_id="expert_alpha",
        title="Expert proposal", markdown=source_markdown)
    args = {"draft_id": draft.draft_id, "expected_draft_sha256": draft.content_sha256}
    observed, scope, binding, _permit, dispatch, *_ = _binding(
        store, "obsidian_read_private_draft", args)
    tool = ObsidianNativeTools(store).handler("obsidian_read_private_draft")

    with patch("hermes_installer.remote.obsidian_native_tools.current_native_tool_dispatch",
               return_value=dispatch), _admit_current_obsidian_call(
            observed_call=observed, scope=scope, binding=binding,
            observer_client=_OriginObserver(store)):
        result = tool(args)

    assert result["markdown"] == source_markdown
    assert result["content_sha256"] == draft.content_sha256
    assert result["review_complete"] is True
    assert result["origin"] == {
        "source_id": "expert_alpha", "source_revision": "source-revision",
        "execution_id": "expert_session_123", "mission_sha256": None,
        "source_generation_sha256": "f" * 64,
    }
    assert "vault_path" not in result and "executionId" not in result


def test_expert_cannot_use_master_private_draft_review_tool(tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    store = prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER, owner_uid=1000))
    args = {"draft_id": "D" * 43, "expected_draft_sha256": "e" * 64}
    observed, scope, binding, _permit, dispatch, *_ = _binding(
        store, "obsidian_read_private_draft", args, mode="expert_read",
        execution_id="mission_123", source="expert_alpha", mission=_mission(),
        selected=frozenset())
    with patch("hermes_installer.remote.obsidian_native_tools.current_native_tool_dispatch",
               return_value=dispatch), pytest.raises(
                   ObsidianNativeToolUnavailable, match="does not admit"):
        with _admit_current_obsidian_call(
                observed_call=observed, scope=scope, binding=binding):
            pytest.fail("Expert draft review scope must not be admitted")


def test_private_draft_review_never_claims_complete_for_oversized_content():
    from hermes_installer.remote.obsidian_native_scope import _decode_draft_review

    markdown = "x" * (32 * 1024 + 1)
    issued = time.monotonic()
    delivery = {
        "receipt_id": "R" * 43, "owner_subject_sha256": OWNER,
        "owner_turn_handle": "T" * 43, "draft_id": "D" * 43,
        "content_sha256": hashlib.sha256(markdown.encode()).hexdigest(),
        "origin_record_sha256": "e" * 64, "source_generation_sha256": "f" * 64,
        "startup_binding_id": "G" * 43, "observed_call_handle": "H" * 43,
        "tool_call_id": "read-private-draft", "arguments_sha256": "a" * 64,
        "returned_byte_length": 0,
        "returned_content_sha256": hashlib.sha256(b"").hexdigest(),
        "complete": False, "covered_byte_length": 0,
        "delivered_monotonic": issued, "expires_monotonic": issued + 4,
    }
    delivery["receipt_sha256"] = hashlib.sha256(json.dumps(
        delivery, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False).encode("utf-8")).hexdigest()
    review = _decode_draft_review({
        "schema": 1, "nonce": "fixture", "ok": True,
        "draft_id": "D" * 43, "title": "Large draft", "markdown": None,
        "content_sha256": hashlib.sha256(markdown.encode()).hexdigest(),
        "byte_length": len(markdown.encode()), "review_complete": False,
        "next_step": "Use the owner draft review flow to reduce the draft before Jarvis reviews it.",
        "base_note_id": None, "base_sha256": None,
        "origin_source_id": "expert_alpha", "origin_source_revision": "r17",
        "origin_execution_id": "expert_session_123", "mission_sha256": None,
        "source_generation_sha256": "f" * 64, "origin_record_sha256": "e" * 64,
        "delivery": delivery,
        "issued_monotonic": issued, "expires_monotonic": issued + 4,
    })

    assert review.review_complete is False
    assert review.markdown is None
    assert review.byte_length == 32 * 1024 + 1


@pytest.mark.parametrize("reservation_error", [
    RuntimeError("archive capacity is unavailable"),
    OSError("archive fsync failed before reservation readback"),
])
def test_promotion_reservation_failure_precedes_public_note_write(tmp_path, reservation_error):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    store = prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER, owner_uid=1000))
    draft = store.create_private_draft(
        execution_id="D" * 43, source_instance_id="hermes",
        title="Final", markdown="# Final\nReviewed.\n")
    args = {"draft_id": draft.draft_id, "expected_draft_sha256": draft.content_sha256,
            "destination": "Notes/Final.md", "expected_base_sha256": None,
            "review_disposition": "approve"}
    observer = _OriginObserver(store)
    observer.reservation_error = reservation_error
    tool = ObsidianNativeTools(store).handler("obsidian_promote_reviewed_draft")
    observed, scope, binding, permit, dispatch, *_ = _binding(
        store, "obsidian_promote_reviewed_draft", args, mode="master_effect",
        with_permit=True)

    with patch("hermes_installer.remote.obsidian_native_tools.current_native_tool_dispatch",
               return_value=dispatch), patch(
            "hermes_installer.native_invocations.current_native_tool_dispatch",
            return_value=dispatch), _admit_current_obsidian_call(
            observed_call=observed, scope=scope, binding=binding, permit=permit,
            observer_client=observer):
        with pytest.raises(type(reservation_error), match="archive (capacity|fsync)"):
            tool(args)

    assert not (store._root / "Notes" / "Final.md").exists()
    assert store.read_private_draft(execution_id="D" * 43,
                                    draft_id=draft.draft_id)["state"] == "private-draft"


def test_promotion_requires_master_effect_permit_and_expert_cannot_write_owner_note(tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    store = prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER, owner_uid=1000))
    draft = store.create_private_draft(
        execution_id="D" * 43, source_instance_id="hermes",
        title="Final", markdown="# Final\nReviewed.\n")
    args = {"draft_id": draft.draft_id, "expected_draft_sha256": draft.content_sha256,
            "destination": "Notes/Final.md", "expected_base_sha256": None,
            "review_disposition": "approve"}
    tool = ObsidianNativeTools(store).handler("obsidian_promote_reviewed_draft")
    observed, scope, binding, permit, dispatch, execution, source, mission, selected = _binding(
        store, "obsidian_promote_reviewed_draft", args, mode="master_effect",
        with_permit=True)
    assert permit is not None

    with patch("hermes_installer.remote.obsidian_native_tools.current_native_tool_dispatch",
               return_value=dispatch), \
            patch("hermes_installer.native_invocations.current_native_tool_dispatch",
                  return_value=dispatch), _admit_current_obsidian_call(
            observed_call=observed, scope=scope, binding=binding, permit=permit,
            observer_client=_OriginObserver(store)):
        saved = tool(args)
    assert saved["contentSha256"] == draft.content_sha256
    assert (store._root / "Notes" / "Final.md").read_text(encoding="utf-8") == "# Final\nReviewed.\n"

    expert_observed, expert_scope, expert_binding, _, expert_dispatch, *_ = _binding(
        store, "obsidian_promote_reviewed_draft", args, mode="expert_read",
        execution_id="mission_123", source="expert_alpha", mission=_mission(), selected=frozenset())
    with patch("hermes_installer.remote.obsidian_native_tools.current_native_tool_dispatch",
               return_value=expert_dispatch), pytest.raises(
                   ObsidianNativeToolUnavailable, match="does not admit"):
        with _admit_current_obsidian_call(
                observed_call=expert_observed, scope=expert_scope, binding=expert_binding):
            pytest.fail("Expert promotion scope must not be admitted")
