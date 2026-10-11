"""Native-call wrapper contracts for the Obsidian storage leaf.

These tests bind synthetic root receipts only to exercise the wrapper. They do
not prove ROOT's middleware issuance, startup vault binding, or Pi acceptance.
"""
from __future__ import annotations

import hashlib
import time
from unittest.mock import patch

import pytest

from hermes_installer.native_invocations import NativeToolDispatch, canonical_tool_arguments
from hermes_installer.remote.core_native_observer import (
    ObservedNativeToolCall, RootVerifiedMasterReadCall, _MASTER_READ_CALL_SEAL,
)
from hermes_installer.remote.jarvis_final_effects import FinalEffectPermit, review_digest
from hermes_installer.remote.jarvis_mission_executor import MissionBinding
from hermes_installer.remote.obsidian_native_tools import (
    ObsidianNativeToolUnavailable, ObsidianNativeTools, _admit_current_obsidian_call,
)
from hermes_installer.remote.obsidian_second_brain import (
    ObsidianVaultConfig, prepare_obsidian_vault,
)

OWNER = "a" * 64


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
    caller = RootVerifiedMasterReadCall(
        observed_call_handle=observed.handle, owner_turn_handle=observed.owner_turn_handle,
        tool_call_id=observed.tool_call_id, tool_name=name,
        arguments_sha256=digest, source_generation_sha256="f" * 64,
        mode=mode, expires_monotonic=time.monotonic() + 15,
        _seal=_MASTER_READ_CALL_SEAL,
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
    return observed, caller, permit, dispatch, execution_id, source, mission, selected


def _mission():
    return MissionBinding(
        schema=2, mission_id="mission_123", revision=1, plan_sha256="1" * 64,
        task_sha256="2" * 64, source_profile_id="hermes", execution_mode="oneshot",
        autonomy_mode="approval_required", selected_source_ids=("expert_alpha",),
        scope_sha256="3" * 64, authorization_sha256=None,
    )


def test_registers_finite_tools_without_identity_or_path_arguments(tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    store = prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER))
    context = _PluginContext()

    names = ObsidianNativeTools(store).register(context)

    assert set(names) == set(context.tools)
    assert all("additionalProperties" is False for row in context.tools.values())
    for row in context.tools.values():
        assert not {"owner", "owner_subject_sha256", "execution_id", "source_instance_id",
                    "note_scope", "vault_path", "permit"} & set(row["schema"]["properties"])


def test_master_read_uses_exact_current_call_and_fixed_owner_store(tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    store = prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER))
    (store._root / "Notes" / "Owner.md").write_text("# Owner\nCurrent owner note.\n", encoding="utf-8")
    tool = ObsidianNativeTools(store).handler("obsidian_search_notes")
    args = {"query": "Current owner"}
    observed, caller, _permit, dispatch, execution, source, mission, selected = _binding(
        store, "obsidian_search_notes", args)

    with patch("hermes_installer.remote.obsidian_native_tools.current_native_tool_dispatch",
               return_value=dispatch), _admit_current_obsidian_call(
            observed_call=observed, caller=caller, owner_subject_sha256=OWNER,
            execution_id=execution, source_instance_id=source,
            mission_binding=mission, selected_note_ids=selected):
        result = tool(args)

    assert [note["title"] for note in result["notes"]] == ["Owner"]


def test_expert_reads_are_restricted_to_root_selected_notes(tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    store = prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER))
    (store._root / "Notes" / "Granted.md").write_text("Private granted research.\n", encoding="utf-8")
    (store._root / "Notes" / "Other.md").write_text("Other private note.\n", encoding="utf-8")
    rows = {row.title: row for row in store.list_notes().notes}
    tool = ObsidianNativeTools(store).handler("obsidian_search_notes")
    args = {"query": "private"}
    observed, caller, _permit, dispatch, execution, source, mission, _ = _binding(
        store, "obsidian_search_notes", args, mode="expert_read",
        execution_id="mission_123", source="expert_alpha", mission=_mission(),
        selected=frozenset({rows["Granted"].note_id}))

    with patch("hermes_installer.remote.obsidian_native_tools.current_native_tool_dispatch",
               return_value=dispatch), _admit_current_obsidian_call(
            observed_call=observed, caller=caller, owner_subject_sha256=OWNER,
            execution_id=execution, source_instance_id=source,
            mission_binding=mission, selected_note_ids=frozenset({rows["Granted"].note_id})):
        assert [row["title"] for row in tool(args)["notes"]] == ["Granted"]

    with pytest.raises(ObsidianNativeToolUnavailable, match="root-selected notes"):
        with patch("hermes_installer.remote.obsidian_native_tools.current_native_tool_dispatch",
                   return_value=dispatch), _admit_current_obsidian_call(
                observed_call=observed, caller=caller, owner_subject_sha256=OWNER,
                execution_id=execution, source_instance_id=source,
                mission_binding=_mission(), selected_note_ids=None):
            pass


def test_private_draft_identity_comes_from_root_context_and_not_arguments(tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    store = prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER))
    tool = ObsidianNativeTools(store).handler("obsidian_create_private_draft")
    args = {"title": "Proposal", "markdown": "# Proposal\nPrivate text.\n"}
    observed, caller, _permit, dispatch, execution, source, mission, selected = _binding(
        store, "obsidian_create_private_draft", args, mode="expert_read",
        execution_id="mission_123", source="expert_alpha", mission=_mission(),
        selected=frozenset())

    with patch("hermes_installer.remote.obsidian_native_tools.current_native_tool_dispatch",
               return_value=dispatch), _admit_current_obsidian_call(
            observed_call=observed, caller=caller, owner_subject_sha256=OWNER,
            execution_id=execution, source_instance_id=source,
            mission_binding=mission, selected_note_ids=selected):
        result = tool(args)

    assert result["executionId"] == "mission_123"
    assert result["sourceInstanceId"] == "expert_alpha"
    assert store.read_private_draft(execution_id="mission_123",
                                    draft_id=result["draftId"])["markdown"] == args["markdown"]


def test_promotion_requires_master_effect_permit_and_expert_cannot_write_owner_note(tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    store = prepare_obsidian_vault(ObsidianVaultConfig(root, OWNER))
    draft = store.create_private_draft(
        execution_id="D" * 43, source_instance_id="hermes",
        title="Final", markdown="# Final\nReviewed.\n")
    args = {"draft_id": draft.draft_id, "expected_draft_sha256": draft.content_sha256,
            "destination": "Notes/Final.md", "expected_base_sha256": None}
    tool = ObsidianNativeTools(store).handler("obsidian_promote_reviewed_draft")
    observed, caller, permit, dispatch, execution, source, mission, selected = _binding(
        store, "obsidian_promote_reviewed_draft", args, mode="master_effect",
        with_permit=True)
    assert permit is not None

    with patch("hermes_installer.remote.obsidian_native_tools.current_native_tool_dispatch",
               return_value=dispatch), \
            patch("hermes_installer.native_invocations.current_native_tool_dispatch",
                  return_value=dispatch), _admit_current_obsidian_call(
            observed_call=observed, caller=caller, owner_subject_sha256=OWNER,
            execution_id=execution, source_instance_id=source,
            mission_binding=mission, selected_note_ids=selected, permit=permit):
        saved = tool(args)
    assert saved["contentSha256"] == draft.content_sha256
    assert (store._root / "Notes" / "Final.md").read_text(encoding="utf-8") == "# Final\nReviewed.\n"

    expert_observed, expert_caller, _, expert_dispatch, *_ = _binding(
        store, "obsidian_promote_reviewed_draft", args, mode="expert_read",
        execution_id="mission_123", source="expert_alpha", mission=_mission(), selected=frozenset())
    with patch("hermes_installer.remote.obsidian_native_tools.current_native_tool_dispatch",
               return_value=expert_dispatch), pytest.raises(
                   ObsidianNativeToolUnavailable, match="does not admit"):
        _admit_current_obsidian_call(
            observed_call=expert_observed, caller=expert_caller,
            owner_subject_sha256=OWNER, execution_id="mission_123",
            source_instance_id="expert_alpha", mission_binding=_mission(),
            selected_note_ids=frozenset())
