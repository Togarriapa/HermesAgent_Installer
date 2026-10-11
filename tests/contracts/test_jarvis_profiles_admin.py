from __future__ import annotations

import hashlib

import pytest

from hermes_installer.remote.jarvis_chat import JarvisChatDenied
from hermes_installer.remote.jarvis_profiles_admin import (
    JarvisProfileAdmin, ProfileAdminDescriptor, ProfileAdminFile,
    ProfileAdminWriteResult, reviewed_profiles_admin_feature,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class _Provider:
    def __init__(self):
        self.files = {("hermes", "soul"): "Jarvis owner prompt\n",
                      ("dev-peter", "soul"): "Internal profile prompt\n"}
        self.generation = "a" * 64
        self.writes = []

    def list_profiles(self, *, subject, core_generation, access_jwt, accepted_ingress):
        return (
            ProfileAdminDescriptor("hermes", "Jarvis", "jarvis", self.generation, ("soul",)),
            ProfileAdminDescriptor("dev-peter", "Dev Peter", "expert", self.generation, ("soul",)),
        )

    def read_file(self, *, subject, core_generation, profile_key, file_kind, access_jwt, accepted_ingress):
        value = self.files[(profile_key, file_kind)]
        return ProfileAdminFile(profile_key, file_kind, "SOUL.md", self.generation,
                                value, _sha(value), True)

    def write_generation(self, *, subject, core_generation, profile_key, file_kind,
                         expected_sha256, content, idempotency_key, access_jwt, accepted_ingress):
        before = self.files[(profile_key, file_kind)]
        if _sha(before) != expected_sha256:
            return ProfileAdminWriteResult("conflict", None, _sha(before), None, False)
        self.files[(profile_key, file_kind)] = content
        self.generation = _sha(self.generation + _sha(content))
        self.writes.append((profile_key, file_kind, idempotency_key))
        return ProfileAdminWriteResult("active", self.generation, _sha(content), "recovery-safe-id-12345", True)


def test_opaque_profile_ids_bind_owner_and_current_core_generation_and_never_expose_paths():
    provider = _Provider()
    admin = JarvisProfileAdmin(provider)
    snapshot = admin.list_profiles(subject="owner-a", core_generation="core-a",
                                   access_jwt="jwt", accepted_ingress=object())
    assert [item["kind"] for item in snapshot["profiles"]] == ["jarvis", "expert"]
    assert all("path" not in item for item in snapshot["profiles"])
    profile_id = snapshot["profiles"][1]["id"]
    with pytest.raises(JarvisChatDenied):
        admin.read_file(subject="owner-b", core_generation="core-a", profile_id=profile_id,
                        file_kind="soul", access_jwt="jwt", accepted_ingress=object())
    with pytest.raises(JarvisChatDenied):
        admin.read_file(subject="owner-a", core_generation="core-b", profile_id=profile_id,
                        file_kind="soul", access_jwt="jwt", accepted_ingress=object())
    with pytest.raises(JarvisChatDenied):
        admin.read_file(subject="owner-a", core_generation="core-a", profile_id="../SOUL.md",
                        file_kind="soul", access_jwt="jwt", accepted_ingress=object())


def test_save_requires_fresh_single_use_review_token_and_exact_file_cas():
    provider = _Provider()
    admin = JarvisProfileAdmin(provider)
    auth = {"subject": "owner-a", "core_generation": "core-a",
            "access_jwt": "jwt", "accepted_ingress": object()}
    profile_id = admin.list_profiles(**auth)["profiles"][0]["id"]
    initial = admin.read_file(**auth, profile_id=profile_id, file_kind="soul")
    proposed = initial["content"] + "Use concise answers.\n"
    preview = admin.preview(**auth, profile_id=profile_id, file_kind="soul",
        base_sha256=initial["sha256"], content=proposed)
    assert "Use concise answers." in preview["diff"]
    saved = admin.save(**auth, profile_id=profile_id, file_kind="soul",
        base_sha256=initial["sha256"], content=proposed,
        preview_token=preview["previewToken"], idempotency_key="idempotency_key_1234567890")
    assert saved["state"] == "active" and saved["effectiveReadback"] is True
    assert len(provider.writes) == 1
    with pytest.raises(JarvisChatDenied):
        admin.save(**auth, profile_id=profile_id, file_kind="soul",
            base_sha256=initial["sha256"], content=proposed,
            preview_token=preview["previewToken"], idempotency_key="idempotency_key_1234567890")


def test_source_race_consumes_preview_without_repeating_the_write():
    provider = _Provider()
    admin = JarvisProfileAdmin(provider)
    auth = {"subject": "owner-a", "core_generation": "core-a",
            "access_jwt": "jwt", "accepted_ingress": object()}
    profile_id = admin.list_profiles(**auth)["profiles"][1]["id"]
    initial = admin.read_file(**auth, profile_id=profile_id, file_kind="soul")
    proposed = initial["content"] + "Changed by owner.\n"
    preview = admin.preview(**auth, profile_id=profile_id, file_kind="soul",
        base_sha256=initial["sha256"], content=proposed)
    provider.files[("dev-peter", "soul")] = "concurrent edit\n"
    result = admin.save(**auth, profile_id=profile_id, file_kind="soul",
        base_sha256=initial["sha256"], content=proposed,
        preview_token=preview["previewToken"], idempotency_key="idempotency_key_1234567891")
    assert result["state"] == "conflict"
    assert provider.writes == []


def test_editor_fragment_uses_fixed_routes_and_never_opens_expert_chat():
    feature = reviewed_profiles_admin_feature()
    assert ("POST", "/chat/api/profiles/{profile_id}/save") in feature.api_routes
    assert "textarea" in feature.view_html and "Review changes" in feature.view_html
    assert "Experts remain internal workers" in feature.view_html
    assert "chat with" not in feature.mount_js.lower()
    assert "localStorage" not in feature.mount_js and "sessionStorage" not in feature.mount_js
