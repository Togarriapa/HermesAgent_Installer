from __future__ import annotations

from pathlib import Path

import pytest

from hermes_installer.authority.native_worker_start_recipe import (
    ARGV_SUFFIX,
    ENVIRONMENT_BINDING_NAMES,
    LOADER_CHANNEL_FD_NAME,
    LOADER_PHASES,
    NativeWorkerRecipeUnavailable,
    RECIPE_ID,
    _read_source_member,
    audit_pinned_hermes_source,
)
from hermes_installer.hermes_source import VerifiedHermesSource


def _source(root: Path) -> VerifiedHermesSource:
    return VerifiedHermesSource(
        artifact_id="hermes-source-7085fbf7753266fc4943c55ac04926186bc90005",
        archive_sha256="592ac0b09a7130cf2f8166f039098ba4ed40fb91535c601a6a7e5b1fcf889d01",
        archive_size_bytes=80_347_460,
        commit="7085fbf7753266fc4943c55ac04926186bc90005",
        git_tree_sha1="64e4a14da0e2f639a6977f90d6af07d93ea100c3",
        archive_tree_manifest_sha256="d2b2b093616021065671c9206b53f4c60bff3a8e4b52c7c2c56f88f6f5572b15",
        normalization_manifest_sha256="5dfb4361f1ecf96d355a0ce4192cf4d03eeded09e59ec42f00fddd20ffc799b9",
        archive_path=root,
        tree_path=root,
    )


def test_audit_rejects_mismatched_identity_before_source_reads(tmp_path):
    wrong = _source(tmp_path)
    object.__setattr__(wrong, "commit", "0" * 40)
    with pytest.raises(NativeWorkerRecipeUnavailable, match="identity differs"):
        audit_pinned_hermes_source(wrong)


def test_source_member_reader_rejects_symlinked_leaf(tmp_path):
    (tmp_path / "real.py").write_bytes(b"not a Hermes source")
    (tmp_path / "plugin.py").symlink_to("real.py")
    with pytest.raises(NativeWorkerRecipeUnavailable, match="unavailable"):
        _read_source_member(tmp_path, "plugin.py")


def test_recipe_contract_is_the_existing_fixed_cli_and_unix_handshake():
    assert RECIPE_ID == "native-owner-overlay-worker-v1"
    assert ARGV_SUFFIX == ("-m", "hermes_cli.main", "chat", "--query-file", "-", "--oneshot", "--quiet")
    assert LOADER_CHANNEL_FD_NAME == "hermes-loader-progress"
    assert LOADER_PHASES == ("entrypoint-imported", "actions-registered", "ready")
    assert ENVIRONMENT_BINDING_NAMES == (
        "HOME", "HERMES_HOME", "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES",
    )
