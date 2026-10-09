"""Build the immutable HI08 source-event overlay for the pinned Hermes tree.

The source tree is never edited. Each complete upstream file is hash checked,
then exact reviewed call-site replacements are written to a separate overlay.
The host must mount the resulting overlay read-only and ahead of the pristine
source in the selected PM environment before native provider dispatch is enabled.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path


HERMES_SOURCE_COMMIT = "7085fbf7753266fc4943c55ac04926186bc90005"


_FILES = {
    "agent/chat_completion_helpers.py": {
        "source_sha256": "fbd79987a8257f79de6ed291d398f455456385f828631dd8d9d0e6cea3ba46f2",
        "edits": (
            (
                "    if agent.api_mode == \"codex_responses\":\n"
                "        return agent._run_codex_stream(api_kwargs, client=make_client(\"codex_stream_request\"),\n",
                "    if agent.api_mode == \"codex_responses\":\n"
                "        from hermes_installer.native_boundary import prepare_provider_request\n"
                "        api_kwargs = prepare_provider_request(api_kwargs, purpose=\"native-primary\")\n"
                "        return agent._run_codex_stream(api_kwargs, client=make_client(\"codex_stream_request\"),\n",
                1,
            ),
            (
                "    return request_client.chat.completions.create(**api_kwargs)\n",
                "    from hermes_installer.native_boundary import prepare_provider_request\n"
                "    api_kwargs = prepare_provider_request(api_kwargs, purpose=\"native-primary\")\n"
                "    return request_client.chat.completions.create(**api_kwargs)\n",
                1,
            ),
            (
                "        return request_client.chat.completions.create(**stream_kwargs)\n",
                "        from hermes_installer.native_boundary import prepare_provider_request\n"
                "        stream_kwargs = prepare_provider_request(stream_kwargs, purpose=\"native-primary\")\n"
                "        return request_client.chat.completions.create(**stream_kwargs)\n",
                1,
            ),
            (
                "    event stream; non-streaming an OpenAI-shaped SimpleNamespace.\"\"\"\n"
                "    from agent.bedrock_adapter import (",
                "    event stream; non-streaming an OpenAI-shaped SimpleNamespace.\"\"\"\n"
                "    from hermes_installer.native_boundary import deny_unsupported_provider_mode\n"
                "    deny_unsupported_provider_mode(\"bedrock_converse\")\n"
                "    from agent.bedrock_adapter import (",
                1,
            ),
            (
                "    if agent.api_mode == \"anthropic_messages\":\n"
                "        # Request-local client",
                "    if agent.api_mode == \"anthropic_messages\":\n"
                "        from hermes_installer.native_boundary import deny_unsupported_provider_mode\n"
                "        deny_unsupported_provider_mode(\"anthropic_messages\")\n"
                "        # Request-local client",
                1,
            ),
            (
                "    if agent.provider == \"moa\":\n"
                "        # MoA is a virtual provider",
                "    if agent.provider == \"moa\":\n"
                "        from hermes_installer.native_boundary import deny_unsupported_provider_mode\n"
                "        deny_unsupported_provider_mode(\"moa\")\n"
                "        # MoA is a virtual provider",
                1,
            ),
            (
                "        def _open_anthropic_stream(next_api_kwargs: dict[str, Any]):\n"
                "            final_kwargs = dict(next_api_kwargs)",
                "        def _open_anthropic_stream(next_api_kwargs: dict[str, Any]):\n"
                "            from hermes_installer.native_boundary import deny_unsupported_provider_mode\n"
                "            deny_unsupported_provider_mode(\"anthropic_messages\")\n"
                "            final_kwargs = dict(next_api_kwargs)",
                1,
            ),
        ),
    },
    "agent/auxiliary_client.py": {
        "source_sha256": "cdaf4384374eaa906a51e3060b41aa656f88fff336f44160bd053726ed1dec73",
        "edits": (
            (
                "def _create_with_progress(\n",
                "def _prepare_native_aux_request(kwargs: dict[str, Any]) -> dict[str, Any]:\n"
                "    from hermes_installer.native_boundary import prepare_provider_request\n"
                "    return prepare_provider_request(kwargs, purpose=\"native-auxiliary\")\n"
                "\n\n"
                "def _create_with_progress(\n",
                1,
            ),
            (
                "client.chat.completions.create(**kwargs)",
                "client.chat.completions.create(**_prepare_native_aux_request(kwargs))",
                5,
            ),
            (
                "client.chat.completions.create(**stream_kwargs)",
                "client.chat.completions.create(**_prepare_native_aux_request(stream_kwargs))",
                3,
            ),
            (
                "create = lambda request: client.chat.completions.create(**bypass_chat_sdk_request_transform(request, client))",
                "create = lambda request: client.chat.completions.create(**_prepare_native_aux_request("
                "bypass_chat_sdk_request_transform(request, client)))",
                1,
            ),
            (
                "    kwargs.setdefault(\"max_retries\", 0)\n",
                "    kwargs[\"max_retries\"] = 0\n",
                1,
            ),
            (
                "    async_kwargs.setdefault(\"max_retries\", 0)\n",
                "    async_kwargs[\"max_retries\"] = 0\n",
                1,
            ),
            (
                "client = _VertexOpenAI(api_key=token, base_url=base_url)",
                "client = _VertexOpenAI(api_key=token, base_url=base_url, max_retries=0)",
                1,
            ),
        ),
    },
    "agent/tool_executor.py": {
        "source_sha256": "8b145fbc70936f028f18e59cb7f9c8723fc992a067fe068f06e7f9f876e9c679",
        "edits": (
            (
                "    messages.append(tool_message)\n"
                "    if not _flush_session_db_after_tool_progress(agent, messages, stage=f\"tool result {function_name}\"):",
                "    from hermes_installer.native_boundary import record_tool_result\n"
                "    record_tool_result(messages, tool_message)\n"
                "    messages.append(tool_message)\n"
                "    if not _flush_session_db_after_tool_progress(agent, messages, stage=f\"tool result {function_name}\"):",
                1,
            ),
        ),
    },
}


class NativePatchError(RuntimeError):
    """Pinned upstream source or destination did not match the reviewed patch."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _transform(relative_path: str, original: bytes) -> bytes:
    entry = _FILES.get(relative_path)
    if entry is None:
        raise NativePatchError("file is not in the reviewed Hermes overlay")
    if _sha256(original) != entry["source_sha256"]:
        raise NativePatchError(f"pinned Hermes source changed: {relative_path}")
    try:
        text = original.decode("utf-8")
    except UnicodeError:
        raise NativePatchError(f"pinned Hermes source is not UTF-8: {relative_path}") from None
    for before, after, count in entry["edits"]:
        actual = text.count(before)
        if actual != count:
            raise NativePatchError(f"pinned Hermes patch anchor mismatch: {relative_path}")
        text = text.replace(before, after)
    return text.encode("utf-8")


def _ensure_overlay_parent(overlay: Path, relative_path: str, *, create: bool) -> Path:
    """Walk beneath the output root without following attacker-controlled links."""
    parent = overlay
    for segment in Path(relative_path).parts[:-1]:
        parent = parent / segment
        if parent.is_symlink():
            raise NativePatchError(f"native overlay contains a symbolic link: {relative_path}")
        if parent.exists():
            if not parent.is_dir():
                raise NativePatchError(f"native overlay parent is not a directory: {relative_path}")
        elif create:
            parent.mkdir(mode=0o755)
        else:
            raise NativePatchError(f"native overlay parent is unavailable: {relative_path}")
    resolved = parent.resolve(strict=True) if parent.exists() else parent
    if resolved != overlay and overlay not in resolved.parents:
        raise NativePatchError("native overlay path escaped its root")
    return parent


def apply_native_boundary_overlay(source_root: Path, overlay_root: Path) -> dict[str, str]:
    """Create/verify the three-file HI08 overlay without modifying upstream files."""
    source = Path(source_root).resolve(strict=True)
    overlay = Path(overlay_root).resolve(strict=False)
    if source == overlay or source in overlay.parents:
        raise NativePatchError("native source overlay must be outside the pristine source tree")
    if not source.is_dir() or not overlay.is_absolute():
        raise NativePatchError("native source or overlay root is invalid")

    prepared: dict[str, tuple[bytes, bytes, int]] = {}
    for relative_path in _FILES:
        original_path = source / relative_path
        try:
            original = original_path.read_bytes()
            mode = original_path.stat(follow_symlinks=False).st_mode
        except OSError:
            raise NativePatchError(f"pinned Hermes file is unavailable: {relative_path}") from None
        patched = _transform(relative_path, original)
        prepared[relative_path] = (original, patched, mode)

    overlay.mkdir(parents=True, exist_ok=True, mode=0o755)
    overlay = overlay.resolve(strict=True)
    results: dict[str, str] = {}
    for relative_path, (_original, patched, source_mode) in prepared.items():
        target = overlay / relative_path
        _ensure_overlay_parent(overlay, relative_path, create=True)
        if target.is_symlink():
            raise NativePatchError(f"native overlay target is a symbolic link: {relative_path}")
        if target.exists():
            try:
                existing = target.read_bytes()
            except OSError:
                raise NativePatchError(f"native overlay target is unreadable: {relative_path}") from None
            if existing != patched:
                raise NativePatchError(f"native overlay target has unreviewed bytes: {relative_path}")
            os.chmod(target, (target.stat(follow_symlinks=False).st_mode & 0o555) or 0o444)
        else:
            fd, temporary_name = tempfile.mkstemp(prefix=".native-boundary-", dir=target.parent)
            temporary = Path(temporary_name)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(patched)
                    stream.flush()
                    os.fsync(stream.fileno())
                mode = source_mode & 0o555
                os.chmod(temporary, mode or 0o444)
                os.replace(temporary, target)
            finally:
                if temporary.exists():
                    temporary.unlink()
        results[relative_path] = _sha256(patched)
    return results


def verify_native_boundary_overlay(source_root: Path, overlay_root: Path) -> dict[str, str]:
    """Verify the output overlay against current exact-pin source and patch bytes."""
    source = Path(source_root).resolve(strict=True)
    overlay = Path(overlay_root).resolve(strict=True)
    results: dict[str, str] = {}
    for relative_path in _FILES:
        expected = _transform(relative_path, (source / relative_path).read_bytes())
        target = overlay / relative_path
        _ensure_overlay_parent(overlay, relative_path, create=False)
        if target.is_symlink():
            raise NativePatchError(f"native overlay target is a symbolic link: {relative_path}")
        try:
            actual = target.read_bytes()
        except OSError:
            raise NativePatchError(f"native overlay file is unavailable: {relative_path}") from None
        if actual != expected:
            raise NativePatchError(f"native overlay digest mismatch: {relative_path}")
        if target.stat(follow_symlinks=False).st_mode & 0o222:
            raise NativePatchError(f"native overlay file is writable: {relative_path}")
        results[relative_path] = _sha256(expected)
    return results
