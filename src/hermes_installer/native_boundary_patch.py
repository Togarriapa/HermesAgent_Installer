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
    # The installer writes a separate overlay, while the PM runtime imports
    # Hermes as two regular Python packages.  Put a hash-pinned path extender
    # in each package initializer so the overlay's patched leaf modules win
    # and unpatched modules continue to resolve from the selected source tree.
    "hermes_cli/__init__.py": {
        "source_sha256": "6a4ab05b8621ec1cd66a5abbe30fa32ed5bddddea95903036da01f0af1af94ce",
        "edits": ((
            "_stdio_repaired = _ensure_utf8()\n",
            "_stdio_repaired = _ensure_utf8()\n\n"
            "# Installer-owned overlay support: keep the pristine selected Hermes\n"
            "# package on the extended path while allowing reviewed leaf overrides.\n"
            "from pkgutil import extend_path as _extend_path\n"
            "__path__ = _extend_path(__path__, __name__)\n",
            1,
        ),),
    },
    "agent/__init__.py": {
        "source_sha256": "21cdce89e9ffdb847634bf498b087410cd191a1e375db43928735846fb7ddc86",
        "edits": ((
            "from . import jiter_preload as _jiter_preload\n",
            "# Permit exact reviewed installer leaf overrides from the separate overlay.\n"
            "from pkgutil import extend_path as _extend_path\n"
            "__path__ = _extend_path(__path__, __name__)\n"
            "from . import jiter_preload as _jiter_preload\n",
            1,
        ),),
    },
    "tools/__init__.py": {
        "source_sha256": "7bca460f476ac9ace706c8cfd07e98f8aae34d839862f0f68abafc3a8397cf35",
        "edits": ((
            "\n\n\ndef check_file_requirements():\n",
            "\n\n# Allow only the hash-pinned installer leaf overlay to precede this pristine package.\n"
            "from pkgutil import extend_path as _extend_path\n"
            "__path__ = _extend_path(__path__, __name__)\n"
            "\n\ndef check_file_requirements():\n",
            1,
        ),),
    },
    "hermes_cli/plugins.py": {
        "source_sha256": "a618a69581355e5fe56cb3d2250fc02647315359aae7fa0e6bd4dccc4ed3d3ad",
        "edits": (
            (
                "        manifests: list[PluginManifest] = self._collect_directory_manifests()\n",
                "        manifests: list[PluginManifest] = self._collect_directory_manifests()\n"
                "        from hermes_installer.native_plugin_loader import install_selected_native_plugins\n"
                "        try:\n"
                "            manifests = install_selected_native_plugins(self, manifests)\n"
                "        except Exception:\n"
                "            logger.warning(\"Root-selected native plugins are unavailable; skipping this cohort\")\n",
                1,
            ),
            (
                "        self._notify_plugin_loaded(loaded_before)\n",
                "        self._notify_plugin_loaded(loaded_before)\n"
                "        from hermes_installer.native_plugin_loader import finish_selected_native_plugin_discovery\n"
                "        finish_selected_native_plugin_discovery(self)\n",
                1,
            ),
        ),
    },
    "hermes_cli/main.py": {
        "source_sha256": "a6293934e0ef99849d7a2f3c040256c2466f6fc0382b876bf750f8bd8e6cb912",
        "edits": ((
            "        if _qfile == \"-\":\n"
            "            args.query = sys.stdin.read()\n",
            "        if _qfile == \"-\":\n"
            "            try:\n"
            "                from hermes_installer.native_invocations import read_selected_native_input\n"
            "                args.query = read_selected_native_input(sys.stdin.buffer)\n"
            "            except Exception:\n"
            "                print(\"Error: --query-file stdin did not match the selected root input\", file=sys.stderr)\n"
            "                sys.exit(2)\n",
            1,
        ),),
    },
    "tools/mcp_tool_registration.py": {
        "source_sha256": "7e73a415283c5255fedeb9318fceeb556eb31a19cea2e9bd3d9fdfc0f9297ade",
        "edits": ((
            "    ``_server_tool_scopes`` records the registering scope (default: this scope's own).\"\"\"\n"
            "    from tools.registry import registry\n",
            "    ``_server_tool_scopes`` records the registering scope (default: this scope's own).\"\"\"\n"
            "    from hermes_installer.native_plugin_loader import filter_unselected_native_mcp_candidates\n"
            "    candidates = filter_unselected_native_mcp_candidates(name, candidates)\n"
            "    if not candidates:\n"
            "        return []\n"
            "    from tools.registry import registry\n",
            1,
        ),),
    },
    "tools/mcp_tool_discovery.py": {
        "source_sha256": "cf2dc204fd293727e0e13a045428152f8e1925aa48ea521f6ec97035dd1e86d9",
        "edits": ((
            "    each); it only affects which servers start, not which names ``-t`` validation can see.\"\"\"\n"
            "    with _owner_secret_scope():",
            "    each); it only affects which servers start, not which names ``-t`` validation can see.\"\"\"\n"
            "    from hermes_installer.native_plugin_loader import prepare_native_mcp_candidate_discovery\n"
            "    # The installer profile has no worker-configured MCP authority.\n"
            "    # Return only candidates installed from the sealed root index;\n"
            "    # do not connect mcp_servers or load schema-cache handlers.\n"
            "    return list(prepare_native_mcp_candidate_discovery())\n"
            "    with _owner_secret_scope():",
            1,
        ),),
    },
    "agent/turn_facade.py": {
        "source_sha256": "e9176a8ae1d7822fa45c75b680d5ae4be7c949e49c877673aea867cc146856a0",
        "edits": (
            (
                "            if task_started:\n"
                "                task_finished = True\n"
                "                finish_task_run(**task_context, result=result)\n"
                "            return result\n",
                "            if task_started:\n"
                "                task_finished = True\n"
                "                finish_task_run(**task_context, result=result)\n"
                "            from hermes_installer.native_invocations import finish_selected_native_turn\n"
                "            finish_selected_native_turn(self, result)\n"
                "            return result\n",
                1,
            ),
            (
                "                    with suppress(Exception):\n"
                "                        _review_queue.note_turn_finished()\n",
                "                    with suppress(Exception):\n"
                "                        _review_queue.note_turn_finished()\n"
                "                    with suppress(Exception):\n"
                "                        from hermes_installer.native_invocations import clear_native_turn_scope\n"
                "                        clear_native_turn_scope()\n",
                1,
            ),
        ),
    },
    "agent/chat_completion_helpers.py": {
        "source_sha256": "fbd79987a8257f79de6ed291d398f455456385f828631dd8d9d0e6cea3ba46f2",
        "edits": (
            (
                "    if agent.api_mode == \"codex_responses\":\n"
                "        return agent._run_codex_stream(api_kwargs, client=make_client(\"codex_stream_request\"),\n",
                "    if agent.api_mode == \"codex_responses\":\n"
                "        from hermes_installer.native_invocations import prepare_native_provider_request\n"
                "        api_kwargs = prepare_native_provider_request(api_kwargs, purpose=\"native-primary\")\n"
                "        return agent._run_codex_stream(api_kwargs, client=make_client(\"codex_stream_request\"),\n",
                1,
            ),
            (
                "    return request_client.chat.completions.create(**api_kwargs)\n",
                "    from hermes_installer.native_invocations import prepare_native_provider_request\n"
                "    api_kwargs = prepare_native_provider_request(api_kwargs, purpose=\"native-primary\")\n"
                "    from hermes_installer.native_boundary import take_prepared_native_request_handle\n"
                "    native_request_handle = take_prepared_native_request_handle()\n"
                "    response = request_client.chat.completions.with_raw_response.create(**api_kwargs)\n"
                "    from hermes_installer.native_invocations import install_provider_response_tool_calls\n"
                "    install_provider_response_tool_calls(agent, response, native_request_handle)\n"
                "    return response.parse()\n",
                1,
            ),
            (
                "        for chunk in _iter_provider_stream_chunks(stream, response=lambda: self._attempt_stream_response):\n"
                "            self._count_chunk(_diag, chunk)\n",
                "        for chunk in _iter_provider_stream_chunks(stream, response=lambda: self._attempt_stream_response):\n"
                "            self._count_chunk(_diag, chunk)\n",
                1,
            ),
            (
                "        return request_client.chat.completions.create(**stream_kwargs)\n",
                "        from hermes_installer.native_invocations import prepare_native_provider_request\n"
                "        stream_kwargs = prepare_native_provider_request(stream_kwargs, purpose=\"native-primary\")\n"
                "        from hermes_installer.native_boundary import take_prepared_native_request_handle\n"
                "        native_request_handle = take_prepared_native_request_handle()\n"
                "        stream = request_client.chat.completions.create(**stream_kwargs)\n"
                "        from hermes_installer.native_invocations import attach_provider_stream_capture\n"
                "        attach_provider_stream_capture(stream, native_request_handle)\n"
                "        return stream\n",
                1,
            ),
            (
                "        if stream.final_response is not None:\n"
                "            return self._adopt_final_response(stream.final_response)\n",
                "        if stream.final_response is not None:\n"
                "            return self._adopt_final_response(stream.final_response)\n"
                "        if finish_reason is not None and not runaway:\n"
                "            from hermes_installer.native_invocations import finish_provider_stream_response\n"
                "            finish_provider_stream_response(self.agent, stream)\n",
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
                "    from hermes_installer.native_invocations import prepare_native_provider_request\n"
                "    return prepare_native_provider_request(kwargs, purpose=\"native-auxiliary\")\n"
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
                "    messages.append(tool_message)\n"
                "    from hermes_installer.native_invocations import record_native_tool_result\n"
                "    record_native_tool_result(agent, messages, tool_message, function_result)\n"
                "    if not _flush_session_db_after_tool_progress(agent, messages, stage=f\"tool result {function_name}\"):",
                1,
            ),
            (
                "    _advance_start_order(lambda: _begin_tool_execution(agent, ref, display_index))\n"
                "    return _run_with_activity_heartbeat(agent, ref.name, lambda: execute(ref.args))\n",
                "    _advance_start_order(lambda: _begin_tool_execution(agent, ref, display_index))\n"
                "    def _invoke_observed_tool_call():\n"
                "        from hermes_installer.native_invocations import dispatch_observed_tool_call\n"
                "        return dispatch_observed_tool_call(\n"
                "            agent, tool_call_id=ref.call_id, tool_name=ref.name, arguments=ref.args,\n"
                "            execute=lambda: execute(ref.args),\n"
                "        )\n"
                "    return _run_with_activity_heartbeat(agent, ref.name, _invoke_observed_tool_call)\n",
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
    """Create/verify the reviewed HI08 provider, tool, and native plugin overlay."""
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
