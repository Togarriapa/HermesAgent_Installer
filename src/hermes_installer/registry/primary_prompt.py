"""Pure marker helpers for the explicitly managed primary Jarvis SOUL block."""
from __future__ import annotations


BEGIN_MARKER = b"<!-- HERMES-INSTALLER-MANAGED-JARVIS-PRIMARY v1 BEGIN -->"
END_MARKER = b"<!-- HERMES-INSTALLER-MANAGED-JARVIS-PRIMARY v1 END -->"
OWNER_PRECEDENCE = (
    b"The owner-authored SOUL instructions before this managed block take precedence "
    b"where they conflict. This block does not grant tools, authorization, account access, "
    b"or budget."
)
MAX_SOUL_BYTES = 1024 * 1024


class PrimaryPromptBlockError(ValueError):
    """The SOUL block is ambiguous, edited, or too large to manage safely."""


def render_managed_block(source_prompt: bytes) -> bytes:
    if not isinstance(source_prompt, bytes) or not source_prompt or len(source_prompt) > 64 * 1024:
        raise PrimaryPromptBlockError("bundled primary prompt is missing or oversized")
    if b"\x00" in source_prompt or BEGIN_MARKER in source_prompt or END_MARKER in source_prompt:
        raise PrimaryPromptBlockError("bundled primary prompt contains an invalid marker or NUL")
    try:
        source_prompt.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise PrimaryPromptBlockError("bundled primary prompt is not UTF-8") from None
    body = (BEGIN_MARKER + b"\n" + OWNER_PRECEDENCE + b"\n\n" + source_prompt
            + (b"" if source_prompt.endswith(b"\n") else b"\n")
            + END_MARKER + b"\n")
    if len(body) > MAX_SOUL_BYTES:
        raise PrimaryPromptBlockError("managed primary prompt block exceeds the native SOUL bound")
    return body


def append_managed_block(owner_prefix: bytes, block: bytes) -> tuple[bytes, bytes]:
    if not isinstance(owner_prefix, bytes) or len(owner_prefix) > MAX_SOUL_BYTES:
        raise PrimaryPromptBlockError("owner SOUL prefix is missing or oversized")
    if not isinstance(block, bytes) or block.count(BEGIN_MARKER) != 1 or block.count(END_MARKER) != 1:
        raise PrimaryPromptBlockError("managed primary prompt block is malformed")
    if owner_prefix.count(BEGIN_MARKER) or owner_prefix.count(END_MARKER):
        raise PrimaryPromptBlockError("owner SOUL already contains an ambiguous managed marker")
    separator = b"" if owner_prefix.endswith(b"\n\n") else (b"\n" if owner_prefix.endswith(b"\n") else b"\n\n")
    result = owner_prefix + separator + block
    if len(result) > MAX_SOUL_BYTES:
        raise PrimaryPromptBlockError("combined primary SOUL exceeds the native file bound")
    return result, separator


def split_managed_block(
    current: bytes, *, owner_prefix_length: int, separator: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Return exact prefix, recorded separator and complete EOF block."""
    if not isinstance(current, bytes) or len(current) > MAX_SOUL_BYTES:
        raise PrimaryPromptBlockError("active SOUL is missing or oversized")
    if current.count(BEGIN_MARKER) != 1 or current.count(END_MARKER) != 1:
        raise PrimaryPromptBlockError("active SOUL managed markers are absent or ambiguous")
    start = current.find(BEGIN_MARKER)
    end_marker = current.find(END_MARKER)
    if end_marker <= start or not current.endswith(END_MARKER + b"\n"):
        raise PrimaryPromptBlockError("managed primary block is edited or is not the final SOUL block")
    if (type(owner_prefix_length) is not int or owner_prefix_length < 0
            or separator not in {b"", b"\n", b"\n\n"}
            or owner_prefix_length + len(separator) != start):
        raise PrimaryPromptBlockError("managed primary block prefix receipt is invalid")
    prefix = current[:owner_prefix_length]
    if current[owner_prefix_length:start] != separator:
        raise PrimaryPromptBlockError("managed primary block separator changed")
    if prefix.count(BEGIN_MARKER) or prefix.count(END_MARKER):
        raise PrimaryPromptBlockError("owner prefix contains an ambiguous managed marker")
    block = current[start:end_marker + len(END_MARKER) + 1]
    return prefix, separator, block
