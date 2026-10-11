"""Truthful channel status projection until a reviewed native read adapter exists."""
from __future__ import annotations

CHANNEL_STATUS_PENDING = (
    "No reviewed native messaging status reader is available; channel configuration and connection state are unknown."
)


def project_channel_status() -> tuple[list[dict], str]:
    """Return no fabricated rows and an explicit source limitation.

    The official dashboard messaging endpoint is a broad management router (including writes and
    connection tests), not an approved narrow Core RPC.  It is intentionally not called here.
    """
    return [], CHANNEL_STATUS_PENDING
