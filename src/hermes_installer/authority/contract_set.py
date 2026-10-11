"""Validation helpers for the current versioned runtime contract set.

The contract-set manifest is committed with the candidate source tree. It
binds the exact stable-path payloads without copying historical planning
trees into current installer releases. Legacy release receipts retain their
separate baseline/amendment readers in the versioned compatibility path.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any


CONTRACT_SET_PATH = "contracts/contract-set-v1.json"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class ContractSetError(ValueError):
    """The current source's contract set is incomplete or changed."""


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractSetError("contract-set manifest has duplicate keys")
        result[key] = value
    return result


def verify_contract_set(raw: bytes,
                        available: Mapping[str, tuple[str, int]]) -> tuple[str, str]:
    """Verify a complete contracts/ inventory against release/source rows.

    Returns the SHA-256 of the exact manifest bytes and a deterministic digest
    of its payload rows. ``available`` must already reflect verified held file
    bytes, not caller-provided path metadata.
    """
    if not isinstance(raw, bytes) or not raw or len(raw) > 4 * 1024 * 1024:
        raise ContractSetError("contract-set manifest exceeds its fixed bound")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError):
        raise ContractSetError("contract-set manifest is malformed") from None
    if (not isinstance(document, dict) or set(document) != {"schema", "files"}
            or type(document["schema"]) is not int or document["schema"] != 1
            or not isinstance(document["files"], list) or not document["files"]):
        raise ContractSetError("contract-set manifest has an unsupported schema")

    expected: dict[str, tuple[str, int]] = {}
    previous = ""
    for row in document["files"]:
        if (not isinstance(row, dict) or set(row) != {"path", "sha256", "size_bytes"}
                or not isinstance(row["path"], str)
                or not row["path"].startswith("contracts/")
                or row["path"] == CONTRACT_SET_PATH
                or ".." in row["path"].split("/")
                or row["path"] <= previous
                or not isinstance(row["sha256"], str) or not _SHA256.fullmatch(row["sha256"])
                or type(row["size_bytes"]) is not int or row["size_bytes"] < 0):
            raise ContractSetError("contract-set manifest row is malformed")
        expected[row["path"]] = (row["sha256"], row["size_bytes"])
        previous = row["path"]

    actual = {path: value for path, value in available.items()
              if path.startswith("contracts/") and path != CONTRACT_SET_PATH}
    if actual != expected:
        raise ContractSetError("available runtime contract files differ from the exact manifest")
    payload_raw = json.dumps(
        {path: {"sha256": digest, "size_bytes": size}
         for path, (digest, size) in sorted(expected.items())},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest(), hashlib.sha256(payload_raw).hexdigest()
