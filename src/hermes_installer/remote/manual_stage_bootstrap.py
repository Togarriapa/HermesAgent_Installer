"""Fixed root-only startup refresh for the separate Jarvis manual stage.

This module only refreshes the one boot identity field and restores one exact
owned nftables table. It is not a general firewall or service-management API.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import time
from pathlib import Path
from typing import Any

from .manual_stage import ManualGatewayStageConfig, STAGE_CONFIG, _unique_json_pairs
from .manual_stage_inspector import (
    MAX_OUTPUT, TABLE_FAMILY, TABLE_NAME, StageInspectionDenied,
    _run_fixed, _validate_nft,
)

NFT = "/usr/sbin/nft"
GATEWAY_UID, GATEWAY_GID = 996, 981
XPRA_UID = 1000
CONFIG_DIRECTORY_MODE = 0o755
CONFIG_MODE = 0o440
MAX_CONFIG_BYTES = 16_384
NFT_CREATE_BATCH = f'''add table inet hermes_jarvis_mvp
add chain inet hermes_jarvis_mvp output {{ type filter hook output priority -10; policy accept; }}
add rule inet hermes_jarvis_mvp output ip daddr 127.0.0.1 tcp dport 14500 meta skuid != {GATEWAY_UID} reject with tcp reset comment "Jarvis MVP display gateway only"
'''.encode("ascii")


def _boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not re.fullmatch(r"[0-9a-f-]{36}", value):
        raise StageInspectionDenied("current kernel boot identity is malformed")
    return value


def _config_document(config: ManualGatewayStageConfig) -> tuple[dict[str, Any], os.stat_result, bytes]:
    """Reopen the fixed config and bind parsed content to its validated receipt."""
    directory = STAGE_CONFIG.parent
    parent = os.lstat(directory)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_gid != 0
            or stat.S_IMODE(parent.st_mode) != CONFIG_DIRECTORY_MODE):
        raise StageInspectionDenied("manual-stage config directory ownership differs")
    fd = os.open(STAGE_CONFIG, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or mode not in {0o400, 0o440, 0o600}
                or (mode == 0o440 and info.st_gid != GATEWAY_GID)
                or info.st_size > MAX_CONFIG_BYTES):
            raise StageInspectionDenied("manual-stage config is not a protected root-owned file")
        data = bytearray()
        while len(data) <= MAX_CONFIG_BYTES:
            chunk = os.read(fd, min(4096, MAX_CONFIG_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(fd)
    raw = bytes(data)
    if not raw or len(raw) > MAX_CONFIG_BYTES or hashlib.sha256(raw).hexdigest() != config.config_sha256:
        raise StageInspectionDenied("manual-stage config changed during boot refresh")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_json_pairs)
    except Exception:
        raise StageInspectionDenied("manual-stage config is malformed") from None
    if (not isinstance(value, dict) or value.get("schema") != 2
            or value.get("hostname") != "jarvis.togarriapahome.uk"
            or value.get("gateway_uid") != GATEWAY_UID
            or value.get("gateway_gid") != GATEWAY_GID
            or value.get("xpra_uid") != XPRA_UID):
        raise StageInspectionDenied("manual-stage config is outside the fixed owned deployment")
    return value, info, raw


def _replace_boot_id(raw: bytes, boot_id: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f-]{36}", boot_id):
        raise StageInspectionDenied("new kernel boot identity is malformed")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_json_pairs)
        if (not isinstance(value, dict) or value.get("schema") != 2
                or "boot_id" not in value):
            raise ValueError
        value["boot_id"] = boot_id
        return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                           separators=(",", ":")) + "\n").encode("ascii")
    except Exception:
        raise StageInspectionDenied("manual-stage config cannot be refreshed") from None


def _atomic_refresh_config(config: ManualGatewayStageConfig, boot_id: str) -> str:
    """Replace only boot_id; keep the protected config readable only by root/Gateway."""
    from .manual_stage import _read_config_current

    _read_config_current(config)
    _value, original_info, raw = _config_document(config)
    updated = _replace_boot_id(raw, boot_id)
    if len(updated) > MAX_CONFIG_BYTES:
        raise StageInspectionDenied("refreshed manual-stage config exceeds its bound")
    parent_fd = os.open(STAGE_CONFIG.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                        getattr(os, "O_NOFOLLOW", 0))
    temp_name = f".gateway-stage-boot-{secrets.token_hex(16)}"
    temp_fd = -1
    try:
        temp_fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                          getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                          0o600, dir_fd=parent_fd)
        offset = 0
        while offset < len(updated):
            written = os.write(temp_fd, updated[offset:])
            if written <= 0:
                raise StageInspectionDenied("manual-stage config write was incomplete")
            offset += written
        os.fchown(temp_fd, 0, GATEWAY_GID)
        os.fchmod(temp_fd, CONFIG_MODE)
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = -1
        # Refuse to replace a changed entry, including a symlink swap.
        current = os.stat(STAGE_CONFIG.name, dir_fd=parent_fd, follow_symlinks=False)
        if ((current.st_dev, current.st_ino) != (original_info.st_dev, original_info.st_ino)
                or not stat.S_ISREG(current.st_mode) or current.st_uid != 0
                or current.st_gid != original_info.st_gid
                or stat.S_IMODE(current.st_mode) != stat.S_IMODE(original_info.st_mode)):
            raise StageInspectionDenied("manual-stage config entry changed during refresh")
        check_fd = os.open(STAGE_CONFIG.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        try:
            digest = hashlib.sha256()
            while True:
                part = os.read(check_fd, 8192)
                if not part:
                    break
                digest.update(part)
            if digest.hexdigest() != config.config_sha256:
                raise StageInspectionDenied("manual-stage config changed during refresh")
        finally:
            os.close(check_fd)
        os.replace(temp_name, STAGE_CONFIG.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except Exception:
        try:
            os.unlink(temp_name, dir_fd=parent_fd)
        except OSError:
            pass
        raise
    finally:
        if temp_fd >= 0:
            os.close(temp_fd)
        os.close(parent_fd)
    return hashlib.sha256(updated).hexdigest()


def _parse_tables(raw: bytes) -> set[tuple[str, str]]:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_json_pairs)
        if not isinstance(value, dict) or set(value) != {"nftables"} or not isinstance(value["nftables"], list):
            raise ValueError
        found = set()
        for row in value["nftables"]:
            if "metainfo" in row:
                if set(row) != {"metainfo"}:
                    raise ValueError
                continue
            if set(row) != {"table"}:
                raise ValueError
            table = row["table"]
            if set(table) - {"family", "name", "handle"}:
                raise ValueError
            family, name = table.get("family"), table.get("name")
            if not isinstance(family, str) or not isinstance(name, str):
                raise ValueError
            found.add((family, name))
        return found
    except Exception:
        raise StageInspectionDenied("nftables table inventory is malformed") from None


def _apply_nft_creation_batch() -> None:
    proc = subprocess.Popen((NFT, "-f", "-"), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                            "LANG": "C", "LC_ALL": "C"}, close_fds=True)
    try:
        stdout, stderr = proc.communicate(NFT_CREATE_BATCH, timeout=3)
    except Exception:
        proc.kill()
        proc.communicate()
        raise StageInspectionDenied("fixed manual-stage nftables transaction failed") from None
    if proc.returncode != 0 or len(stdout) > 4096 or len(stderr) > 4096:
        raise StageInspectionDenied("fixed manual-stage nftables transaction failed")


def ensure_owned_nft_rule() -> bytes:
    """Keep all foreign tables untouched; create only our exact absent table."""
    deadline = time.monotonic() + 3
    inventory = _run_fixed((NFT, "-j", "-n", "list", "tables"), deadline=deadline,
                           maximum=MAX_OUTPUT)
    owned = (TABLE_FAMILY, TABLE_NAME)
    present = owned in _parse_tables(inventory)
    if present:
        table = _run_fixed((NFT, "-j", "-n", "list", "table", *owned),
                           deadline=deadline, maximum=MAX_OUTPUT)
        _validate_nft(table, GATEWAY_UID)
        return table
    _apply_nft_creation_batch()
    table = _run_fixed((NFT, "-j", "-n", "list", "table", *owned),
                       deadline=time.monotonic() + 3, maximum=MAX_OUTPUT)
    _validate_nft(table, GATEWAY_UID)
    return table


def refresh_manual_stage_boot_state() -> None:
    if os.geteuid() != 0:
        raise StageInspectionDenied("manual-stage boot refresh must run as root")
    # This narrowly permits reading an otherwise fully validated config whose
    # only stale field is boot_id; the gateway/inspector parsers stay strict.
    config = ManualGatewayStageConfig.load(allow_stale_boot_id=True)
    boot_id = _boot_id()
    _atomic_refresh_config(config, boot_id)
    ensure_owned_nft_rule()
    refreshed = ManualGatewayStageConfig.load()
    if refreshed.boot_id != boot_id:
        raise StageInspectionDenied("manual-stage boot identity did not become current")


def main() -> None:
    import argparse
    argparse.ArgumentParser(description="fixed root-only Jarvis stage boot refresh").parse_args()
    refresh_manual_stage_boot_state()


if __name__ == "__main__":
    main()
