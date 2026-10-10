from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from hermes_installer.authority.native_schema_derivation import (
    NativeSchemaDerivationDenied,
    RootNativeSchemaArtifactReceipt,
    _MODULE_PINS,
    _MODULE_SIZES,
    _NativeSchemaContentStore,
)


def test_schema_child_cas_writes_once_and_revalidates_owned_inode(tmp_path):
    store = _NativeSchemaContentStore(tmp_path)
    content = b'{"additionalProperties":false,"type":"object"}'
    digest = hashlib.sha256(content).hexdigest()

    stored = store.put(content, digest)
    path = tmp_path / "native-action-schema-cas" / stored.relative_path
    info = path.stat()
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_uid == os.geteuid()
    assert (info.st_dev, info.st_ino) == (stored.device, stored.inode)
    assert store.read(stored.relative_path, stored.device, stored.inode,
                      digest, len(content)) == content

    # Content-addressed writes are idempotent and preserve the physical object.
    again = store.put(content, digest)
    assert (again.device, again.inode) == (stored.device, stored.inode)

    path.write_bytes(b'{"type":"string"}')
    with pytest.raises(NativeSchemaDerivationDenied, match="permissions changed|bytes differ"):
        store.read(stored.relative_path, stored.device, stored.inode,
                   digest, len(content))


def test_schema_receipt_type_rejects_caller_minted_proof():
    fields = {name: "x" for name in RootNativeSchemaArtifactReceipt.__dataclass_fields__
              if name != "_seal"}
    with pytest.raises(TypeError, match="root schema registry"):
        RootNativeSchemaArtifactReceipt(**fields, _seal=object())


def test_five_reviewed_schema_module_sources_match_exact_path_hash_and_size_pins():
    for relative_path, expected_sha256 in _MODULE_PINS:
        content = Path(relative_path).read_bytes()
        assert len(content) == _MODULE_SIZES[relative_path]
        assert hashlib.sha256(content).hexdigest() == expected_sha256
