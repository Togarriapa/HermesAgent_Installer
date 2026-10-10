from __future__ import annotations

import hashlib

import pytest

from hermes_installer.authority.public_web_selection import (
    PublicWebSelectionDenied,
    RootTTYPublicInputDisclosure,
    canonical_scope_payload,
)


def _valid_scope() -> dict[str, object]:
    return {
        "enrollment_id": "scope-0123456789abcdef0123456789abcdef",
        "target_id": "plugin-web-public-read",
        "generation": "profile-generation-1",
        "principal_id": "principal-1",
        "profile_id": "profile-1",
        "recipient": "public-web",
        "targets": [{
            "hostname": "docs.example.org",
            "path_prefixes": ["/manual"],
            "query_keys": ["language"],
        }],
        "request_bytes_limit": 4096,
        "response_bytes_limit": 8192,
        "deadline_seconds": 5,
    }


def test_scope_payload_is_canonical_v142_and_returns_exact_digest() -> None:
    value = _valid_scope()

    raw, digest = canonical_scope_payload(value)

    assert raw == (
        b'{"deadline_seconds":5,"enrollment_id":"scope-0123456789abcdef0123456789abcdef",'
        b'"generation":"profile-generation-1","principal_id":"principal-1",'
        b'"profile_id":"profile-1","recipient":"public-web",'
        b'"request_bytes_limit":4096,"response_bytes_limit":8192,"target_id":"plugin-web-public-read",'
        b'"targets":[{"hostname":"docs.example.org","path_prefixes":["/manual"],'
        b'"query_keys":["language"]}]}'
    )
    assert digest == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("mutate", [
    lambda row: {**row, "extra": "unreviewed"},
    lambda row: {**row, "request_bytes_limit": True},
    lambda row: {**row, "targets": [{"hostname": "127.0.0.1", "path_prefixes": ["/"], "query_keys": []}]},
    lambda row: {**row, "targets": [{"hostname": "docs.example.org", "path_prefixes": ["/../private"], "query_keys": []}]},
    lambda row: {**row, "targets": [{"hostname": "docs.example.org", "path_prefixes": ["/manual"], "query_keys": ["access_token"]}]},
    lambda row: {**row, "recipient": "paid-provider"},
])
def test_scope_payload_rejects_open_schema_or_unsafe_scope(mutate) -> None:
    with pytest.raises(PublicWebSelectionDenied):
        canonical_scope_payload(mutate(_valid_scope()))


def test_disclosure_dto_cannot_be_forged_from_caller_fields() -> None:
    with pytest.raises(TypeError, match="issued by the root TTY"):
        RootTTYPublicInputDisclosure(
            disclosure_observation_handle="d" * 64,
            disclosure_sha256="0" * 64,
            retained_observed_input_handle="r" * 32,
            input_sha256="1" * 64,
            input_size_bytes=4,
            public_permission_selection_handle="p" * 32,
            selected_execution_handle="e" * 32,
            tty_controller_observation_handle="tty-" + "a" * 64,
            issued_monotonic=1.0,
            expires_monotonic=2.0,
            one_use_nonce="n" * 64,
            _issuer_token=object(),
        )
