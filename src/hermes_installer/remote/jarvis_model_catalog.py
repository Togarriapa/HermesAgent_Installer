"""Pinned, finite Codex subscription model choices from Hermes' source catalog."""
from __future__ import annotations

CODEX_PROVIDER_ID = "openai-codex"
CODEX_MODEL_SOURCE_REVISION = "7085fbf7753266fc4943c55ac04926186bc90005"
CODEX_MODEL_SOURCE_PATH = "hermes_cli/codex_models.py"
CODEX_MODEL_SOURCE_SHA256 = "701e5aa665fac59c17e31aa33bef9bf225fef128ddf5b6cbf8419282f861b217"

# Exact DEFAULT_CODEX_MODELS from the pinned source. The Spark research preview is
# account-gated and remains visible as pending metadata, but cannot be selected until
# a source-proven account entitlement check exists.
CODEX_SELECTABLE_MODELS: tuple[str, ...] = (
    "gpt-6-sol",
    "gpt-6-luna",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "gpt-5.6-luna",
    "gpt-5.5",
    "gpt-5.4-mini",
    "gpt-5.4",
)
CODEX_ACCOUNT_GATED_MODEL = "gpt-5.3-codex-spark"
CODEX_KNOWN_MODELS: tuple[str, ...] = CODEX_SELECTABLE_MODELS + (CODEX_ACCOUNT_GATED_MODEL,)
CODEX_MODEL_ID_SET = frozenset(CODEX_SELECTABLE_MODELS)
CODEX_KNOWN_MODEL_ID_SET = frozenset(CODEX_KNOWN_MODELS)
