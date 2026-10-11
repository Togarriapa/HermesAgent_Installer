"""Immutable recipe identity for installed root-owned cron task qualification.

This file describes bounded fixture semantics only.  It is not a selected
resource, source receipt, publication, process command, or authority record.
"""
from __future__ import annotations

from types import MappingProxyType


RECIPE_ID = "hermes-installed-resource-cron-task-recipe-v1"
SUITE_ID = "resource-cron-task-v1"
SCHEMA_MODULE = "hermes_installer.authority.qualification_resource_cron_schema"
SCHEMA_ID = "hermes-installed-resource-cron-task-schema-v1"
SOURCE_KIND = "schedule-event"
PROCESS_OPERATION_ID = "hermes-resource-profile-task-v1"
EXPECTED_TERMINAL_STATE = "completed"
EXPECTED_CLEANUP_STATE = "clean"

# Only the fixture producer may derive generated resource/profile/principal IDs
# from its private per-run nonce.  No caller-provided authority is in this row.
RECIPE = MappingProxyType({
    "schema": 1,
    "recipe_id": RECIPE_ID,
    "suite_id": SUITE_ID,
    "schema_module": SCHEMA_MODULE,
    "schema_id": SCHEMA_ID,
    "source_kind": SOURCE_KIND,
    "operation_id": PROCESS_OPERATION_ID,
    "expected_terminal_state": EXPECTED_TERMINAL_STATE,
    "expected_cleanup_state": EXPECTED_CLEANUP_STATE,
    "max_prompt_bytes": 256,
    "additional_metered_budget": 0,
})

