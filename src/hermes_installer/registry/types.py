from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping
class ResourceKind(StrEnum):
    PROFILE="profiles"; SKILL="skills"; PLUGIN="plugins"; MCP="mcps"; BUNDLE="bundles"; CHANNEL="channels"; CRON="crons"; WEBHOOK="webhooks"
@dataclass(frozen=True,slots=True)
class Resource:
    id:str; kind:ResourceKind; version:str; body:Mapping[str,Any]; source_revision:str
    requires:tuple[str,...]=(); inherits:tuple[str,...]=(); capabilities:frozenset[str]=frozenset(); digest:str=""
