"""Literal feature fragments and their fixed route ownership for Jarvis."""
from __future__ import annotations

import re

from . import jarvis_bots as _bots
from . import jarvis_missions as _missions
from . import jarvis_native_inventory as _native_inventory
from . import jarvis_files as _files
from .jarvis_activity_assets import FEATURE_ASSETS as _ACTIVITY_ASSETS
from .jarvis_bots_ui import FEATURE_ASSETS as _BOTS_ASSETS
from .jarvis_feature_contract import JarvisFeatureAssets
from .jarvis_missions_assets import FEATURE_ASSETS as _MISSION_ASSETS
from .jarvis_native_controls_assets import FEATURE_ASSETS as _NATIVE_CONTROLS_ASSETS
from .jarvis_learning_feature import FEATURE_ASSETS as _LEARNING_ASSETS
from .jarvis_native_inventory_assets import FEATURE_ASSETS as _NATIVE_INVENTORY_ASSETS
from .jarvis_files_assets import FEATURE_ASSETS as _FILES_ASSETS

# Runtime resources are compiled only from these explicit, reviewed modules.
FEATURE_ASSETS: tuple[JarvisFeatureAssets, ...] = (
    _MISSION_ASSETS, _BOTS_ASSETS, _ACTIVITY_ASSETS, _NATIVE_CONTROLS_ASSETS, _LEARNING_ASSETS,
    _NATIVE_INVENTORY_ASSETS,
    _FILES_ASSETS,
)

# New endpoint installers are explicit. Activity is installed exactly once by
# JarvisChatService.install; native settings is installed by the dashboard API.
FEATURE_ROUTE_INSTALLERS = (
    ("missions", _missions.install_jarvis_missions_routes, _missions.FEATURE_ROUTES),
    ("bots", _bots.install_jarvis_bots_routes, _bots.FEATURE_ROUTES),
    ("native-inventory", _native_inventory.install_jarvis_native_inventory_routes,
     _NATIVE_INVENTORY_ASSETS.api_routes),
    ("files", _files.install_jarvis_files_routes, _files.FEATURE_ROUTES),
)
FEATURE_ROUTE_OWNERS = (
    ("activity", "chat-service.install", _ACTIVITY_ASSETS.api_routes),
    ("native-controls", "dashboard", _NATIVE_CONTROLS_ASSETS.api_routes),
    ("resources-learning", "dashboard", _LEARNING_ASSETS.api_routes),
)

# Files may reuse only this fixed authenticated conversation selector.
_SHARED_INSTALLER_READS = {"files": {("GET", "/chat/api/conversations")}}


def _route_shape(route: tuple[str, str]) -> tuple[str, str]:
    method, path = route
    return method, re.sub(r"\{[a-z][a-z0-9_]*\}", "{}", path)


def install_jarvis_feature_routes(app, service) -> None:
    """Install only explicit feature adapters and validate static route ownership."""
    from .jarvis_feature_contract import validate_feature_assets

    validate_feature_assets(FEATURE_ASSETS)
    assets = {feature.feature_id: feature for feature in FEATURE_ASSETS}
    installers = {}
    for entry in FEATURE_ROUTE_INSTALLERS:
        if (not isinstance(entry, tuple) or len(entry) != 3
                or not isinstance(entry[0], str) or not callable(entry[1])
                or not isinstance(entry[2], tuple) or entry[0] in installers):
            raise ValueError("dashboard feature route installer is invalid")
        installers[entry[0]] = (entry[1], entry[2])
    owners = {}
    for entry in FEATURE_ROUTE_OWNERS:
        if (not isinstance(entry, tuple) or len(entry) != 3
                or entry[0] not in {"activity", "native-controls", "resources-learning"}
                or entry[1] not in {"chat-service.install", "dashboard"}
                or not isinstance(entry[2], tuple) or entry[0] in owners):
            raise ValueError("dashboard feature route owner is invalid")
        owners[entry[0]] = (entry[1], entry[2])
    if set(assets) != set(installers) | set(owners) or set(installers) & set(owners):
        raise ValueError("dashboard feature routes and static assets differ")

    all_routes: set[tuple[str, str]] = set()
    for feature_id, asset in assets.items():
        declared = {_route_shape(route) for route in asset.api_routes}
        if len(declared) != len(asset.api_routes) or all_routes & declared:
            raise ValueError("dashboard feature API routes are ambiguous")
        all_routes.update(declared)
        if feature_id in installers:
            installer, routes = installers[feature_id]
            if {_route_shape(route) for route in routes} != declared:
                raise ValueError("dashboard feature asset and installer routes differ")
            registered = {_route_shape((route.method, route.resource.canonical))
                          for route in app.router.routes()}
            if declared & registered != _SHARED_INSTALLER_READS.get(feature_id, set()):
                raise ValueError("feature reused an unreviewed shared route")
        else:
            owner, routes = owners[feature_id]
            if (owner == "chat-service.install") != (feature_id == "activity"):
                raise ValueError("dashboard feature route owner differs")
            if {_route_shape(route) for route in routes} != declared:
                raise ValueError("dashboard feature asset and existing routes differ")
            registered = {_route_shape((route.method, route.resource.canonical))
                          for route in app.router.routes()}
            if not declared.issubset(registered):
                raise ValueError("shared feature routes are not registered exactly")

    registered = {_route_shape((route.method, route.resource.canonical))
                  for route in app.router.routes()}
    for feature_id, (installer, _routes) in installers.items():
        installer(app, service)
    added = {_route_shape((route.method, route.resource.canonical))
             for route in app.router.routes()} - registered
    expected = {_route_shape(route) for _, routes in installers.values() for route in routes} - registered
    if added != expected:
        raise ValueError("feature installer added an unreviewed route")
