"""Literal feature fragments and their fixed route ownership for Jarvis."""
from __future__ import annotations

import re

from . import jarvis_bots as _bots
from . import jarvis_missions as _missions
from . import jarvis_native_inventory as _native_inventory
from . import jarvis_files as _files
from . import jarvis_models as _models
from . import jarvis_context as _context
from . import jarvis_obsidian_vault as _obsidian
from . import jarvis_extensions_admin as _extensions
from .jarvis_runtime_visibility_assets import FEATURE_ASSETS as _ACTIVITY_ASSETS
from .jarvis_bots_ui import FEATURE_ASSETS as _BOTS_ASSETS
from .jarvis_feature_contract import JarvisFeatureAssets
from .jarvis_missions_assets import FEATURE_ASSETS as _MISSION_ASSETS
from .jarvis_native_controls_assets import FEATURE_ASSETS as _NATIVE_CONTROLS_ASSETS
from .jarvis_learning_feature import FEATURE_ASSETS as _LEARNING_ASSETS
from .jarvis_native_inventory_assets import FEATURE_ASSETS as _NATIVE_INVENTORY_ASSETS
from .jarvis_files_assets import FEATURE_ASSETS as _FILES_ASSETS
from .jarvis_models_assets import FEATURE_ASSETS as _MODELS_ASSETS
from .jarvis_overview_assets import FEATURE_ASSETS as _OVERVIEW_ASSETS
from .jarvis_integrations_assets import FEATURE_ASSETS as _INTEGRATIONS_ASSETS
from .jarvis_context_assets import FEATURE_ASSETS as _CONTEXT_ASSETS
from .jarvis_second_brain_assets import FEATURE_ASSETS as _OBSIDIAN_ASSETS
from .jarvis_extensions_assets import FEATURE_ASSETS as _EXTENSIONS_ASSETS

# Runtime resources are compiled only from these explicit, reviewed modules.
FEATURE_ASSETS: tuple[JarvisFeatureAssets, ...] = (
    _MISSION_ASSETS, _BOTS_ASSETS, _ACTIVITY_ASSETS, _NATIVE_CONTROLS_ASSETS, _LEARNING_ASSETS,
    _NATIVE_INVENTORY_ASSETS,
    _FILES_ASSETS,
    _MODELS_ASSETS,
    _OVERVIEW_ASSETS,
    _INTEGRATIONS_ASSETS,
    _CONTEXT_ASSETS,
    _OBSIDIAN_ASSETS,
    _EXTENSIONS_ASSETS,
)

# New endpoint installers are explicit. Activity is installed exactly once by
# JarvisChatService.install; native settings is installed by the dashboard API.
FEATURE_ROUTE_INSTALLERS = (
    ("missions", _missions.install_jarvis_missions_routes, _missions.FEATURE_ROUTES),
    ("bots", _bots.install_jarvis_bots_routes, _bots.FEATURE_ROUTES),
    ("native-inventory", _native_inventory.install_jarvis_native_inventory_routes,
     _NATIVE_INVENTORY_ASSETS.api_routes),
    ("files", _files.install_jarvis_files_routes, _files.FEATURE_ROUTES),
    ("models-settings", _models.install_jarvis_models_routes, _models.FEATURE_ROUTES),
    ("context", _context.install_jarvis_context_routes, _CONTEXT_ASSETS.api_routes),
    ("second-brain", _obsidian.install_jarvis_obsidian_vault_routes, _OBSIDIAN_ASSETS.api_routes),
    ("extensions", _extensions.install_jarvis_extensions_admin_routes, _EXTENSIONS_ASSETS.api_routes),
)
FEATURE_ROUTE_OWNERS = (
    ("activity", "chat-service.install", _ACTIVITY_ASSETS.api_routes),
    ("native-controls", "dashboard", _NATIVE_CONTROLS_ASSETS.api_routes),
    ("resources-learning", "dashboard", _LEARNING_ASSETS.api_routes),
    ("overview", "dashboard", _OVERVIEW_ASSETS.api_routes),
    ("integrations", "dashboard-and-bots-read", _INTEGRATIONS_ASSETS.api_routes),
)

# Files may reuse only this fixed authenticated conversation selector.
_SHARED_INSTALLER_READS = {
    "files": {("GET", "/chat/api/conversations")},
    "context": {("GET", "/chat/api/conversations")},
    "second-brain": set(),
}
_INTEGRATIONS_SHARED_READS = (
    ("GET", "/chat/api/capabilities"),
    ("GET", "/chat/api/channels"),
)
_OWNER_BY_FEATURE = {
    "activity": "chat-service.install",
    "native-controls": "dashboard",
    "resources-learning": "dashboard",
    "overview": "dashboard",
    "integrations": "dashboard-and-bots-read",
}


def _route_shape(route: tuple[str, str]) -> tuple[str, str]:
    method, path = route
    return method, re.sub(r"\{[a-z][a-z0-9_]*\}", "{}", path)


def _validate_feature_asset_routes(assets: tuple[JarvisFeatureAssets, ...]) -> None:
    """Allow GET/POST pairs inside a feature; only identical GETs may cross features."""
    all_routes: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for asset in assets:
        local_paths: dict[str, str] = {}
        local_routes: set[tuple[str, str]] = set()
        for route in asset.api_routes:
            method, path = route
            shape = _route_shape(route)[1]
            if (route in local_routes
                    or (shape in local_paths and local_paths[shape] != path)):
                raise ValueError("dashboard feature API routes are ambiguous")
            local_routes.add(route)
            local_paths[shape] = path
            for feature_id, previous_method, previous_path in all_routes.get(shape, ()):
                if feature_id == asset.feature_id:
                    continue
                if (path != previous_path or method != "GET" or previous_method != "GET"):
                    raise ValueError("dashboard feature API routes are ambiguous")
            all_routes.setdefault(shape, []).append((asset.feature_id, method, path))


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
                or entry[0] not in _OWNER_BY_FEATURE
                or entry[1] != _OWNER_BY_FEATURE[entry[0]]
                or not isinstance(entry[2], tuple) or entry[0] in owners):
            raise ValueError("dashboard feature route owner is invalid")
        owners[entry[0]] = (entry[1], entry[2])
    if set(assets) != set(installers) | set(owners) or set(installers) & set(owners):
        raise ValueError("dashboard feature routes and static assets differ")

    _validate_feature_asset_routes(FEATURE_ASSETS)
    for feature_id, asset in assets.items():
        declared = {_route_shape(route) for route in asset.api_routes}
        if len(declared) != len(asset.api_routes):
            raise ValueError("dashboard feature API routes are ambiguous")
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
            if feature_id == "integrations":
                bot_routes = installers.get("bots", (None, ()))[1]
                channels_read = ("GET", "/chat/api/channels")
                capabilities_read = ("GET", "/chat/api/capabilities")
                if (owner != "dashboard-and-bots-read"
                        or asset.api_routes != _INTEGRATIONS_SHARED_READS
                        or routes != _INTEGRATIONS_SHARED_READS
                        or bot_routes.count(channels_read) != 1
                        or _route_shape(capabilities_read) not in registered
                        or _route_shape(channels_read) in registered):
                    raise ValueError("integration readiness reads do not have their reviewed owners")
            elif not declared.issubset(registered):
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
    registered_after_install = {_route_shape((route.method, route.resource.canonical))
                                for route in app.router.routes()}
    for feature_id, (_owner, routes) in owners.items():
        if not {_route_shape(route) for route in routes}.issubset(registered_after_install):
            raise ValueError(f"shared feature routes were not registered for {feature_id}")
