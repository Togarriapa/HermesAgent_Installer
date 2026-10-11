"""Literal feature fragments included in the Jarvis dashboard build.

The release integrator appends reviewed module imports here. Never discover
fragments from a directory or user-controlled configuration at runtime.
"""
from __future__ import annotations

from . import jarvis_missions as _missions
from . import jarvis_bots as _bots
from . import jarvis_activity as _activity
from .jarvis_feature_contract import JarvisFeatureAssets
from .jarvis_missions_assets import FEATURE_ASSETS as _MISSION_ASSETS
from .jarvis_bots_ui import FEATURE_ASSETS as _BOT_ASSETS
from .jarvis_activity_assets import FEATURE_ASSETS as _ACTIVITY_ASSETS
from .jarvis_native_controls_assets import FEATURE_ASSETS as _CONTROL_ASSETS

# Kept as a typed tuple so composition remains explicit and bounded. Feature
# owners provide each FEATURE_ASSETS export for the integration checkpoint.
FEATURE_ASSETS: tuple[JarvisFeatureAssets, ...] = (
    _MISSION_ASSETS, _BOT_ASSETS, _ACTIVITY_ASSETS, _CONTROL_ASSETS,
)

# Route installers are also an explicit, reviewed registry. An installed feature
# cannot add an endpoint by dropping a module into this package or by request data.
FEATURE_ROUTE_INSTALLERS = (
    ("missions", _missions.install_jarvis_missions_routes, _missions.FEATURE_ROUTES),
    ("bots", _bots.install_jarvis_bots_routes, _bots.FEATURE_ROUTES),
)

# These routes belong to the shared chat/dashboard services installed first.
# Validate their actual registration without installing a second handler.
_PREINSTALLED_ROUTES = (
    ("activity", _ACTIVITY_ASSETS.api_routes),
    ("native-controls", (("GET", "/chat/api/settings"),)),
)


def install_jarvis_feature_routes(app, service) -> None:
    """Install exactly the route adapters represented by the literal UI registry."""
    from .jarvis_feature_contract import validate_feature_assets

    validate_feature_assets(FEATURE_ASSETS)
    assets = {feature.feature_id: feature for feature in FEATURE_ASSETS}
    installer_ids = [entry[0] for entry in FEATURE_ROUTE_INSTALLERS
                     if (isinstance(entry, tuple) and len(entry) == 3
                         and isinstance(entry[0], str) and callable(entry[1])
                         and isinstance(entry[2], tuple))]
    existing_ids = [entry[0] for entry in _PREINSTALLED_ROUTES]
    if (len(installer_ids) != len(FEATURE_ROUTE_INSTALLERS)
            or len(set(installer_ids + existing_ids)) != len(installer_ids + existing_ids)
            or set(installer_ids + existing_ids) != set(assets)):
        raise ValueError("dashboard feature routes and static assets differ")
    registered = {(route.method, route.resource.canonical) for route in app.router.routes()}
    for feature_id, routes in _PREINSTALLED_ROUTES:
        if assets[feature_id].api_routes != routes or not set(routes).issubset(registered):
            raise ValueError("shared feature routes are not registered exactly")
    for feature_id, installer, routes in FEATURE_ROUTE_INSTALLERS:
        if assets[feature_id].api_routes != routes:
            raise ValueError("dashboard feature asset and installer routes differ")
        installer(app, service)
    added = {(route.method, route.resource.canonical) for route in app.router.routes()} - registered
    expected = {route for _, _, routes in FEATURE_ROUTE_INSTALLERS for route in routes}
    if added != expected:
        raise ValueError("feature installer added an unreviewed route")
