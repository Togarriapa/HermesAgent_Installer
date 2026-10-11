"""Literal feature fragments included in the Jarvis dashboard build.

The release integrator appends reviewed module imports here. Never discover
fragments from a directory or user-controlled configuration at runtime.
"""
from __future__ import annotations

from . import jarvis_missions as _missions
from .jarvis_feature_contract import JarvisFeatureAssets
from .jarvis_missions_assets import FEATURE_ASSETS as _MISSION_ASSETS

# Kept as a typed tuple so composition remains explicit and bounded. Feature
# owners provide each FEATURE_ASSETS export for the integration checkpoint.
FEATURE_ASSETS: tuple[JarvisFeatureAssets, ...] = (_MISSION_ASSETS,)

# Route installers are also an explicit, reviewed registry. An installed feature
# cannot add an endpoint by dropping a module into this package or by request data.
FEATURE_ROUTE_INSTALLERS = (
    ("missions", _missions.install_jarvis_missions_routes, _missions.FEATURE_ROUTES),
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
    if len(installer_ids) != len(FEATURE_ROUTE_INSTALLERS) or set(installer_ids) != set(assets):
        raise ValueError("dashboard feature routes and static assets differ")
    for feature_id, installer, routes in FEATURE_ROUTE_INSTALLERS:
        if assets[feature_id].api_routes != routes:
            raise ValueError("dashboard feature asset and installer routes differ")
        installer(app, service)
