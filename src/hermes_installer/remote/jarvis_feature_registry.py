"""Literal feature fragments included in the Jarvis dashboard build.

The release integrator appends reviewed module imports here. Never discover
fragments from a directory or user-controlled configuration at runtime.
"""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets

# Kept as a typed tuple so composition remains explicit and bounded. Feature
# owners provide each FEATURE_ASSETS export for the integration checkpoint.
FEATURE_ASSETS: tuple[JarvisFeatureAssets, ...] = ()
