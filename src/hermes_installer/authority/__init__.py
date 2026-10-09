"""Root-owned host authority and fixed-effect broker contracts."""

from .daemon import build_authority_service, build_enrolled_authority_service, serve_authority
from .enrollment import (
    NativeBridgeEnrollment, RootCredentialVault, create_authority_signing_key, load_protected_enrollment,
    write_artifact_catalog, write_authority_config,
)
from .client import (
    AuthorityClient, DEFAULT_SOCKET_DIR, canonical_profile_target,
    default_socket_path, profile_launch_envelope,
)
from .types import (
    AuthorityDenied, BrokeredEffectResponse, EffectAuthorization, HostContext, NativeEventHandle,
    Sensitivity, VerifiedEffectAuthorization, canonical_bytes, canonical_digest,
)

__all__ = [
    "AuthorityClient", "AuthorityDenied", "BrokeredEffectResponse",
    "EffectAuthorization", "HostContext", "NativeEventHandle", "NativeBridgeEnrollment", "Sensitivity",
    "VerifiedEffectAuthorization", "canonical_bytes", "canonical_digest", "canonical_profile_target",
    "profile_launch_envelope", "DEFAULT_SOCKET_DIR", "default_socket_path",
    "build_authority_service", "serve_authority",
    "build_enrolled_authority_service", "RootCredentialVault",
    "create_authority_signing_key", "load_protected_enrollment",
    "write_authority_config", "write_artifact_catalog",
]
