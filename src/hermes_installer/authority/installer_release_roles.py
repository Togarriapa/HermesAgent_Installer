"""Canonical finite role vocabulary for the current installed release format.

Adding a role requires reviewed release-member path and content policy. Keep
producers, verifiers, and publishers on this one vocabulary; membership alone
does not authorize any particular file or path.
"""

RELEASE_MEMBER_ROLES = frozenset({
    "launcher",
    "interpreter",
    "module",
    "source-module",
    "template",
    "plan",
    "artifact-catalog",
    "bootstrap-policy",
    "baseline",
    "amendment",
    "runtime-member",
    "native-health-fixture",
    "application-effect-fixture",
    "application-build-driver",
    "network-startup-helper",
})

# Fixed source/member mapping for the root's pre-application network gate.
# The source digest and size remain unset until the final coherent helper
# source has completed review; release builds must not stage it earlier.
NETWORK_STARTUP_HELPER = (
    "installer-private-loopback-worker-gate-v180",
    "helpers/private-loopback-worker-gate.py",
    "helpers/private-loopback-worker-gate.py",
    None,
    None,
    "network-startup-helper",
)
