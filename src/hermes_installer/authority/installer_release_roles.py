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
})
