"""Fixed official user-plugin entry point for the protected Resources bridge."""

from pathlib import Path
import os
import stat


PLUGIN_ID = "hermes-installer-resources-delegation"
OBSERVER_SOCKET = Path("/run/hermes-jarvis-native-observer/native-observer.sock")


def _observer_listener_is_staged() -> bool:
    """Check the fixed socket's root-owned runtime custody before registering hooks."""
    try:
        parent = OBSERVER_SOCKET.parent.lstat()
        endpoint = OBSERVER_SOCKET.lstat()
        return bool(
            stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and parent.st_gid == 1000
            and stat.S_IMODE(parent.st_mode) == 0o750
            and stat.S_ISSOCK(endpoint.st_mode) and endpoint.st_uid == 0
            and endpoint.st_gid == 1000 and stat.S_IMODE(endpoint.st_mode) == 0o660
            and endpoint.st_gid in {*os.getgroups(), os.getegid()}
        )
    except OSError:
        return False


def register(ctx):
    """Install only the root-backed observer and exact Resources tool.

    The official loader calls this function for the selected fixed plugin. If
    the optional inspector socket is not ready, ordinary Hermes startup keeps
    working and the feature remains unavailable until a later core restart.
    """
    if getattr(ctx, "plugin_id", None) != PLUGIN_ID or not _observer_listener_is_staged():
        return ()

    from hermes_installer.remote.core_native_observer import register_native_resources_observer
    return register_native_resources_observer(ctx, None)
