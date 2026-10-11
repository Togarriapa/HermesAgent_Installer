"""Fixed official user-plugin entry point for the protected Resources bridge."""
PLUGIN_ID = "hermes-installer-resources-delegation"


def register(ctx):
    """Install only the root-backed observer and exact Resources tool.

    The official loader calls this function for the selected fixed plugin.
    Registration is independent of inspector startup order: the middleware
    and tool use a fixed client whose invocation fails closed until the root
    observer socket is present and its peer/custody checks succeed. This lets
    the core migrate before the inspector starts without requiring a second
    core restart that would invalidate the inspector's retained custody.
    """
    if getattr(ctx, "plugin_id", None) != PLUGIN_ID:
        return ()

    from hermes_installer.remote.core_native_observer import register_native_resources_observer
    return register_native_resources_observer(ctx, None)
