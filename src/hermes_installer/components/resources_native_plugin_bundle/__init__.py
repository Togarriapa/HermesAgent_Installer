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

    from hermes_installer.remote.core_native_observer import (
        CoreNativeObservationClient,
        register_native_resources_observer,
    )
    from hermes_installer.remote.jarvis_final_effects import install_jarvis_final_effect_middleware
    from hermes_installer.native_invocations import install_pinned_tool_executor_dispatch_bridge

    client = CoreNativeObservationClient()
    # Register enforcement before the Resources tool, then bind the exact
    # source-pinned executor entry in memory. If the executor source differs,
    # the middleware remains installed and denies because lexical call context
    # is absent. No upstream source file is patched on disk.
    effect_registrations = install_jarvis_final_effect_middleware(
        ctx, client)
    try:
        install_pinned_tool_executor_dispatch_bridge()
    except Exception:
        # Keep the deny-by-default middleware active. Its missing-context
        # branch prevents downstream native dispatch.
        pass
    observer_registrations = register_native_resources_observer(ctx, None)
    return (*observer_registrations, *effect_registrations)
