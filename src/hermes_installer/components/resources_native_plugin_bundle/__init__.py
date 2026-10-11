"""Fixed official user-plugin entry point for the protected Resources bridge."""
PLUGIN_ID = "hermes-installer-resources-delegation"


def register(ctx):
    """Install only the root-backed observer and exact Resources tool.

    The official loader calls this function for the selected fixed plugin.
    Resources registration is independent of inspector startup order. Obsidian
    tools are registered only when the root observer can issue a fixed-owner
    binding at plugin load; after owner enrollment or inspector recovery, Core
    must reload this plugin so the native handlers bind the prepared store.
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
    obsidian_binding = None
    obsidian_store = None
    try:
        # The native plugin runs in Core UID 1000. The root observer supplies
        # only a sealed fixed-owner selection; the Gateway process never gets
        # a store or a filesystem path it can open.
        import os
        if os.geteuid() != 1000:
            raise PermissionError("Obsidian native tools require the fixed Core UID")
        obsidian_binding = client.bind_obsidian_native_vault()
        from hermes_installer.remote.obsidian_second_brain import (
            ObsidianVaultConfig, prepare_obsidian_vault,
        )
        obsidian_store = prepare_obsidian_vault(ObsidianVaultConfig(
            obsidian_binding.vault_root, obsidian_binding.owner_subject_sha256, owner_uid=1000))
    except Exception:
        # Missing root enrollment or a failed fixed-vault custody check leaves
        # these tools unavailable without preventing unrelated Core tools.
        obsidian_binding = obsidian_store = None
    # Register enforcement before the Resources tool, then bind the exact
    # source-pinned executor entry in memory. If the executor source differs,
    # the middleware remains installed and denies because lexical call context
    # is absent. No upstream source file is patched on disk.
    effect_registrations = install_jarvis_final_effect_middleware(
        ctx, client, obsidian_binding=obsidian_binding)
    obsidian_registrations = ()
    if obsidian_store is not None:
        try:
            from hermes_installer.remote.obsidian_native_tools import ObsidianNativeTools
            obsidian_registrations = ObsidianNativeTools(obsidian_store).register(ctx)
        except Exception:
            obsidian_registrations = ()
    try:
        install_pinned_tool_executor_dispatch_bridge()
    except Exception:
        # Keep the deny-by-default middleware active. Its missing-context
        # branch prevents downstream native dispatch.
        pass
    observer_registrations = register_native_resources_observer(ctx, None)
    return (*observer_registrations, *effect_registrations, *obsidian_registrations)
