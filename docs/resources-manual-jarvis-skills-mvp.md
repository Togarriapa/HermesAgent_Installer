# Manual Jarvis Resources skill MVP

This package is a narrowly scoped, user-owned staging path for the verified
HermesAgent_Resources snapshot. It is not the managed installer and does not
complete the `resources-bundle-native-enrichment` OpenSpec change.

The pinned snapshot is Resources revision
`113f42d33be9e0c8f0f47f5ca998e687323dec83`, tree
`c0c994b5e0b96b90cfd2fc564ea8632dff124308`, catalog `2.3.1`. The primary
`profiles/hermes@*` closure contains four portable skill documents:
`conversation-gateway`, `hermes-response-contract`, `speech-input-routing`,
and `spoken-response-delivery`. Each compiles to one `SKILL.md`; this selected
closure has no external reference files. The stage does not install or change
the primary SOUL/profile, configuration, credentials, memories, or existing
skills.

The deterministic bundle contains those four files, a source/member digest
manifest, and `manual_stage_jarvis_skills.py`. Its installer writes one
revision-namespaced directory below the existing Hermes home `skills/` root,
with an ownership journal. It refuses unowned conflicts and edited staged
members, preserves all existing bytes, and is idempotent for an intact owned
generation. Run it as the existing Hermes-home owner, never with `sudo`:

```sh
python3 manual_stage_jarvis_skills.py install \
  --bundle /path/to/jarvis-primary-skills-113f42d33be9.zip \
  --home /home/admin/.hermes \
  --expected-sha256 <independently-verified-bundle-sha256>
```

Materialization is not discovery evidence. Verify all four names through the
pinned Hermes `tools.skills_tool.skills_list()` for the active Hermes home,
then open/refetch Desktop Capabilities → Skills on the active default/Jarvis
connection and inspect the visible entries. Only those target observations can
change `discovered` from false. Skill content is not proof of authentication,
functional execution, enablement, or target acceptance.

The Resources `voice-pipeline` declaration is not imported by this package.
The pinned Hermes Desktop plugin discovery API has no native module path for
that declaration; its installer PluginContext adapter and local Wyoming/Piper
effects/authority are separate unfinished work. The 207 specialist profiles
remain internal and are not exposed as selectable profiles by this package.
Authentication, activation, runtime integration, plugins, accounts, complete
resource readiness, and unsafe deletion remain open requirements.
