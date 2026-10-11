# HermesAgent Installer

A Raspberry Pi5 installer for official Hermes headless core and a responsive Jarvis interface, with managed integrations and Resources. **Development is ongoing; complete installation, capability parity and release acceptance are not finished.**

Start with [CURRENT-PLAN.md](CURRENT-PLAN.md), the [complete current functional scope](requirements/current-scope.json), [user guide](docs/usage.md), [operations and recovery](docs/operations.md), [contributor guide](docs/contributing.md) and [AGENTS.md](AGENTS.md).

Core installation comes first, followed by individual capability ports, Jarvis, full Resources and actual end-to-end review. Desktop/Xpra is excluded from the product. Existing data, authentication, PM runtime, Resources and unrelated services must survive adoption and owned cleanup. Public routes retain Cloudflare Access OTP, JWT/binding, conversation ownership and bounded expiry/revocation; raw backend RPC, host shell and management proxies are excluded.

The selected Pi serves protected Jarvis chat, restored sessions, Overview, Capabilities, Models, Settings, Missions, Bots, Logs, Integrations, Learning, Tools & Skills and Files. A real Codex chat and one request using the approved `gpt6Luna` selection have been observed; durable default selection and cold resume remain pending. Native discovery reports 449 skills, including the bundled skills, but discovery is not functional-use proof. A mission draft and activity/usage display were observed; mission execution remains unavailable. Phone chat text entry is not verified because the soft keyboard did not appear on tap, so practical phone/family use remains incomplete. Fresh-install, the pending Resources receipt refresh, complete Resources operation and capability parity remain open. See [current runtime evidence](docs/evidence/jarvis-core-current.md).

All tests, fixtures, previews and validators run only on the identified Pi through the root browser. Local source/spec editing and Git are permitted. Zero additional metered spending is the default. No account secrets, huge model downloads, reimage or unrelated service replacement are implied by setup.

Active implementation is [codex/luna-installer-development](https://github.com/Togarriapa/HermesAgent_Installer/tree/codex/luna-installer-development). Other branch contents are reference checkouts and must consult that branch's current plan before implementation. Obsolete plans are removed from current files; Git history and tags remain intact.
