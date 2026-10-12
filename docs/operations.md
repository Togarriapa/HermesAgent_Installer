# Operations and recovery

Inventory the selected owner's existing HOME/HERMES_HOME, protected credential references, official PM executable/source/lock, owned units/ports and journal before a change. Adopt rather than reset. Keep finite install/resume/rollback operations separate from general shell authority.

The owned core uses official headless hermes serve on a validated loopback port. Verify actual private authenticated chat, stop/history and stored-session restart; health alone is insufficient. After restart, resume the same server-owned stored session and atomically replace generation-local session IDs. Stale/unknown ownership is denied without replacement history.

Product authority is intended to remain with Jarvis as the sole master. Experts are internal workers, Teams group Experts, and Skills are methods; these terms do not create user-facing identities or Bot DM accounts. OneShot and Kanban are optional/selective workflows. Begin autonomously only when the user explicitly delegated autonomy at task start; otherwise obtain owner approval before acting. Jarvis reviews final effects and alone performs them. This semantic model is pending implementation and acceptance; do not treat these instructions as proof that current runtime paths enforce them.

Checkpoint updates and failures. Interrupted download, wrong digest, network/DNS failure, disk exhaustion, service conflict and invalid policy leave recoverable state and prior data/auth intact. Backups, compatible restore, resume, rollback and restart/reboot each need actual Pi effects and failure proof. Uninstall removes only owned artifacts and preserves user data unless explicitly selected.

Desktop/Xpra cleanup waits for working independent core and replacement protected public owner chat with expiry/revocation/restart proof. Preserve shared tunnel/packages, PM/HOME/auth/Resources and recovery copies; never blanket-purge packages. Unknown ownership remains pending.

Public ingress validates Access JWT before bytes and binds server-derived ownership. Expired original JWT/run bounds, missing/refused/stale heartbeat or witness stop bytes and cancel the exact run. Renewing a browser credential does not extend original turn deadlines. Reject raw RPC/shell/backend management, arbitrary files/URLs and cross-user conversation/approval/artifact access.

For diagnosis record exact candidate/version, target/runtime, command, effect, denial/recovery, sanitized error and concrete resume action. Keep secrets out of reports. Record configured/authenticated/functionally-tested/enabled/actual-target states independently. [Current scope](../requirements/current-scope.json) defines obligations; factual [evidence](evidence/) does not by itself qualify a release.

## Trust this device — planned authentication convenience

The direct request is tracked inside jarvis-core-platform/R0200/R0201/R0203 and the existing HI-T266.2/RT-T266.3/VD-T266.5 groups. On2026-10-13, connector readback verified720h for both the exact Jarvis Access application and allow policy, with HttpOnly/binding-cookie protection retained. This applied application-wide browser convenience affects newly issued sessions; already issued tokens keep their original expiry. It is not a per-device trust feature or evidence of month-long physical-device operation.

After successful authentication, the planned unchecked personal-device option must use a supported native mechanism with visible expiry and Forget/Sign out behavior. M5 additionally requires opt-in, individually revocable native Android/tablet pairing and bounded automatic credential renewal, without hourly/daily interactive OTP during normal paired use. Native pairing, renewal and actual restart/revocation behavior remain unimplemented and unqualified. Shared-device behavior and the original request/turn limits remain separate from browser login duration.

Official source checks on 2026-10-12:

- [Session management](https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/) documents global timeout 15 minutes–one month (default 24 hours), while policy/application controls include immediate timeout–one month. Valid global identity can obtain a new application token after policy checking; Cloudflare One Client authentication, when enabled, takes precedence. These controls do not establish a Jarvis per-device opt-in API.
- [Authorization cookies](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/) documents Cloudflare-managed cookies and HttpOnly protection. Application cookie settings must be verified for this browser use case. Its 30-day CF_Device anti-abuse cookie is not evidence of remembered-login consent.

Before enabling the control, qualify the exact native device/session scope, authenticated opt-in/readback, expiry/revocation, browser reopen and forget/logout. Do not change a global/application/policy TTL and call that per-device trust. Do not promise eternal login, copy credentials into browser storage or create a local bypass cookie. Android/tablet WARP is optional research, not enrolled by this task.

If supported per-device behavior is unavailable, show that limitation and leave the option pending; a non-secret saved preference is only a preference. Logout/forget must use verified native controls with truthful scope. A broader user/application revocation must be labeled as such. Never claim JavaScript cleared HttpOnly or team-domain cookies. Manual cookie clearing or expiration may require sign-in again.

Every request/byte still needs valid Access authorization and fresh revocation evidence. New authentication does not extend original 600s/stricter run deadlines or revive expired turns, repeat uncertain effects, or run pending work automatically. Before deploying auth/UI changes, provide the existing mandatory exact-candidate phone/tablet/desktop affected-flow review and actual native session evidence; fixture-only coverage leaves live acceptance OPEN.
