# Fixed read-only registry discovery refinement v1

Sol-owned additive refinement of baseline R0045/R0048/R0049/R0050/R0051 and Resources RB02/RB03/RB04/RB05. Frozen baseline, all original scope and AC01..18 remain unchanged.

Why: bundled mcp-registry and agent37-discovery promise useful discovery, but generic MCP execution cannot safely represent their public fixed HTTP metadata read. Add RB06, task RB-T07, evidence EV-RB06 in resources-bundle-native-enrichment; prerequisites RB-T02/RB-T03/HI-T03/HI-T08/HI-T09. Retain existing implementation/native/target checkboxes open.


## Fixed discovery transport (RB06)

The pinned Resources plugin declarations permit read-only discovery/metadata, deny install/execute/publication and require source review. A protected host `registry.read` effect maps fixed service ID and typed action to exact HTTPS GET routes. Workers supply normalized bounded fields, never URL/host/method/header/socket. Root verifies current HostContext, complete query-source provenance, recipient, request digest and one-use effect grant before external bytes; unknown/private query is not eligible for public registry egress. Host uses verified TLS, fixed origin, no redirects or credential forwarding. Returned metadata is untrusted; index ranking and download/source URLs never authorize execution, installation or activation.

MCP service `mcp-registry`: origin https://registry.modelcontextprotocol.io. List GET /v0.1/servers permits bounded search, version=latest, cursor and limit. Version history GET /v0.1/servers/{encoded-name}/versions and detail /versions/{encoded-version} permit only include_deleted=false; do not invent pagination there. Encode path segments and reject path escape or destination override.

Agent37 service `agent37-discovery`: origin https://www.agent37.com. Selected API routes observed by components owner from official page implementation: GET /api/skills/search with query, limit<=30, offset, owner, repo, sort in relevance/updated and fixed minStars=10/recentlyUpdated=30; detail GET /api/skills/{id}, ID restricted to returned 32-hex identifier. Project only bounded public metadata; omit content/executable instructions. This route is an observed website implementation, not a claimed stable documented API; incompatible drift leaves discovery incomplete with exact next step.

Installer policy bounds (not upstream capability claims): normalized query<=256 UTF-8 bytes, limit<=30, at most3 pages/90 entries per operation, response<=2MiB, whole operation<=9seconds, finite cursor/ID cache bound to same caller/session/source receipt. Every follow-up page/detail requires current authorization and bounded remaining deadline; malformed/oversized responses and redirects fail before activation. Record source timestamps/provenance, independent fixture/native/live read states, no credential/account or licensing inference. Tests must count actual outbound effects/denials and payload projection; string inventory does not complete RB-T07 or original RB acceptance.

Primary MCP documentation was read directly: https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/official-registry-api.md and official OpenAPI. Agent37 exact route observations were supplied by the components owner after official-page/script and live GET inspection; this Sol turn independently confirms fixed source declaration and official page identity, not all delegated wire observations. Preserve that evidence distinction.

Evidence must include bounded useful positive reads, forged/private/unknown source denial before bytes, wrong service/action/digest/retry/recipient, redirect/destination/path override, malformed/oversized data, page exhaustion/cancellation, untrusted result preservation and actual installed native plugin workflow. Fixture success alone cannot satisfy AC16/AC18 or all-item native operation.
