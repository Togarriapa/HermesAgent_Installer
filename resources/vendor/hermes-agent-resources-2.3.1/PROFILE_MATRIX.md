# Profile Matrix

This is the canonical responsibility/boundary summary for Hermes Profiles. Exact Profile-to-Skill/Plugin/MCP dependencies come from the YAML manifests and can be rendered deterministically with `python scripts/render_registry_reference.py`.

Do **not** create versioned matrix supplements. Update this file when a responsibility boundary changes.

## Core orchestration

| Profile family | Responsibility | Key boundary |
| --- | --- | --- |
| Hermes | Sole user-facing gateway and six-section response composition | No specialist may become a user endpoint |
| Orchestrator | Decomposition, recruitment, parallelism, deliberation, reconciliation | Evidence over majority vote; no authority expansion |
| Team Leader | Scoped internal coordination and deliberation | Reports through orchestration chain |
| Resource Evolution Manager | Registry update assessment, overlay rebase, regression/permission review | Update notice is not activation authority |

## Technology, AI and homelab operations

| Profile family | Responsibility | Key boundary |
| --- | --- | --- |
| Developers / QA / DevOps | Software delivery and verification | Production writes require explicit runtime authority |
| Systems / Network / SRE / Database | Architecture and service reliability | No physical-engineering authority inferred from titles |
| Cybersecurity / Privacy Security | Threat, security and privacy engineering | Least privilege and scoped tooling |
| Data Science / Engineering / Analytics | Data products, analytics and ML | Evidence/data provenance required |
| HermesAgent Expert | Hermes registry, provisioner, runtime and topology expertise | Registry declaration is distinct from live runtime enforcement |
| Homelab Infrastructure Operator | Cross-service diagnosis plus bounded Hermes/Nextcloud host, backup/recovery and Cloudflare operations | Internal-only; every infrastructure write and every infrastructure alarm requires fresh effective Authentik `System` membership; no raw SSH/arbitrary shell |
| AI Developer | AI application implementation | Model output is untrusted at tool boundaries |
| AI Systems Architect | Model/tool/retrieval/agent architecture | Architecture proposal is not deployment permission |
| AI Prompt Engineer | Prompt/system-instruction design and evaluation | Prompt text cannot grant structural authority |
| AI Agent Orchestration Engineer | Multi-agent workflow design | Scaling creates capacity, not permissions |
| AI Evaluation Engineer | Behavioral benchmarks and regressions | Claims require evaluation evidence |
| LLMOps Engineer | Model/runtime operations and observability | Production changes require host authorization |
| AI Safety & Reliability Engineer | Failure modes, safety and robustness | Safety boundaries cannot be voted away |
| AI Knowledge Engineer | Retrieval, indexing and knowledge architecture | Preserve source provenance and access control |

The Homelab Infrastructure Operator uses Authentik as the authoritative identity/group decision point. `System` membership is checked before a write and alarm recipients are independently resolved at send time. Home Assistant remains the smart-home/device automation control plane; the homelab operator does not duplicate routine HA/Starlink automations.

## Kobo and ebook publishing

| Profile | Responsibility | Key boundary |
| --- | --- | --- |
| Kobo Integration Specialist | Device/cloud/USB workflow capability detection and safe transfer | No undocumented Kobo API, credential scraping, DRM circumvention, deletion, or unrequested delivery |
| Kobo Library & Notebook Specialist | Read and synthesize user-exported Kobo notebooks/reading notes | Exported/authorized files only; preserve notebook/page provenance |
| Ebook Planner | Reader, scope, chapter architecture and production plan | Research gaps and user decisions stay explicit |
| Ebook Writer | Long-form ebook drafting from approved plan/evidence | Preserve attribution and distinguish supplied material from generated prose |
| Ebook Designer | Typography, layout, navigation and device-readable presentation | Design must remain reflow-safe unless fixed layout is intentionally chosen |
| Ebook Converter | EPUB/PDF conversion and validation | Never remove DRM; preserve source artifact and verify output |
| Ebook Editor / Publisher | Developmental/copy editing, metadata and release readiness | Publishing/delivery remains a separate explicit action |

Typical workflow:

`Kobo notes / Hermes results -> Planner -> Writer -> Editor -> Designer -> Converter -> EPUB QA -> explicit Kobo delivery`

## Health, traditional remedies and fitness

Traditional-remedy, herbalism, historical materia-medica, Amish-remedy and ancient-remedy Profiles are research/education roles. They distinguish historical/cultural use from current clinical evidence; natural does not mean safe; diagnosis, individualized prescribing, and advice to delay urgent/effective care are denied.

Fitness Profiles cover general coaching, bodybuilding, calisthenics, powerlifting, strength/conditioning, mobility, endurance, prenatal/postpartum, senior and youth fitness. Pregnancy/postpartum clinician restrictions are hard constraints; youth work requires safeguarding; dangerous dehydration/cutting and performance-enhancing drug/hormone advice are denied.

## Amish and ancient-tradition profiles

Amish Profiles cover remedies, lifestyle, construction, farming, housekeeping, cooking and preservation. They must preserve affiliation/community/region variation rather than treating Amish life as uniform.

Ancient-tradition Profiles cover remedies, lifestyle, building, agriculture, domestic life, foodways, preservation and material culture. Claims must be civilization/place/period/source specific and label attested, inferred, reconstructed and speculative material.

## Catholic profiles

Catholic Profiles cover catechesis, Scripture, theology, tradition, history, relationships/family life, prayer, Traditional Latin Mass, Roman Rite history, pre-Vatican-II practice, devotions/sacramentals, Gregorian chant, fasting/calendar discipline, Patristics and Ecclesiastical Latin.

They distinguish binding doctrine, discipline, liturgical law, historical/customary practice, theological opinion, devotion and prudential judgment. No Profile impersonates clergy or grants ecclesiastical permission.

## Other durable responsibility domains

The registry also maintains dedicated Profiles for product/requirements/operations/HR/recruiting/procurement; finance/accounting/investment; Portuguese/EU/international law and privacy; education/SEN/child development; research/fact checking/humanities; career/remote work; home/property/resilience; farming/agriculture; architecture; 3D/additive manufacturing; translation; and household operations.

For exact current dependencies and versions, use the manifest-derived registry reference rather than manually duplicating every selector here.
