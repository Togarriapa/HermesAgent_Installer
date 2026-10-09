# Capability Coverage

This is the canonical current capability map. Individual manifest YAML files remain authoritative for exact dependencies, instructions, versions, tools, and permissions. Use `python scripts/render_registry_reference.py` for a live manifest-derived Profile/integration table.

## HermesAgent, software, data, AI and homelab infrastructure

HermesAgent runtime/provisioner expertise; general/backend/frontend/web/DevOps development; systems architecture; network/SRE/database/infrastructure; cybersecurity/privacy engineering; data engineering/science/analytics; AI/ML application development; AI systems architecture; prompt engineering; agent orchestration; evaluation; LLMOps; AI safety/reliability; retrieval and knowledge engineering.

Homelab infrastructure coverage adds cross-service diagnosis, bounded Hermes/Nextcloud host operations, Nextcloud maintenance, backup/recovery, Cloudflare tunnel/DNS operations, and periodic read-only health review. Infrastructure mutation and infrastructure alarms are restricted to Hermes users with current effective membership in the Authentik `System` group. Membership is freshly checked before writes and recipients are freshly resolved at alarm delivery; failures deny rather than broaden access. Raw SSH/arbitrary shell is not exposed to agents.

Home Assistant remains the smart-home/device automation control plane, including routine device/Starlink automations; Hermes infrastructure operations consume only the context/control already intentionally exposed by the existing Home Assistant MCP.

## Product, operations, people and career

Product management/research, business analysis/requirements, COO/operations, project/agile/scrum, improvement management, HR/people operations, recruiting, procurement/vendor management, negotiation/conflict resolution, remote-work optimization, career advising/development, executive leadership, and decision science.

## Finance, accounting and investment

Portuguese/international accounting, CFO/financial planning, wealth/portfolio/asset/stocks/crypto/real-estate management, investment research and independent risk analysis, normalized financial data stewardship, explicit-order real-money execution, Ledger/live-wallet control, and autonomous testnet experimentation.

## Law, privacy and governance

Portuguese, EU, international and employment-law research; GDPR/privacy; estate/succession; insurance; ethics; fact checking/source verification; and privacy/security engineering. Licensed representation or professional sign-off is not implied.

## Home, property, resilience and fabrication

Preventive home maintenance; plumbing/appliances/carpentry/finishes/roofing/drainage/grounds/home comfort; building architecture; energy/solar; water/wastewater; emergency preparedness; arboriculture; building biology/pests; automotive maintenance; Home Assistant/smart-home/IoT; electrical/mechanical/robotics engineering; 3D CAD/modeling/optimization/printing.

## Farm, agriculture, food and traditional living

Farm planning/management, agriculture/agronomy, horticulture/orchards, livestock navigation, farm machinery, irrigation/water, weather, homesteading, cooking and food preservation. Amish coverage includes lifestyle, remedies, construction, farming, housekeeping, cooking and preservation while preserving community/affiliation/region variation. Ancient-tradition coverage is civilization/place/period/source specific and labels attested, inferred, reconstructed and speculative material.

## Health, traditional remedies and fitness

Nutrition; traditional-remedy research; herbalism/ethnobotany; historical materia medica; natural-lifestyle education; traditional foodways; Amish/ancient remedy research; general fitness; bodybuilding/hypertrophy; calisthenics; powerlifting; strength/conditioning; mobility/flexibility; endurance; prenatal/postpartum; senior and youth fitness.

Traditional-use claims are separated from modern evidence. Remedy roles do not diagnose/prescribe or advise delaying effective/urgent care. Fitness roles use symptom-aware progression/referral; pregnancy/postpartum clinician restrictions and youth safeguarding are hard boundaries.

## Education, children, family and social sciences

Curriculum/homeschooling, homeroom, mathematics, science, literacy, languages, history, music, theology, child development, SEN, safeguarding, psychology, sociology, anthropology, culture, philosophy, debate/dissent analysis, Catholic relationship/family guidance, and Portuguese/Sicilian/Spanish/German Catholic family perspectives.

## Catholic theology, tradition and liturgy

Scripture, theology, Magisterium, Catholic history, tradition, family guidance, prayer planning/writing, Traditional Latin Mass, Roman Rite liturgical history, pre-Vatican-II practice, devotions/sacramentals, Gregorian chant/sacred music, calendar/fasting/abstinence, Patristics/Church Fathers, and Ecclesiastical Latin. Outputs distinguish doctrine, discipline, liturgical law, historical practice, devotion/custom, opinion and current jurisdiction.

## Research, information and language

General/scientific research, evidence synthesis, misinformation/media literacy, historical method, knowledge management/archive work, professional European Portuguese↔English translation, writing/editing, and source-integrity procedures.

## Ebook publishing and Kobo

Ebook Planner, Writer, Editor/Publisher, Designer and Converter cover architecture, long-form drafting, editing/proofing, reflowable design, metadata, EPUB/PDF conversion and validation. Kobo Library & Notebook Specialist owns exported-note ingestion/synthesis; Kobo Integration Specialist owns device/model/firmware capability detection, sync/USB troubleshooting and transfer workflows. Validated non-DRM EPUB/PDF delivery uses approved Dropbox/Google Drive/USB paths only on explicit request, with USB/manual fallback when cloud support is unavailable.

## Integrations and automation

GitHub, web research, Composio, filesystem/GitHub/Home Assistant MCP, Home Assistant/Wyoming voice, WhatsApp Business, Authentik authorization, bounded Hermes/Nextcloud host operations, scoped Cloudflare homelab operations, Cloudflare/GitHub webhooks, scheduled resource reconciliation, read-only homelab health review, ebook conversion tools, and Kobo export/sideload bridge are bounded by host policy and per-resource declarations.

GitHub Actions provide PR validation, semantic-version/catalog consistency checks, weekly maintenance audits, dependency-update PRs, and optional signed notification to Hermes after a validated `main` update.
