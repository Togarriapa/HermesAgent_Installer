# Ebook and Kobo document adapters

The preserved `ebook-toolchain` and `kobo-bridge` plugin manifests remain the
source identities. `components/plugin_documents.py` provides fixed managed
Pandoc, EPUBCheck, and Calibre recipes plus an export operation for one
explicitly enrolled Kobo. Tool arguments and paths never come from model tool
arguments; the adapter does not remove DRM, inspect accounts, alter notebooks,
or discover/mount devices. EPUB conversion accepts a rights-receipted Markdown
or text source from the approved import root, runs the fixed Pandoc arguments,
validates EPUB structure, and uses optional managed EPUBCheck when present. PDF
conversion accepts a rights-receipted valid EPUB and uses the fixed Calibre
`ebook-convert` recipe. Executables must resolve beneath the managed tool root;
time, input, and output sizes are bounded. The native adapters never resolve
those paths themselves: they submit only bounded opaque IDs and format/title
options through `plugin_effects.invoke` (`ebook-toolchain/run`,
`kobo-bridge/read`, and `kobo-bridge/deliver`). The root action resolves the
fixed recipe, protected profile roots, rights receipts, enrolled device/model,
and output generation. The package maps ebook `run`, `inspect`, and `validate`
action IDs to the root operation `plugin.ebook-toolchain.run`; Kobo uses its
separate root `read` and `deliver` operations. Run arguments are `source_id`, `format` (`epub3` or
`pdf`), `title`, and the root-selected `recipe_id`; inspect/validate accept
only `source_id` and `recipe_id`. Kobo read accepts `book_id` plus
`enrollment_id`; delivery accepts `export_id` plus `enrollment_id`. The root
selects the enrolled USB or user-authorized cloud connection. These are
opaque references, never paths or executable arguments. Kobo notebook reads are limited to exported-file IDs;
delivery validates the selected model/generation and transport capability in
the root action. The local host fixture helper covers USB and refuses existing
destinations. EPUBs are validated as packages; PDFs receive a bounded
header/trailer check. Full PDF conformance remains unverified.

Fixture executables exercise real subprocess recipes and create EPUB/PDF
artifacts through host helpers. Native-handler fixtures assert that every
generation, notebook-read, or delivery request reaches the selected root
effect API with only typed IDs/options, stable idempotency for writes, and no
caller paths or executable arguments. Additional helper fixtures verify Kobo
export bytes, authorization, enrollment mismatch, rights denial, malformed
output, symlink input, and overwrite refusal. These results do not establish native ARM64 toolchain,
Kobo hardware/model capability, Dropbox, Google Drive, Composio OAuth, or
account readiness. Native registration stays unavailable until the runtime
injects the selected `plugin_effects` facade and root package bindings for
these exact actions. Manifest tool preferences do not permit arbitrary argv
or shell.
