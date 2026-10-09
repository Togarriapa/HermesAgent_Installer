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
time, input, and output sizes are bounded. Outputs are created once beneath the
approved output root and include source/output digests and validation
provenance. Kobo delivery accepts only enrolled book and device IDs, validates
the current model/generation and root-issued `plugin.kobo-bridge.deliver`
authorization, requires root-confirmed `usb_epub_pdf_export` capability, then
copies a structurally recognized non-DRM EPUB or PDF to
the existing enrolled USB root and verifies its digest without overwriting
files. EPUBs are validated as packages; PDFs receive a bounded header/trailer
check. Full PDF conformance remains unverified.

Fixture executables exercise real subprocess recipes and create EPUB/PDF
artifacts. Additional fixtures verify Kobo export bytes, authorization,
enrollment mismatch, rights denial, malformed output, symlink input, and
overwrite refusal. These results do not establish native ARM64 toolchain,
Kobo hardware/model capability, Dropbox, Google Drive, Composio OAuth, or
account readiness. Native registration stays unavailable until the root
runtime supplies a protected document runtime with managed tool IDs, approved
profile roots, rights receipts, current device enrollment, and per-effect
authorization. Manifest tool preferences do not permit arbitrary argv or
shell.
