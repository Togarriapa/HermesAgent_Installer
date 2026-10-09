This fixture contains the upstream `skills/diagram-design/scripts/export_svg.py`
copied byte-for-byte from cathrynlavery/diagram-design commit
`f4547ee95f88e5b28a52517feff6b6c11cc657f9`. The helper is MIT licensed under
the upstream repository's `LICENSE`; its SHA-256 is
`3dcf516f8262f6f295b7e8e4b71d923bde8ef6242275182d13343860d6a3b913`.

The small `source/skills/diagram-design` tree is a local import fixture, not a
copy of the complete upstream repository. The integration test builds a
separate harmless HTML/SVG fixture in pytest's temporary directory.
