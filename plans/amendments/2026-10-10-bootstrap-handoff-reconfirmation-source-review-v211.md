# Bootstrap handoff reconfirmation source review v211

Refines BD-F02/HI-T149.1, BD-T208.1 and VD-T208.2. Sol inspected exact committed26cf496fa354fcdd7798d8af67bfa9547ffe4751 (tree144a5cf08f86475f487fd6bb1cea1082e8c41500). New registry reconfirmation preserves original same-controller/TTY/live descriptors as lineage, requires exact sameSHA input and unchanged lifecycle, closes original proof and mints independent fresh60s proof for one-use existing handoff. Expired original is not current authority; existing source/runtime/reexec checks remain.

Only installed root_setup member supersedes v204: src/hermes_installer/root_setup.py, module hermes_installer.root_setup, installed installer-module:hermes_installer.root_setup at lib/python/hermes_installer/root_setup.py;62517B SHA2565bd49b6e0105d65d342302df953ed41f6ab0f0edd2bb90d7e7c2b4b4ada30563, module/root-owned0444/preload. Exact machine rows in planning/bootstrap-handoff-reconfirmation-source-review-v211.json. All other source members unchanged; builder single call is structural reference, no self-pin/rawcatalog row.

BD-T208.1/VD-T208.2 remain OPEN for exact pin application, full unexcluded regression checks and actual target evidence. Known prior root pin mismatch must not be waived. This is source review only, not completed tests/installation or inferred target diagnosis. All original scope and AC01..18 OPEN; frozen baseline unchanged.

Reported source checks: root_setup28 passed; release/factory86 passed,7 skipped,1 exact old root_setup tuple failure; compileall/diff clean. Full unexcluded rerun after application remains required.
