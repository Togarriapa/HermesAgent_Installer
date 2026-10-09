# Superpowers Hermes hook fixture

This fixture copies the Hermes integration files needed by `test_superpowers.py` from
`obra/superpowers` commit `8ca22dba9a94f28898bbce59f2537ff4d87c747d` (MIT). The upstream
plugin module is retained byte-for-byte; its SHA256 is
`7fd93899e39371d56ba1e32660548673afa78f3a4a8bd306f93fbb418afa6f3c`.

The test loads this module as an installed plugin under a temporary directory, runs its real
`register()` function, then triggers the registered `pre_llm_call` callback through a fixture
that implements the `register_skill` and `register_hook` methods exposed by Hermes at
`7085fbf7753266fc4943c55ac04926186bc90005`. The fixture proves the upstream callback's effect;
it does not claim that the native Hermes loader or a Raspberry Pi was exercised.
