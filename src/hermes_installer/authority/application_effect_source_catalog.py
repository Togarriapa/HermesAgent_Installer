"""Fixed installer-owned sources for local application qualification effects.

This catalog is deliberately separate from upstream application generation,
runtime ABI probes, and their receipts. Values mirror the v175 Sol-owned
append-only descriptor; tests keep the two representations byte-for-byte
aligned.
"""

APPLICATION_EFFECT_SOURCE_CATALOG_PATH = (
    "plans/amendments/2026-10-10-application-effect-sources-v175/"
    "application-effect-sources-v1.json"
)
APPLICATION_EFFECT_SOURCE_CATALOG_ARTIFACT_ID = "release-file:eda54c5b908c9d5176afef9ee2bf434b"
APPLICATION_EFFECT_SOURCE_CATALOG_SHA256 = "de6df1701fa51727127cdbdb30c6e12a6f4e07297ffce686b758fd3ead1076b4"
APPLICATION_EFFECT_SOURCE_CATALOG_SIZE = 11830

# artifact_id, release member path, role, SHA-256, byte count
APPLICATION_EFFECT_SOURCE_MEMBERS = (
    ("installer-application-effect-graphify-entrypoint-v1",
     "src/hermes_installer/components/probes/graphify_fixture/entrypoint.py",
     "source-module", "db0e49e0878f0406d9dba29c9f9860bee2bc7260e59c9ac7e20ecf88b5a03378", 153),
    ("installer-application-effect-graphify-helper-v1",
     "src/hermes_installer/components/probes/graphify_fixture/helper.py",
     "source-module", "acc16fab89297ad11006519103d1033d611b1315529b5614098a3d60c80c2f74", 155),
    ("installer-application-effect-graphify-result-validator-v1",
     "src/hermes_installer/components/probes/graphify_result.py",
     "source-module", "f3f0b44d9d9d707daceee4d563be1d028080ec661c11a29e85e1f38cda0901e9", 6481),
    ("installer-application-effect-graphify-result-schema-v1",
     "src/hermes_installer/components/probes/graphify_probe_result.schema.json",
     "application-effect-fixture", "0649acf5c5e96c629b73e884683df7fe2f98e1fead448c1548f52c22cdd18136", 1157),
    ("installer-application-effect-browser-use-probe-v1",
     "src/hermes_installer/components/browser_use_qualification_probe.py",
     "source-module", "2f939a6cd82f73f4e7474ed7f0c412e9a22fb65df01e7765c1a87cf675a52e58", 4404),
    ("installer-application-effect-browser-use-result-validator-v1",
     "src/hermes_installer/components/browser_use.py",
     "source-module", "2e27c93d701de22792fae24ddb097d3d0dd7424dd5a25ce510ee75fecc90740f", 6531),
    ("installer-application-effect-scrapegraph-probe-v1",
     "src/hermes_installer/components/probes/scrapegraph_ai_probe.py",
     "source-module", "30974c44d2bd9e60847bcad6ba3849cf8b2a262f8c08f79b832a9bba723ed6ab", 5446),
    ("installer-application-effect-scrapegraph-result-validator-v1",
     "src/hermes_installer/components/scrapegraph_ai.py",
     "source-module", "e2ac08afa32b9940705403eb9e2af35b08e21cc6f61ed6731438a6c1c1c98dcb", 11891),
    ("installer-application-effect-hyperframes-probe-v1",
     "src/hermes_installer/components/probes/hyperframes_probe.py",
     "source-module", "f4a63a90b4467ae2db4fcdf7d874bc8f6b75e6b1f02910e326e75fcb49d498aa", 12692),
    ("installer-application-effect-hyperframes-composition-v1",
     "src/hermes_installer/components/probes/hyperframes_fixture/composition.html",
     "application-effect-fixture", "fc20eaf85de0fe9bbc63bf4b315892a4fb0934d19819eb8b9450fa5bb7ed6052", 707),
)
