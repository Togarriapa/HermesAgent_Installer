"""One PM-environment Hermes request worker for the native dispatch test."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

def option(name):
    prefix = "--" + name + "="
    for item in sys.argv[1:]:
        if item.startswith(prefix):
            return item[len(prefix):]
    raise SystemExit("missing required worker argument " + name)

source = Path(option("source-root")).resolve(strict=True)
home = Path(option("home")).resolve(strict=True)
expected = option("expected-sha")
model = option("model")
actual = subprocess.run(
    ["git", "-C", str(source), "rev-parse", "HEAD"], cwd=source, check=True,
    capture_output=True, text=True, timeout=3,
    env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1",
         "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"},
).stdout.strip()
if actual != expected:
    raise SystemExit("pinned Hermes source identity mismatch")
os.environ["HERMES_HOME"] = str(home)
os.environ["HOME"] = os.environ.get("HOME", str(home.parent))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.dont_write_bytecode = True

from providers import get_provider_profile
LOCAL_PROVIDER_NAME = "hermes-installer-dispatch"
profile = get_provider_profile(LOCAL_PROVIDER_NAME)
if profile is None or profile.default_aux_model != model:
    raise SystemExit("managed Hermes provider profile was not discovered")
from run_agent import AIAgent
agent = None
try:
    agent = AIAgent(
        quiet_mode=True, enabled_toolsets=[], skip_context_files=True,
        load_soul_identity=False, skip_memory=True, skip_background_review=True,
    )
    if agent.provider != LOCAL_PROVIDER_NAME or agent.model != model:
        raise SystemExit("Hermes native config did not select the managed provider")
    primary = agent.client.chat.completions.create(
        model=model, messages=[{"role": "user", "content": "native primary fixture"}], max_tokens=24,
    )
    if primary.choices[0].message.content != "native fixture response":
        raise SystemExit("primary route response mismatch")
    from agent.auxiliary_client import call_llm
    auxiliary = call_llm(
        task="title_generation", main_runtime=None,
        messages=[{"role": "user", "content": "native auxiliary fixture"}],
        max_tokens=24, timeout=5,
    )
    if "native fixture response" not in str(auxiliary):
        raise SystemExit("auxiliary route response mismatch")
    print("NATIVE_DISPATCH_OK")
finally:
    if agent is not None:
        agent.close()
