#!/bin/sh
# Fixed non-root launcher for the retained official Hermes source and PM Python.
# This is a candidate-owned manual MVP wrapper, not a general installer runtime.
set -eu

SOURCE='/home/admin/HermesInstaller/data/generations/hermes-agent-7085fbf77532'
PYTHON='/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv/bin/python'
EXPECTED_PREFIX='/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv'

if [ "$(id -u)" -eq 0 ]; then
  echo 'Hermes backend must not run as root' >&2
  exit 126
fi
if [ "${HOME:-}" != /home/admin ]; then
  echo 'Unexpected preserved Hermes profile owner/home' >&2
  exit 126
fi
if [ ! -x "$PYTHON" ]; then
  echo 'Selected Hermes PM Python is unavailable' >&2
  exit 126
fi
if [ ! -f "$SOURCE/hermes_cli/main.py" ]; then
  echo 'Selected Hermes source generation is unavailable' >&2
  exit 126
fi

# Keep the runtime self-contained: do not inherit unrelated Python startup hooks.
unset PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE
PYTHONPATH=$SOURCE
export PYTHONPATH

if ! "$PYTHON" -c 'import importlib.util, os, sys; expected_prefix=os.path.realpath(sys.argv[1]); source=os.path.realpath(sys.argv[2]); spec=importlib.util.find_spec("hermes_cli.main"); assert sys.version_info[:2] == (3, 14), sys.version; assert os.path.realpath(sys.prefix) == expected_prefix, sys.prefix; assert spec is not None and os.path.realpath(spec.origin) == os.path.join(source, "hermes_cli", "main.py"), None if spec is None else spec.origin' "$EXPECTED_PREFIX" "$SOURCE"; then
  echo 'PM Python/source generation identity check failed' >&2
  exit 126
fi

exec "$PYTHON" -m hermes_cli.main "$@"
