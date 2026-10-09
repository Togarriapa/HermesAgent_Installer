#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python_bin=python3
if ! command -v "$python_bin" >/dev/null 2>&1; then
  printf '%s\n' 'Python 3.11 or newer is required. Install it with your supported system package manager, then rerun ./install.sh.' >&2
  exit 2
fi
if ! "$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  printf '%s\n' 'Python 3.11 or newer is required. Install it with your supported system package manager, then rerun ./install.sh.' >&2
  exit 2
fi
PYTHONPATH="$repo_dir/src" exec "$python_bin" -m hermes_installer.cli "$@"
