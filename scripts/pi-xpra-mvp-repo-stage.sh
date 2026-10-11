#!/usr/bin/env bash
# Root-pasted, opt-in staging for the isolated Xpra display component on Debian 13 arm64.
# This script does not configure Hermes, Xpra auth, or a running service.
set -Eeuo pipefail
umask 077

readonly KEY_URL='https://xpra.org/xpra.asc'
readonly KEY_FINGERPRINT='B4993B57323148E37977E5D873254CAD17978FAF'
readonly XPRA_SOURCE='deb [arch=arm64 signed-by=KEYFILE] https://xpra.org/ trixie main'
readonly PLAN_PREFIX='/var/tmp/hermes-xpra-v259-apt-simulation-'
readonly -a ROOT_PACKAGES=(
  'xpra-server=6.5.4-r0-1'
  'xpra-common=6.5.4-r0-1'
  'xpra-x11=6.5.4-r0-1'
  'xpra-codecs=6.5.4-r0-1'
  'xpra-html5=21-r1-1'
  xauth
)

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'USAGE'
Usage (root on the target Raspberry Pi, Debian 13 arm64 only):
  sudo bash pi-xpra-mvp-repo-stage.sh query
  sudo bash pi-xpra-mvp-repo-stage.sh simulate
  sudo bash pi-xpra-mvp-repo-stage.sh install <simulation-sha256>

Review the complete simulation before install. The install command repeats it and
requires its exact SHA-256; it refuses removals, upgrades, unauthenticated repo
metadata, or a changed plan. It installs only the listed Xpra component roots
and their required dependencies, with no recommendations/removals/upgrades.
USAGE
}

[[ $EUID -eq 0 ]] || die 'run with sudo on the Pi; this script is not a Mac installer'
[[ $# -ge 1 ]] || { usage; exit 2; }
command -v apt-get >/dev/null || die 'apt-get unavailable'
command -v apt-cache >/dev/null || die 'apt-cache unavailable'
command -v curl >/dev/null || die 'curl unavailable; refusing to install a fetcher'
command -v gpg >/dev/null || die 'gpg unavailable; refusing unauthenticated repository setup'
[[ $(dpkg --print-architecture) == arm64 ]] || die 'target must report dpkg architecture arm64'
grep -qE '^VERSION_CODENAME=trixie$' /etc/os-release || die 'target must be Debian 13 trixie'

mode=$1
if [[ $mode != query && $mode != simulate && $mode != install ]]; then usage; exit 2; fi
if [[ $mode == install && $# != 2 ]]; then usage; exit 2; fi
if [[ $mode != install && $# != 1 ]]; then usage; exit 2; fi

tmp=$(mktemp -d /var/tmp/hermes-xpra-v259.XXXXXX)
cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT INT TERM
mkdir -p "$tmp/lists/partial" "$tmp/parts" "$tmp/gnupg"
chmod 700 "$tmp/gnupg"

# Reuse existing Debian indexes read-only, but refresh only the pinned Xpra
# source. All apt list/cache writes remain in this temporary directory.
if [[ -d /var/lib/apt/lists ]]; then cp -a /var/lib/apt/lists/. "$tmp/lists/"; fi
if [[ -f /etc/apt/sources.list ]]; then cp -p /etc/apt/sources.list "$tmp/sources.list"; else : >"$tmp/sources.list"; fi
if [[ -d /etc/apt/sources.list.d ]]; then
  find /etc/apt/sources.list.d -maxdepth 1 -type f \( -name '*.list' -o -name '*.sources' \) -exec cp -p '{}' "$tmp/parts/" \;
fi

curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  "$KEY_URL" -o "$tmp/xpra.asc"
key_listing=$(gpg --batch --with-colons --show-keys "$tmp/xpra.asc")
primary_count=$(awk -F: '$1 == "pub" { count++ } END { print count + 0 }' <<<"$key_listing")
actual_fingerprint=$(awk -F: '
  $1 == "pub" { waiting = 1; next }
  waiting && $1 == "fpr" { print toupper($10); waiting = 0 }
' <<<"$key_listing")
[[ $primary_count == 1 && $actual_fingerprint == "$KEY_FINGERPRINT" ]] ||
  die "expected exactly one primary Xpra key with fingerprint $KEY_FINGERPRINT; got count=$primary_count fingerprint=$actual_fingerprint"
install -m 0644 "$tmp/xpra.asc" "$tmp/xpra-key.asc"
repo=${XPRA_SOURCE/KEYFILE/$tmp\/xpra-key.asc}
printf '%s\n' "$repo" >"$tmp/parts/hermes-xpra-v259.list"
chmod 0755 "$tmp"

apt_opts=(
  -o "Dir::State::lists=$tmp/lists"
  -o "Dir::Cache::archives=$tmp/archives"
  -o "Dir::Cache::pkgcache=$tmp/pkgcache.bin"
  -o "Dir::Cache::srcpkgcache=$tmp/srcpkgcache.bin"
  -o "Dir::Etc::sourcelist=$tmp/sources.list"
  -o "Dir::Etc::sourceparts=$tmp/parts"
  -o 'APT::Get::List-Cleanup=false'
  -o 'Acquire::https::Verify-Peer=true'
  -o 'Acquire::https::Verify-Host=true'
)
mkdir -p "$tmp/archives/partial"
if getent passwd _apt >/dev/null; then
  chown _apt "$tmp/lists/partial" "$tmp/archives/partial"
  chmod 0700 "$tmp/lists/partial" "$tmp/archives/partial"
else
  die 'apt _apt account is missing; refusing to weaken temporary apt directory permissions'
fi

# Refresh only Xpra into the temporary list directory. Dependency resolution
# later sees copied host Debian/Raspberry Pi source definitions and cached
# indexes, with all writes still confined to this temporary apt state.
xpra_update_opts=(
  "${apt_opts[@]}"
  -o "Dir::Etc::sourcelist=$tmp/empty-sources.list"
  -o "Dir::Etc::sourceparts=$tmp/xpra-parts"
)
mkdir -p "$tmp/xpra-parts"
: >"$tmp/empty-sources.list"
cp -p "$tmp/parts/hermes-xpra-v259.list" "$tmp/xpra-parts/"
apt-get "${xpra_update_opts[@]}" update

case $mode in
  query)
    printf '\nInstalled display prerequisites (no changes made):\n'
    dpkg-query -W -f='${binary:Package}\t${Version}\t${Status}\n' xvfb xauth 2>/dev/null || true
    printf '\nCandidate package metadata:\n'
    apt-cache "${apt_opts[@]}" policy "${ROOT_PACKAGES[@]}"
    printf '\nAuthenticated Xpra InRelease SHA-256 (from isolated index):\n'
    find "$tmp/lists" -maxdepth 1 -type f -name '*xpra.org*InRelease' -print0 |
      xargs -0r sha256sum
    ;;
  simulate|install)
    sim="$tmp/simulation.txt"
    apt-get "${apt_opts[@]}" --simulate --no-upgrade --no-remove --no-install-recommends \
      install "${ROOT_PACKAGES[@]}" | tee "$sim"
    if grep -qE '^(Remv|Purg) ' "$sim"; then die 'simulation proposes package removal'; fi
    if grep -qE '^Inst [^ ]+ \[[^]]+\]' "$sim"; then die 'simulation proposes an upgrade of an installed package'; fi
    digest=$(sha256sum "$sim" | awk '{print $1}')
    saved="${PLAN_PREFIX}${digest}.txt"
    install -m 0600 "$sim" "$saved"
    printf '\nSimulation SHA-256: %s\nSaved review copy: %s\n' "$digest" "$saved"
    if [[ $mode == install ]]; then
      [[ $2 == "$digest" ]] || die 'reviewed simulation SHA does not match current plan; inspect the new simulation first'
      printf '\nExact plan reviewed by SHA %s:\n' "$digest"
      cat "$saved"
      printf '\nApplying the explicitly requested install operation for reviewed plan %s.\n' "$digest"
      apt-get "${apt_opts[@]}" install --no-upgrade --no-remove --no-install-recommends "${ROOT_PACKAGES[@]}"
    fi
    ;;
esac
