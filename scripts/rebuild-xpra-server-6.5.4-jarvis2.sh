#!/bin/bash
set -euo pipefail
umask 077

# Root-only, fixed-input repair for the reviewed Pi MVP package. This never
# edits the installed vendor tree and never invokes apt or resolves packages.
readonly ROOT=/var/lib/hermes-installer/vendor
readonly INPUT="$ROOT/xpra-server_6.5.4-r0-1_arm64.deb"
readonly OUTPUT="$ROOT/xpra-server_6.5.4-r0-1+jarvis2_arm64.deb"
readonly EXPECTED_INPUT_SHA=5e46390ee30241e4c5fdcd0ac29218c5c21990ce4a8cce3dd80306c704424b31
readonly REBUILDER=/usr/local/lib/hermes-installer/xpra_control_guard_patch.py

deny() { printf 'refusing Xpra MVP repair: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) == 0 ]] || deny 'run only from the root-only Pi maintenance session'
[[ $(dpkg --print-architecture) == arm64 ]] || deny 'target is not Debian arm64'
[[ -f $INPUT && ! -L $INPUT ]] || deny 'fixed retained signed input is absent or not a regular file'
[[ $(stat -c '%u:%a' "$INPUT") == 0:* ]] || deny 'retained input must be root-owned'
[[ $(sha256sum "$INPUT" | cut -d' ' -f1) == "$EXPECTED_INPUT_SHA" ]] || deny 'retained signed input hash differs'
[[ -f $REBUILDER && ! -L $REBUILDER ]] || deny 'reviewed patch helper is absent or not a regular file'
[[ $(sha256sum "$REBUILDER" | cut -d' ' -f1) == \
   e9935a951490ec01a6c644c5e2e0d251931db96937540f9949f98fd2dda0382a ]] || deny 'patch helper hash differs from reviewed implementation'

mode=${1:-}
case "$mode" in
  build)
    (($# == 1)) || deny 'build accepts no additional arguments'
    [[ ! -e $OUTPUT && ! -L $OUTPUT ]] || deny 'fixed output already exists; preserve it for review'
    installed=$(dpkg-query -W -f='${Version}\n' xpra-server 2>/dev/null || true)
    [[ $installed == 6.5.4-r0-1+jarvis1 ]] || deny "installed xpra-server version is not the reviewed v260 repair ($installed)"
    work=$(mktemp -d "$ROOT/.xpra-repair.XXXXXXXX")
    chmod 0700 "$work"
    trap 'rm -rf -- "$work"' EXIT
    mkdir "$work/original" "$work/rebuilt"
    dpkg-deb --raw-extract "$INPUT" "$work/original"
    cp -a "$work/original/." "$work/rebuilt/"
    python3 "$REBUILDER" patch "$work/rebuilt"
    python3 "$REBUILDER" metadata "$work/rebuilt/DEBIAN"
    python3 "$REBUILDER" verify "$work/original" "$work/rebuilt"
    dpkg-deb --build --root-owner-group "$work/rebuilt" "$work/repaired.deb"
    verify=$(mktemp -d "$work/verify.XXXXXXXX")
    dpkg-deb --raw-extract "$work/repaired.deb" "$verify"
    python3 "$REBUILDER" verify "$work/original" "$verify"
    [[ $(dpkg-deb -f "$work/repaired.deb" Package) == xpra-server ]] || deny 'rebuilt package identity mismatch'
    [[ $(dpkg-deb -f "$work/repaired.deb" Version) == 6.5.4-r0-1+jarvis2 ]] || deny 'rebuilt package version mismatch'
    [[ $(dpkg-deb -f "$work/repaired.deb" Architecture) == arm64 ]] || deny 'rebuilt package architecture mismatch'
    install -o root -g root -m 0644 "$work/repaired.deb" "$OUTPUT"
    printf 'reviewable package: %s\nsha256: ' "$OUTPUT"
    sha256sum "$OUTPUT" | cut -d' ' -f1
    printf 'No package was installed. Review the measured hash, then call install <that-sha256>.\n'
    ;;
  install)
    (($# == 2)) || deny 'install requires the exact reviewed package SHA-256'
    [[ $2 =~ ^[0-9a-f]{64}$ ]] || deny 'invalid SHA-256 argument'
    [[ -f $OUTPUT && ! -L $OUTPUT ]] || deny 'fixed rebuilt package is absent'
    [[ $(stat -c '%u:%a' "$OUTPUT") == 0:644 ]] || deny 'rebuilt package must be root-owned mode 0644'
    [[ $(sha256sum "$OUTPUT" | cut -d' ' -f1) == "$2" ]] || deny 'reviewed package hash does not match'
    [[ $(dpkg-deb -f "$OUTPUT" Package) == xpra-server ]] || deny 'package identity mismatch'
    [[ $(dpkg-deb -f "$OUTPUT" Version) == 6.5.4-r0-1+jarvis2 ]] || deny 'package version mismatch'
    [[ $(dpkg-deb -f "$OUTPUT" Architecture) == arm64 ]] || deny 'package architecture mismatch'
    dpkg --install "$OUTPUT"
    ;;
  *) deny 'usage: rebuild-xpra-server-6.5.4-jarvis2.sh build | install <reviewed-sha256>' ;;
esac
