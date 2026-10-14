#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../../../.." && pwd)"
HELPER="$ROOT/debian/.local/bin/nala-release-sync"
probe() {
  local name="$1" expected="$2" os_release="$3" devuan_file="$4" arch="${5:-amd64}"
  local actual=0
  NALA_PLATFORM_PROBE=1 NALA_OS_RELEASE="$os_release" NALA_DEVUAN_VERSION_FILE="$devuan_file" \
    NALA_ARCH="$arch" NALA_RELEASES_SSV="$ROOT/debian/.nala/manifest/releases.ssv" \
    "$HELPER" >/dev/null 2>&1 || actual=$?
  [ "$actual" -eq "$expected" ] || { echo "scope fixture failed: $name (got $actual, want $expected)" >&2; exit 1; }
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf '%s\n' 'ID=ubuntu' 'VERSION_ID="24.04"' > "$tmp/ubuntu2404"
printf '%s\n' 'ID=ubuntu' 'VERSION_ID="26.04"' > "$tmp/ubuntu2604"
printf '%s\n' 'ID=ubuntu' 'VERSION_ID="22.04"' > "$tmp/ubuntu2204"
printf '%s\n' 'ID=ubuntu' 'VERSION_ID="25.04"' > "$tmp/ubuntu2504"
printf '%s\n' 'ID=debian' 'VERSION_ID="13"' > "$tmp/debian13"
printf '%s\n' 'ID=debian' 'VERSION_ID="12"' > "$tmp/debian12"
printf '%s\n' 'ID=debian' 'VERSION_ID="14"' > "$tmp/debian14"
printf '%s\n' 'ID=devuan' 'VERSION_ID="6"' > "$tmp/devuan6"
touch "$tmp/devuan-version"
probe ubuntu-24.04 0 "$tmp/ubuntu2404" "$tmp/no-devuan"
probe ubuntu-26.04 0 "$tmp/ubuntu2604" "$tmp/no-devuan"
probe debian-13 0 "$tmp/debian13" "$tmp/no-devuan"
probe ubuntu-22.04 1 "$tmp/ubuntu2204" "$tmp/no-devuan"
probe ubuntu-25.04 1 "$tmp/ubuntu2504" "$tmp/no-devuan"
probe debian-12 1 "$tmp/debian12" "$tmp/no-devuan"
probe debian-14 1 "$tmp/debian14" "$tmp/no-devuan"
probe devuan-6 1 "$tmp/devuan6" "$tmp/devuan-version"
probe ubuntu-24.04-arm64 1 "$tmp/ubuntu2404" "$tmp/no-devuan" arm64

arm_log="$tmp/arm-routing.log"
NALA_SYNC_PROBE=1 NALA_RELEASES_SSV="$ROOT/debian/.nala/manifest/releases.ssv" \
  NALA_OS_RELEASE="$tmp/ubuntu2404" NALA_DEVUAN_VERSION_FILE="$tmp/no-devuan" \
  NALA_ARCH=arm64 HOME="$tmp/home" "$HELPER" >"$arm_log" 2>&1
grep -q 'skip chatgpt (arch=amd64, this=arm64)' "$arm_log"
if grep -q 'probed chatgpt' "$arm_log"; then
  echo "arm64 routing processed the amd64 ChatGPT row" >&2
  exit 1
fi

test_manifest="$tmp/releases.ssv"
printf '%s\n' \
  'first first first.deb amd64 shared ""' \
  'later later later.deb amd64 shared ""' > "$test_manifest"
aggregation_log="$tmp/aggregation.log"
if NALA_SYNC_PROBE=1 NALA_SYNC_FAIL_PKGS=first NALA_RELEASES_SSV="$test_manifest" \
  NALA_OS_RELEASE="$tmp/ubuntu2404" NALA_DEVUAN_VERSION_FILE="$tmp/no-devuan" \
  NALA_ARCH=amd64 HOME="$tmp/home" "$HELPER" >"$aggregation_log" 2>&1; then
  echo "failure aggregation unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'failed first' "$aggregation_log"
grep -q 'later' "$aggregation_log"
grep -q '1 manifest row(s) failed' "$aggregation_log"

stubbin="$tmp/bin"
mkdir -p "$stubbin" "$tmp/home"
printf '%s\n' '#!/usr/bin/env bash' 'if [ "${1:-}" = --print-architecture ]; then printf "amd64\n"; exit 0; fi' 'if [ "$1" = -i ]; then printf dpkg-called >> "$NALA_TEST_LOG"; exit 1; fi' 'exit 2' > "$stubbin/dpkg"
printf '%s\n' '#!/usr/bin/env bash' 'case "${*: -1}" in Package) printf testpkg;; Version) printf 2;; *) exit 2;; esac' > "$stubbin/dpkg-deb"
printf '%s\n' '#!/usr/bin/env bash' 'if [ -f "$NALA_TEST_STATE" ]; then IFS=$'"'"'\t'"'"' read -r status version < "$NALA_TEST_STATE"; printf "%s\t%s\n" "$status" "$version"; else exit 1; fi' > "$stubbin/dpkg-query"
printf '%s\n' '#!/usr/bin/env bash' 'while [[ "${1:-}" == *=* ]]; do export "$1"; shift; done' 'exec "$@"' > "$stubbin/sudo"
printf '%s\n' '#!/usr/bin/env bash' 'printf apt-called >> "$NALA_TEST_LOG"; exit 1' > "$stubbin/fake-apt"
printf '%s\n' '#!/usr/bin/env bash' 'printf apt-get-f-called >> "$NALA_TEST_LOG"' '[ "${NALA_TEST_REPAIR:-0}" = 1 ] && printf '"'"'install ok installed\t2\n'"'"' > "$NALA_TEST_STATE"' 'exit 0' > "$stubbin/apt-get"
chmod +x "$stubbin"/*
NALA_INSTALL_PROBE=1 NALA_TEST_APT_BIN="$stubbin/fake-apt" NALA_TEST_BUNDLE="$tmp/fake.deb" \
  NALA_TEST_LOG="$tmp/install.log" NALA_TEST_STATE="$tmp/install.state" NALA_TEST_REPAIR=1 \
  NALA_RELEASES_SSV="$ROOT/debian/.nala/manifest/releases.ssv" \
  HOME="$tmp/home" PATH="$stubbin:$PATH" "$HELPER" >/dev/null
grep -q apt-called "$tmp/install.log"
grep -q dpkg-called "$tmp/install.log"
grep -q apt-get-f-called "$tmp/install.log"

# Nala must never apply its configured autoremove during a release install.
printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "$@" > "$NALA_TEST_ARGV_LOG"' 'exit 1' > "$stubbin/nala"
chmod +x "$stubbin/nala"
NALA_INSTALL_PROBE=1 NALA_TEST_APT_BIN=nala NALA_TEST_BUNDLE="$tmp/fake.deb" \
  NALA_TEST_LOG="$tmp/nala-install.log" NALA_TEST_ARGV_LOG="$tmp/nala-argv.log" \
  NALA_TEST_STATE="$tmp/nala-install.state" NALA_TEST_REPAIR=1 \
  NALA_RELEASES_SSV="$ROOT/debian/.nala/manifest/releases.ssv" \
  HOME="$tmp/home" PATH="$stubbin:$PATH" "$HELPER" >/dev/null
grep -qx -- '--no-autoremove' "$tmp/nala-argv.log"

printf 'half-installed\t1\n' > "$tmp/install.state"
if NALA_INSTALL_PROBE=1 NALA_TEST_APT_BIN="$stubbin/fake-apt" NALA_TEST_BUNDLE="$tmp/fake.deb" \
  NALA_TEST_LOG="$tmp/install-fail.log" NALA_TEST_STATE="$tmp/install.state" NALA_TEST_REPAIR=0 \
  NALA_RELEASES_SSV="$ROOT/debian/.nala/manifest/releases.ssv" \
  HOME="$tmp/home" PATH="$stubbin:$PATH" "$HELPER" >/dev/null 2>&1; then
  echo "final package-version verification unexpectedly succeeded" >&2
  exit 1
fi

signed_manifest="$tmp/signed-releases.ssv"
printf '%s\n' 'signed-deb://https://fixture.invalid/deb chatgpt chatgpt amd64 chatgpt-supported ""' > "$signed_manifest"
packages_fixture="$tmp/Packages"
printf '%s\n' \
  'Package: chatgpt' \
  'Version: 99.1' \
  'Filename: pool/chatgpt_99.1_amd64.deb' \
  'SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' > "$packages_fixture"
packages_sha="$(sha256sum "$packages_fixture" | awk '{print $1}')"
inrelease_fixture="$tmp/InRelease"
printf 'SHA256:\n %s %s main/binary-amd64/Packages\n' \
  "$packages_sha" "$(wc -c < "$packages_fixture")" > "$inrelease_fixture"
printf '%s\n' '#!/usr/bin/env bash' \
  'url=""; out=""' \
  'while [ "$#" -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; https://*) url="$1"; shift;; *) shift;; esac; done' \
  'case "$url" in */InRelease) cp "$NALA_TEST_INRELEASE" "$out";; */Packages) cp "$NALA_TEST_PACKAGES" "$out";; *) exit 2;; esac' > "$stubbin/curl"
printf '%s\n' '#!/usr/bin/env bash' \
  'out=""; while [ "$#" -gt 0 ]; do case "$1" in --output) out="$2"; shift 2;; *) shift;; esac; done' \
  'cat > "$out"' > "$stubbin/gpg"
printf '%s\n' '#!/usr/bin/env bash' '[ "${NALA_TEST_GPGV_FAIL:-0}" != 1 ]' > "$stubbin/gpgv"
chmod +x "$stubbin/curl" "$stubbin/gpg" "$stubbin/gpgv"

caller_trap_success="$tmp/caller-success"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'trap '"'"'printf caller-trap > "$NALA_TEST_CALLER_TRAP"'"'"' EXIT' 'source "$NALA_TEST_HELPER"' > "$tmp/source-success.sh"
chmod +x "$tmp/source-success.sh"
caller_trap_failure="$tmp/caller-failure"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'trap '"'"'printf caller-trap > "$NALA_TEST_CALLER_TRAP"'"'"' EXIT' 'source "$NALA_TEST_HELPER"' > "$tmp/source-failure.sh"
chmod +x "$tmp/source-failure.sh"

metadata_parent="$tmp/metadata"
mkdir -p "$metadata_parent"
NALA_RELEASE_DIFF_ONLY=1 NALA_RELEASES_SSV="$signed_manifest" \
  NALA_OS_RELEASE="$tmp/ubuntu2404" NALA_DEVUAN_VERSION_FILE="$tmp/no-devuan" NALA_ARCH=amd64 \
  NALA_RELEASE_TMPDIR="$metadata_parent" NALA_TEST_INRELEASE="$inrelease_fixture" \
  NALA_TEST_PACKAGES="$packages_fixture" NALA_TEST_STATE="$tmp/no-installed-state" \
  HOME="$tmp/home" PATH="$stubbin:$PATH" "$HELPER" > "$tmp/signed-success.log"
grep -q 'latest=99.1' "$tmp/signed-success.log"
if find "$metadata_parent" -mindepth 1 -print -quit | grep -q .; then
  echo "signed metadata workspace leaked after success" >&2
  exit 1
fi
NALA_RELEASE_DIFF_ONLY=1 NALA_RELEASES_SSV="$signed_manifest" \
  NALA_OS_RELEASE="$tmp/ubuntu2404" NALA_DEVUAN_VERSION_FILE="$tmp/no-devuan" NALA_ARCH=amd64 \
  NALA_RELEASE_TMPDIR="$metadata_parent" NALA_TEST_INRELEASE="$inrelease_fixture" \
  NALA_TEST_PACKAGES="$packages_fixture" NALA_TEST_STATE="$tmp/no-installed-state" \
  NALA_TEST_HELPER="$HELPER" NALA_TEST_CALLER_TRAP="$caller_trap_success" \
  HOME="$tmp/home" PATH="$stubbin:$PATH" "$tmp/source-success.sh" >/dev/null
[ "$(cat "$caller_trap_success")" = caller-trap ]
if find "$metadata_parent" -mindepth 1 -print -quit | grep -q .; then
  echo "signed metadata workspace leaked after sourced success" >&2
  exit 1
fi

if NALA_RELEASE_DIFF_ONLY=1 NALA_RELEASES_SSV="$signed_manifest" \
  NALA_OS_RELEASE="$tmp/ubuntu2404" NALA_DEVUAN_VERSION_FILE="$tmp/no-devuan" NALA_ARCH=amd64 \
  NALA_RELEASE_TMPDIR="$metadata_parent" NALA_TEST_INRELEASE="$inrelease_fixture" \
  NALA_TEST_PACKAGES="$packages_fixture" NALA_TEST_GPGV_FAIL=1 NALA_TEST_STATE="$tmp/no-installed-state" \
  HOME="$tmp/home" PATH="$stubbin:$PATH" "$HELPER" > "$tmp/signed-failure.log" 2>&1; then
  echo "bad signed metadata unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'signature verification failed' "$tmp/signed-failure.log"
if find "$metadata_parent" -mindepth 1 -print -quit | grep -q .; then
  echo "signed metadata workspace leaked after failure" >&2
  exit 1
fi
if NALA_RELEASE_DIFF_ONLY=1 NALA_RELEASES_SSV="$signed_manifest" \
  NALA_OS_RELEASE="$tmp/ubuntu2404" NALA_DEVUAN_VERSION_FILE="$tmp/no-devuan" NALA_ARCH=amd64 \
  NALA_RELEASE_TMPDIR="$metadata_parent" NALA_TEST_INRELEASE="$inrelease_fixture" \
  NALA_TEST_PACKAGES="$packages_fixture" NALA_TEST_GPGV_FAIL=1 NALA_TEST_STATE="$tmp/no-installed-state" \
  NALA_TEST_HELPER="$HELPER" NALA_TEST_CALLER_TRAP="$caller_trap_failure" \
  HOME="$tmp/home" PATH="$stubbin:$PATH" "$tmp/source-failure.sh" >/dev/null 2>&1; then
  echo "bad sourced signed metadata unexpectedly succeeded" >&2
  exit 1
fi
[ "$(cat "$caller_trap_failure")" = caller-trap ]
if find "$metadata_parent" -mindepth 1 -print -quit | grep -q .; then
  echo "signed metadata workspace leaked after sourced failure" >&2
  exit 1
fi

excl_ssv="$tmp/host-excludes.ssv"
printf '%s\n' 'testhost nala first "test exclude"' > "$excl_ssv"
excl_manifest="$tmp/excl-releases.ssv"
printf '%s\n' \
  'first first first.deb amd64 shared ""' \
  'later later later.deb amd64 shared ""' > "$excl_manifest"
excl_log="$tmp/host-exclude.log"
NALA_SYNC_PROBE=1 NALA_RELEASES_SSV="$excl_manifest" \
  NALA_OS_RELEASE="$tmp/ubuntu2404" NALA_DEVUAN_VERSION_FILE="$tmp/no-devuan" NALA_ARCH=amd64 \
  HOST_EXCLUDES="$excl_ssv" HOST_EXCLUDES_HOSTNAME=testhost \
  "$HELPER" >"$excl_log" 2>&1
grep -q 'skip first (host-excluded)' "$excl_log"
if grep -q 'probed first' "$excl_log"; then
  echo "host-excluded row did not stop the first pkg from being probed" >&2
  exit 1
fi
grep -q 'probed later' "$excl_log"

printf '%s\n' 'nala release platform fixtures: ok'
