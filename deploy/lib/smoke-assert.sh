#!/usr/bin/env bash
# Derived from packages/agent-runtime/digitalocean/lib/smoke-assert.sh (Heron's) at weir main bfc070e, renamed for Wren; the history in these comments is Heron's.
# Built-by: @projectx.sui - Co-authored-by: Kaela <kaela@projectxprotocol.dev>
#
# The on-host half of build order step 9's gate, run over the deploy's SSH session:
#
#     ssh -- ops@<ip> bash -s < lib/smoke-assert.sh
#
# A FILE, for the same reason lib/post-boot-assert.sh is one: a block that only ever runs on a host
# nobody has built is a block nobody has ever run. Every path here has a WREN_* seam so the whole
# script runs on this laptop against a stand-in (test/host.test.mjs), and every seam defaults to the
# real host path. The deploy passes none of them.
#
# What it settles, and each line is one of the items Security left open for step 9 on its second
# read of step 6:
#
#   1. /srv/wren/chain.json is readable BY UID 10002 and parses. wren-purse.service runs as
#      `purse` and reads that file at start; at root:root the signer refuses to start and, through
#      wren-beat.service's Requires=, no beat ever runs.
#   2. the docker socket is reachable from a unit under ProtectSystem=strict. The reasoning that
#      says it is -- the kernel's read-only check returns EROFS for regular files, directories and
#      symlinks only, so connect() to a socket inode succeeds -- was accepted as written and is
#      exactly the kind of reasoning that has to be run once. This runs it, in a transient unit
#      carrying the beat unit's own two directives.
#   3. root has no ~/.docker. wren-beat.service runs as root under ProtectHome=yes, which hides
#      /root: a docker client config there would be silently absent at every beat and present for
#      every hand-run command, which is the shape of a bug nobody finds.
#
# What it does NOT settle, said here rather than left to be assumed: unattended-upgrades and the
# journald bound surviving a REBOOT is a step-10 check, because nothing that runs inside one boot
# can observe the next one. It is printed as a reminder at the end, never as an assertion.
set -euo pipefail

SUDO="${WREN_SUDO:-sudo}"
SRV_ROOT="${WREN_SRV_ROOT:-/srv/wren}"
PURSE_UID="${WREN_PURSE_UID:-10002}"
DOCKER_BIN="${WREN_DOCKER_BIN:-/usr/bin/docker}"
SYSTEMD_RUN="${WREN_SYSTEMD_RUN:-systemd-run}"
ROOT_HOME="${WREN_ROOT_HOME:-/root}"

fail() {
  echo "smoke: refused - $1" >&2
  exit 1
}

# --- 1. the signer's chain file, from the signer's own uid --------------------------------------
CHAIN="$SRV_ROOT/chain.json"
$SUDO test -f "$CHAIN" || fail "$CHAIN does not exist; wren-purse.service names it as --chain and reads it at start"
$SUDO -u "#$PURSE_UID" test -r "$CHAIN" \
  || fail "$CHAIN is not readable by uid $PURSE_UID; the signer runs as that uid and refuses to start without it"
$SUDO -u "#$PURSE_UID" python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$CHAIN" \
  || fail "$CHAIN is not parsable JSON read as uid $PURSE_UID; build order step 8 writes the deployment into it"
echo "smoke: $CHAIN is readable and parsable as uid $PURSE_UID"

# --- 2. the docker socket, from inside ProtectSystem=strict -------------------------------------
DOCKER_VERSION="$($SUDO "$SYSTEMD_RUN" --pipe --quiet \
  --property=ProtectSystem=strict --property=ProtectHome=yes --property=PrivateTmp=yes \
  "$DOCKER_BIN" version --format '{{.Server.Version}}' 2>&1)" \
  || fail "the docker socket is NOT reachable from a unit under ProtectSystem=strict and ProtectHome=yes: $DOCKER_VERSION. wren-beat.service carries both, and its own comment names the one-line fallback (ReadWritePaths=/run/docker.sock)."
echo "smoke: docker answered from inside ProtectSystem=strict: server $DOCKER_VERSION"

# --- 3. no ~/.docker for a unit that cannot see /root -------------------------------------------
if $SUDO test -e "$ROOT_HOME/.docker"; then
  fail "$ROOT_HOME/.docker exists, and wren-beat.service runs as root under ProtectHome=yes: the beat would silently not see a client config every hand-run docker command does see"
fi
echo "smoke: $ROOT_HOME/.docker does not exist, so ProtectHome=yes hides nothing the beat needs"

echo "smoke: on-host assertions passed"
echo "smoke: STEP 10, not asserted here - unattended-upgrades and the journald bound surviving a reboot cannot be observed from inside this boot"
