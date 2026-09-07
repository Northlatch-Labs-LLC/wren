#!/usr/bin/env bash
# Derived from packages/agent-runtime/digitalocean/lib/post-boot-assert.sh (Heron's) at weir main bfc070e, renamed for Wren; the history in these comments is Heron's.
# Built-by: @projectx.sui - Co-authored-by: Kaela <kaela@projectxprotocol.dev>
#
# The post-boot assertions, run on the droplet over the deploy's SSH session:
#
#     ssh ops@<ip> bash -s < lib/post-boot-assert.sh
#
# It is a FILE, not a heredoc inside deploy-droplet.sh, for one reason: a block that only ever runs
# on a host nobody has built yet is a block nobody has ever run. As a file it can be executed on
# this laptop against a fixture that stands in for the host (test/host-fixes.test.mjs), so the
# thing that decides whether a droplet lives or is destroyed has itself been run before it decides.
#
# WHY EVERY PRIVILEGED LINE CARRIES sudo. This runs as `ops`, an unprivileged login account.
#   - /usr/sbin is not on a non-root PATH on Debian, so a bare `sshd -T` is "command not found";
#   - `sshd -T` must read /etc/ssh/ssh_host_*_key, mode 0600 root, so even found it exits 1;
#   - `cloud-init status`/`schema --system` read root-only state;
#   - /etc/ssh/sshd_config.d and /etc/wren are 0700-ish root.
# Under `set -euo pipefail` the first of those failures propagated, this block returned non-zero,
# and the deploy destroyed the droplet it had just paid for -- every single time, while the three
# hardening keywords it claims to assert were never actually read (Security's B4 on step 6).
# `ops` holds NOPASSWD:ALL from cloud-init, so sudo here adds no privilege that the SSH key did not
# already carry; it only stops the assertions from failing for the wrong reason.
#
# The WREN_* variables below are seams for the local fixture ONLY. Every default is the real host
# path, and the deploy passes none of them: on the droplet this script runs entirely on its
# defaults.
set -euo pipefail

SUDO="${WREN_SUDO:-sudo}"
SSHD_BIN="${WREN_SSHD_BIN:-/usr/sbin/sshd}"
CLOUD_INIT_BIN="${WREN_CLOUD_INIT_BIN:-cloud-init}"
DEBIAN_VERSION_FILE="${WREN_DEBIAN_VERSION_FILE:-/etc/debian_version}"
SSHD_CONFIG_D="${WREN_SSHD_CONFIG_D:-/etc/ssh/sshd_config.d}"
SRV_ROOT="${WREN_SRV_ROOT:-/srv/wren}"
ETC_ROOT="${WREN_ETC_ROOT:-/etc/wren}"
VAR_ROOT="${WREN_VAR_ROOT:-/var/lib/wren}"
NSSWITCH_FILE="${WREN_NSSWITCH_FILE:-/etc/nsswitch.conf}"
NODE_BIN="${WREN_NODE_BIN:-/usr/bin/node}"
ASSERT_OWNERS="${WREN_ASSERT_OWNERS:-1}"
ASSERT_ACCOUNTS="${WREN_ASSERT_ACCOUNTS:-1}"

fail() {
  echo "post-boot: refused - $1" >&2
  exit 1
}

# --- 1. cloud-init actually applied -----------------------------------------------------------
# The decisive one. v1 booted with root open because cloud-init refused the whole document over a
# single byte and NOTHING asked it whether it had succeeded.
CLOUD_INIT_STATUS="$($SUDO "$CLOUD_INIT_BIN" status --wait --long 2>&1)" || {
  echo "$CLOUD_INIT_STATUS" >&2
  fail "cloud-init status --wait --long exited non-zero"
}
echo "$CLOUD_INIT_STATUS"
# `--wait` prints its progress dots on the SAME line as the first status field, so the line reads
# '....status: done' (seen on the third real run, 2026-09-05, which was destroyed by this very
# check while cloud-init had in fact finished clean). Strip leading dots before matching.
CLOUD_INIT_STATUS="$(sed 's/^\.*//' <<<"$CLOUD_INIT_STATUS")"
grep -q '^status: done$' <<<"$CLOUD_INIT_STATUS" || fail "cloud-init did not finish with 'status: done'"

# "status: done" alone is not enough: cloud-init reports done with a non-empty error list. Both
# shapes it prints an error list in are refused -- the inline `errors: ['...']` and the multi-line
# one whose entries are dashed continuation lines.
ERRORS_LINE="$(grep '^errors:' <<<"$CLOUD_INIT_STATUS" || true)"
if [ -n "$ERRORS_LINE" ] && [ "$ERRORS_LINE" != "errors: []" ]; then
  fail "cloud-init printed '$ERRORS_LINE'; it must be exactly 'errors: []'"
fi
if grep -A5 '^errors:' <<<"$CLOUD_INIT_STATUS" | grep -qE '^[[:space:]]+-[[:space:]]*\S'; then
  fail "cloud-init listed at least one error under 'errors:' in its own status output"
fi

$SUDO "$CLOUD_INIT_BIN" schema --system || fail "cloud-init schema --system refused the applied config"

# --- 2. the two accounts, by id, both directions ----------------------------------------------
if [ "$ASSERT_ACCOUNTS" = "1" ]; then
  [ "$(getent passwd 10001 | cut -d: -f1)" = "wren" ] || fail "uid 10001 is not wren"
  [ "$(getent group 10001 | cut -d: -f1)" = "wren" ] || fail "gid 10001 is not wren"
  # The account that holds the hot key. It was created by nobody before this fix.
  [ "$(getent passwd 10002 | cut -d: -f1)" = "purse" ] || fail "uid 10002 is not purse"
  [ "$(getent group 10002 | cut -d: -f1)" = "purse" ] || fail "gid 10002 is not purse"
  # The container's uid must not be able to read the signer's files through a shared group.
  if id -nG purse 2>/dev/null | tr ' ' '\n' | grep -qx wren; then
    fail "the purse account is in the wren group; the model's container could read the signer's files"
  fi
fi

# --- 3. Debian 13 -----------------------------------------------------------------------------
grep -q "^13" "$DEBIAN_VERSION_FILE" || fail "$DEBIAN_VERSION_FILE does not start with 13"

# --- 4. SSH hardening, read out of sshd's own merged view --------------------------------------
# `sshd -T` is the merged configuration sshd will actually use, which is the only thing worth
# asserting: it settles the 00- vs 50-cloud-init.conf ordering question as a fact rather than an
# argument about glob order.
$SUDO ls "$SSHD_CONFIG_D" >/dev/null 2>&1 || fail "$SSHD_CONFIG_D cannot be read even with sudo"
SSHD_CONF_FILES="$($SUDO ls "$SSHD_CONFIG_D")"
grep -qx '00-wren.conf' <<<"$SSHD_CONF_FILES" || fail "00-wren.conf is not in $SSHD_CONFIG_D"
FIRST_CONF="$(grep '\.conf$' <<<"$SSHD_CONF_FILES" | LC_ALL=C sort | head -n 1)"
[ "$FIRST_CONF" = "00-wren.conf" ] \
  || fail "00-wren.conf does not sort first in $SSHD_CONFIG_D (first is '$FIRST_CONF'); sshd keeps the FIRST value it reads"

SSHD_EFFECTIVE="$($SUDO "$SSHD_BIN" -T)" || fail "$SSHD_BIN -T failed even under sudo"
for KEYWORD in passwordauthentication permitrootlogin kbdinteractiveauthentication; do
  LINE="$(grep -iE "^${KEYWORD} " <<<"$SSHD_EFFECTIVE" || true)"
  [ -n "$LINE" ] || fail "sshd -T printed no '$KEYWORD' line at all"
  grep -qiE "^${KEYWORD} no$" <<<"$LINE" || fail "sshd -T says '$LINE'; it must read '${KEYWORD} no'"
  echo "post-boot: sshd -T: $LINE"
done

# --- 5. node, because the signer's ExecStart is an absolute path to it -------------------------
# cloud-init adds Debian's `nodejs` package because wren-purse.service starts /usr/bin/node and
# wren-beat.service Requires= the signer. That the package ships THAT path was reasoned from
# Debian's packaging and not verified from this laptop -- so step 6 proves it here instead of step
# 5 discovering it (Security's requirement on the second read).
[ -x "$NODE_BIN" ] || fail "$NODE_BIN is not present or not executable; wren-purse.service's ExecStart names it and wren-beat.service Requires= the signer"
echo "post-boot: $NODE_BIN $("$NODE_BIN" --version)"

# --- 6. the resolver path, pinned rather than inherited ----------------------------------------
# wren-alert@.service's RestrictAddressFamilies list is written against this line. `files dns` is
# glibc's own resolver out of /etc/resolv.conf, not nss-resolve's varlink socket. Asserted here so
# which path the dead man's last hop takes is a fact.
grep -qE '^hosts:[[:space:]]+files dns$' "$NSSWITCH_FILE" \
  || fail "$NSSWITCH_FILE does not pin 'hosts: files dns' ($($SUDO grep -E '^hosts:' "$NSSWITCH_FILE" 2>/dev/null || echo 'no hosts line at all'))"
echo "post-boot: $NSSWITCH_FILE pins hosts: files dns"

# --- 7. the layout, at the owner and mode cloud-init claims ------------------------------------
# Every path the units name. A directory made by hand at deploy time is a mode nobody asserts, and
# the one that would have been made by hand is the hot key's home.
$SUDO python3 - "$SRV_ROOT" "$ETC_ROOT" "$VAR_ROOT" "$ASSERT_OWNERS" "$SSHD_CONFIG_D" <<'PY'
import os
import pwd
import grp
import stat
import sys

srv, etc, var = sys.argv[1], sys.argv[2], sys.argv[3]
assert_owners = sys.argv[4] == "1"
sshd_conf_d = sys.argv[5]

EXPECTED = [
    (srv,                       0o751, "root",  "root"),
    (f"{srv}/bin",              0o755, "root",  "root"),
    (f"{srv}/runs",            0o2770, "root",  "wren"),
    (f"{srv}/runs/archive",    0o2770, "root",  "wren"),
    (f"{srv}/state",           0o2770, "root",  "wren"),
    (f"{srv}/keys",             0o700, "purse", "purse"),
    (f"{srv}/purse",            0o750, "purse", "purse"),
    (f"{srv}/purse/dist",       0o750, "purse", "purse"),
    (f"{srv}/policy",           0o755, "root",  "root"),
    (var,                       0o700, "purse", "purse"),
    (f"{var}/audit",            0o700, "purse", "purse"),
    (etc,                       0o700, "root",  "root"),
    (f"{etc}/creds",            0o700, "root",  "root"),
    # The dead man's own memory: root's alone, and outside every mount the container is given.
    (f"{var}/watchdog",         0o700, "root",  "root"),
]

# Files, not only directories. --plan's step 10 used to claim "the same file asserts every path
# above", and the file asserted thirteen directories and no file mode at all (Security's N-5 on the
# second read). These three are every file cloud-init places at a mode something depends on:
# image.env is what the container reads, chain.json is what the signer reads AS purse -- at
# root:root it cannot open it and the beat never runs (N-6) -- and 00-wren.conf is the sshd
# hardening whose ordering the check above already asserts.
EXPECTED_FILES = [
    (f"{srv}/image.env",             0o600, "root",  "root"),
    (f"{srv}/chain.json",            0o600, "purse", "purse"),
    (f"{sshd_conf_d}/00-wren.conf", 0o644, "root",  "root"),
]

problems = []
for path, mode, owner, group in EXPECTED:
    try:
        info = os.stat(path)
    except OSError as exc:
        problems.append(f"{path}: {exc.strerror}")
        continue
    if not stat.S_ISDIR(info.st_mode):
        problems.append(f"{path}: not a directory")
        continue
    actual_mode = stat.S_IMODE(info.st_mode)
    if actual_mode != mode:
        problems.append(f"{path}: mode {actual_mode:04o}, expected {mode:04o}")
    if assert_owners:
        actual_owner = pwd.getpwuid(info.st_uid).pw_name
        actual_group = grp.getgrgid(info.st_gid).gr_name
        if (actual_owner, actual_group) != (owner, group):
            problems.append(f"{path}: {actual_owner}:{actual_group}, expected {owner}:{group}")

for path, mode, owner, group in EXPECTED_FILES:
    try:
        info = os.stat(path)
    except OSError as exc:
        problems.append(f"{path}: {exc.strerror}")
        continue
    if not stat.S_ISREG(info.st_mode):
        problems.append(f"{path}: not a regular file")
        continue
    actual_mode = stat.S_IMODE(info.st_mode)
    if actual_mode != mode:
        problems.append(f"{path}: mode {actual_mode:04o}, expected {mode:04o}")
    if assert_owners:
        actual_owner = pwd.getpwuid(info.st_uid).pw_name
        actual_group = grp.getgrgid(info.st_gid).gr_name
        if (actual_owner, actual_group) != (owner, group):
            problems.append(f"{path}: {actual_owner}:{actual_group}, expected {owner}:{group}")

# No plaintext credential anywhere under /srv/wren, ever. The sealed blobs live in /etc/wren/creds
# and systemd-creds decrypts them into a per-unit tmpfs; a readable file here is the v1 corner.
for root, _dirs, files in os.walk(srv):
    for name in files:
        if name.endswith((".cred", ".key", ".token", ".pem")):
            problems.append(f"{os.path.join(root, name)}: a credential-shaped file under {srv}")

if problems:
    for problem in problems:
        print(f"post-boot: refused - {problem}", file=sys.stderr)
    sys.exit(1)
print(
    f"post-boot: every directory under {srv}, {etc} and {var}, and the modes of "
    + ", ".join(path for path, _m, _o, _g in EXPECTED_FILES)
    + ", are what cloud-init claims"
)
PY

echo "post-boot assertions passed"
