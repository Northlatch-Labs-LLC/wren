#!/usr/bin/env bash
# Derived from packages/agent-runtime/digitalocean/deploy-droplet.sh (Heron's host deploy) at weir
# main bfc070e, renamed for Wren. The history these comments record is Heron's; Wren's own runs are
# in digitalocean/runs/. What differs from Heron's: the image is built from the SHARED runtime
# package (packages/agent-runtime) with THIS package's workspace/ overlaid, the units and policy
# documents come from THIS package, and the purse and phase two are told the agent's name by flag.
# Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
#
# Heron v2's host deploy script. Build order step 6
# (work/rnd/agent/2026-09-05-executive-heron-v2-decided.md section 3), against the CTO's spec
# (2026-09-05-engineering-heron-v2-runtime-and-host.md sections 3-4) and the CISO's, amended by
# the executive to one host, one signer service (wren-purse), a 1-of-2 multisig.
#
# WHAT HAS AND HAS NOT BEEN RUN, in the only words that are true of it.
#
# --plan and every fixture in test/host.test.mjs and test/host-fixes.test.mjs have been run on this
# laptop, repeatedly, including the whole create sequence and its rollback against a stub directory.
# --create, --seal, --smoke and --status have never been run against a real DigitalOcean account or
# a real host from this laptop, and no line below claims otherwise.
#
# --create no longer refuses unconditionally. Until Security's second read of this step it carried
# an unconditional `return 1` before its first API call, which meant the sequence below had never
# executed and carried a destroy path nothing had ever taken. That refusal is lifted: the gate is
# WREN_DEPLOY_CONFIRMED=1 -- the Master's word -- plus every precondition in CREATE_PRECONDITIONS,
# and nothing else. WREN_NO_NETWORK=1 remains what it always was: the test seam, under which every
# network call in this file goes to a stub directory or refuses outright.
#
# Modes:
#   --plan                 prints every resource, path and credential row this WOULD create.
#                           No API call, no network requirement at all -- WREN_NO_NETWORK=1 is
#                           accepted as a marker for a test to assert that, but this mode never
#                           makes a network call regardless of whether that variable is set.
#   --create               creates the droplet and its firewall, waits for SSH, asserts cloud-init
#                           succeeded, builds the image on the host. Refuses without
#                           WREN_DEPLOY_CONFIRMED=1 -- the Master's word -- checked FIRST, before
#                           any other input is even read.
#   --seal <name>          pipes one credential from the desk's pile over the live SSH session
#                           straight into `systemd-creds encrypt --with-key=host` on the host.
#                           Never writes a plaintext file anywhere, never puts the value in an
#                           argv or an environment: stdin only. Refuses a name outside
#                           ^[a-z][a-z0-9-]{0,31}$ before it reads anything at all, and refuses
#                           without WREN_DEPLOY_CONFIRMED=1 -- the same word --create needs.
#                           --dry-run prints the exact pipeline and needs neither.
#   --smoke                build order step 9's gate, in five parts and in this order: the on-host
#                           assertions (lib/smoke-assert.sh), the effective inbound ruleset for the
#                           tag read from the ACCOUNT, a forced real email through
#                           wren-alert@smoke, one real beat, and only then the timers. The mail
#                           gate is hard: no sealed mail-key, or no message id in the journal, and
#                           not one timer is enabled.
#   --install-purse        build order step 5 on the host (WREN_HOST, WREN_DEPLOY_CONFIRMED=1):
#                           bundles packages/purse from the committed tree with the pinned esbuild,
#                           renders wren-purse.service with three sha256 pins (the bundle, the
#                           members document, the policy), installs the official node 22 build
#                           under /opt/node22 from a checksum held here as a literal, ships and
#                           installs the files with their modes, starts and enables the unit, and
#                           probes the socket with a malformed request that must come back as a
#                           recorded refusal. The policy shipped is wren-content-pre-soul.json.
#   --install-beat         build order step 9's beat on the host (WREN_HOST, WREN_DEPLOY_CONFIRMED=1):
#                           bundles packages/purse/bin/beat-phase2.ts with the pinned esbuild, renders
#                           bin/wren-beat with the bundle's sha256, ships the launcher, the bundle,
#                           run-flags.txt, the PicoClaw config template and the two beat units, and
#                           re-hashes them on the host before install. Starts NOTHING and enables
#                           no timer: that is --smoke's fourth and fifth gate.
#   --rebuild-image        rebuilds the image on the host from the committed tree (WREN_HOST,
#                           WREN_DEPLOY_CONFIRMED=1): the same tarball, the same on-host sha256
#                           check and the same build --create runs, and /srv/wren/image.env is
#                           rewritten with the new id, which the launcher pins the next beat to.
#   --status               reads back the timers, the newest state file, and the effective inbound
#                           ruleset for tag wren-v2 from the account.
#   --render-cloud-init    internal: prints the rendered user_data to stdout and exits. Used by
#                           --plan's ASCII/YAML preview and by test/host.test.mjs, so the
#                           substitution logic exists in exactly one place.
#
# Environment:
#   WREN_DEPLOY_CONFIRMED=1   required for --create. The Master's word, nothing else.
#   DO_TOKEN_FILE              path to the DigitalOcean token file (row 11, scoped, 90-day expiry).
#                               Never printed, even when set.
#   SSH_PUBLIC_KEY_FILE        path to the desk's SSH public key (row 1). It opens the one account
#                               cloud-init creates, `ops`.
#   WREN_DESK_IP              the one address the firewall admits on 22.
#   WREN_SSH_KEY_NAME         name to register the key under on the DigitalOcean account
#                               (default wren-ssh); told to the Master before it is registered.
#   WREN_HOST                 ops@<droplet ip>, for --seal/--smoke/--status. Validated before it
#                               reaches ssh, and passed after `--`: a value beginning with `-` is
#                               read by ssh as an option, and -oProxyCommand= is command execution
#                               on THIS laptop (Security's N-7).
#   WREN_PILE                 the desk's pile directory (default ~/.config/protocolx/wren).
#   REGION, SIZE, NAME         override the droplet's region/size/name.
#   WREN_NO_NETWORK=1         every function in this file that would touch the network refuses
#                               unless WREN_STUB_DIR names a directory holding a stand-in for it.
#                               This is how the tests run the create sequence -- including the
#                               destroy-on-failure path and --smoke's mail gate -- with no droplet.
#                               It is a TEST SEAM and nothing else: it cannot make a real deploy
#                               happen, and its absence no longer stops one.
#   WREN_STUB_DIR             the stand-in directory. Test-only; unset in every real run.
#   WREN_DO_API_BASE          lib/do_api.py only, and it accepts the real API or a loopback
#                               address and refuses anything else. The account token is sent with
#                               every call that file makes.
#   WREN_RUN_RECORD_DIR       where the run record is appended (default digitalocean/runs/).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(cd "$HERE/.." && pwd)"
RUNTIME_DIR="$(cd "$PKG_DIR/../agent-runtime" && pwd)"
CHECK_ASCII="$RUNTIME_DIR/scripts/check-ascii.py"
CLOUD_INIT="$HERE/cloud-init.yaml"
LIB_DIR="$HERE/lib"
POST_BOOT_ASSERT="$LIB_DIR/post-boot-assert.sh"
FIREWALL_MATCH="$LIB_DIR/firewall_match.py"
DO_API="$LIB_DIR/do_api.py"
SMOKE_ASSERT="$LIB_DIR/smoke-assert.sh"
TARBALL_SCRIPT="$RUNTIME_DIR/scripts/make-source-tarball.sh"
# The workspace that makes the image Wren's rather than Heron's. Shipped beside the runtime tarball
# as its own archive with its own sha256, verified on the host, and laid over the runtime's
# picoclaw/workspace before docker build. Nothing in packages/agent-runtime is edited for it.
WORKSPACE_DIR="$PKG_DIR/workspace"
AGENT_NAME="wren"
# Where the policy documents ship from. This package's policy/ in every real run. WREN_POLICY_DIR
# is a TEST SEAM and nothing else: it is read only under WREN_NO_NETWORK=1, the same gate every
# stubbed network call sits behind, so a fixture can stand in for documents that do not exist until
# Wren's keys and vault are born (her members document, her values with the vault id). A real run
# cannot be pointed at a fixture by setting it.
POLICY_DIR="$PKG_DIR/policy"
if [ "${WREN_NO_NETWORK:-}" = "1" ] && [ -n "${WREN_POLICY_DIR:-}" ]; then
  POLICY_DIR="$WREN_POLICY_DIR"
fi

REGION="${REGION:-fra1}"
SIZE="${SIZE:-s-1vcpu-512mb-10gb}"
NAME="${NAME:-wren-first}"
IMAGE_SLUG="debian-13-x64"
# The one tag in this file. The firewall targets it and the droplet is created carrying it, so the
# droplet is inside the firewall from its first second (Security's A1).
FIREWALL_TAG="wren-v2"
WREN_SSH_KEY_NAME="${WREN_SSH_KEY_NAME:-wren-ssh}"

# --install-purse. The purse package beside this one, and the node 22 the purse needs: @mysten/sui
# declares engines node>=22 and Debian 13 ships 20, so the official build goes under /opt/node22.
# The checksum is a literal read by hand from https://nodejs.org/dist/v22.23.2/SHASUMS256.txt on
# 2026-09-05 -- the same discipline as PicoClaw's checksum in the Dockerfile: no checksums file is
# fetched at install time from the place it is meant to verify.
PURSE_DIR="$(cd "$PKG_DIR/../purse" && pwd)"
NODE22_VERSION="22.23.2"
NODE22_SHA256="b294a556e639d64338823920e5866c21c02741742d2e1529ee1a225c1ec9252a"

# ---------------------------------------------------------------------------
# THE PRECONDITIONS, AS DATA. One row per check: <function>|<the sentence --plan prints>.
#
# --plan's numbered list and cmd_create's own loop are both generated from this array, so the
# document the Master reads before he says the word and the code that runs cannot say different
# things. That drift is Security's N-5 on the second read: --plan told him the image slug was
# asserted against the account's own GET /v2/images?type=distribution, and cmd_create called seven
# checks, none of them that one. The check exists now (check_image_slug), it is in this array, and
# test/host.test.mjs parses the array out of this file and the numbered list out of --plan's own
# output and refuses if they differ by one row.
#
# The first seven touch nothing outside this laptop. The last two are read-only GETs, and they run
# last so that a run which is going to be refused for a local reason is refused before it speaks to
# the account at all.
# ---------------------------------------------------------------------------
CREATE_PRECONDITIONS=(
  "check_confirmed|refuses unless WREN_DEPLOY_CONFIRMED=1 -- the Master's word, checked before anything else is even read"
  "check_ascii_rendered|refuses unless the RENDERED cloud-init passes scripts/check-ascii.py (never the template)"
  "check_git_clean|refuses unless \`git status --porcelain\` is empty for packages/wren and packages/agent-runtime; there must be a committed sha to name as what shipped"
  "check_tarball_set_equality|refuses unless the source tarball's entry set equals \`git ls-tree\` for packages/agent-runtime, exactly"
  "check_ssh_key_file|refuses unless SSH_PUBLIC_KEY_FILE exists"
  "check_do_token_file|refuses unless DO_TOKEN_FILE exists and is mode 0600"
  "check_desk_ip|refuses unless WREN_DESK_IP is set; the firewall has nothing to admit 22 from without it"
  "check_image_slug|refuses unless the image slug is listed in this account's own GET /v2/images?type=distribution (read-only)"
  "check_no_existing_firewall|refuses if any firewall on this account already targets tag wren-v2 (read-only)"
)

usage() {
  cat >&2 <<'EOF'
usage: deploy-droplet.sh --plan
       deploy-droplet.sh --create   (WREN_DEPLOY_CONFIRMED=1 required)
       deploy-droplet.sh --seal <name> [--dry-run]
       deploy-droplet.sh --smoke
       deploy-droplet.sh --install-purse   (WREN_HOST and WREN_DEPLOY_CONFIRMED=1 required)
       deploy-droplet.sh --install-beat    (WREN_HOST and WREN_DEPLOY_CONFIRMED=1 required)
       deploy-droplet.sh --rebuild-image   (WREN_HOST and WREN_DEPLOY_CONFIRMED=1 required)
       deploy-droplet.sh --status
EOF
}

# ---------------------------------------------------------------------------
# Rendering. One function, so --plan's preview, --create's real use and the test's fixture all
# read the exact same substitution -- the discipline the CTO spec names directly: v1's guard
# scanned the template, not what cloud-init was actually handed.
# ---------------------------------------------------------------------------
render_cloud_init() {
  local key_file="${SSH_PUBLIC_KEY_FILE:-}"
  local key_content
  if [ -n "$key_file" ] && [ -f "$key_file" ]; then
    key_content="$(cat "$key_file")"
  else
    # A placeholder that is itself pure ASCII, so --plan and the test can render and ASCII-check
    # the file with no key file on disk at all. --create refuses long before this matters (see
    # check_ssh_key_file), because SSH_PUBLIC_KEY_FILE is a required precondition there.
    key_content="ssh-ed25519 AAAAPLACEHOLDERPLACEHOLDERPLACEHOLDERPLACEHOLDERPLACEHOLDER wren-ssh-placeholder"
  fi
  sed "s#SSH_PUBLIC_KEY#${key_content}#g" "$CLOUD_INIT"
}

# ---------------------------------------------------------------------------
# The one seam every network call in this file passes through.
#
# There is no way to test "the deploy destroys the droplet when the post-boot check fails" without
# running the create sequence, and no way to run the create sequence on this laptop without
# something standing in for DigitalOcean and for SSH. So every function that touches the network
# asks this first. With WREN_NO_NETWORK=1 and a stub directory the call goes to the stub; with
# WREN_NO_NETWORK=1 and no stub directory it refuses loudly rather than reaching the network
# anyway; with neither it returns 1 and the caller makes the real call.
#
# It cannot be used to make a real deploy happen: cmd_create runs for real only behind
# WREN_DEPLOY_CONFIRMED=1 and its preconditions, and WREN_NO_NETWORK=1 alone refuses (T-2).
# ---------------------------------------------------------------------------
is_stubbed() {
  [ "${WREN_NO_NETWORK:-}" = "1" ] || return 1
  local caller="${FUNCNAME[1]}"
  if [ -z "${WREN_STUB_DIR:-}" ]; then
    echo "deploy-droplet.sh: refused - WREN_NO_NETWORK=1 is set and $caller makes a network call; there is no WREN_STUB_DIR to stand in for it" >&2
    exit 1
  fi
  if [ ! -x "$WREN_STUB_DIR/$caller" ]; then
    echo "deploy-droplet.sh: refused - WREN_NO_NETWORK=1 is set and $WREN_STUB_DIR/$caller does not exist or is not executable" >&2
    exit 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# The run record. One line per event, appended BEFORE the thing it describes happens -- so a
# rollback that is itself interrupted still leaves the droplet id it was about to destroy written
# down. v1 left running, billed hosts on the account with no record that they had ever existed.
# ---------------------------------------------------------------------------
RUN_RECORD_DIR="${WREN_RUN_RECORD_DIR:-$HERE/runs}"

record_run() {
  local event="$1" detail="${2:-}"
  mkdir -p "$RUN_RECORD_DIR"
  RECORD_EVENT="$event" RECORD_DETAIL="$detail" \
  RECORD_DROPLET="${WREN_DROPLET_ID:-}" RECORD_FIREWALL="${WREN_FIREWALL_ID:-}" \
  RECORD_NAME="$NAME" RECORD_REGION="$REGION" \
  python3 "$LIB_DIR/record-run.py" "$RUN_RECORD_DIR/deploy-runs.jsonl"
  echo "deploy-droplet.sh: recorded $event (droplet=${WREN_DROPLET_ID:-none} firewall=${WREN_FIREWALL_ID:-none}) in $RUN_RECORD_DIR/deploy-runs.jsonl" >&2
}

# ---------------------------------------------------------------------------
# The rollback. Armed the moment the first billable thing exists, disarmed only by success.
#
# Before this, ONE step carried `|| destroy_droplet`: the post-boot check. Every other way the
# sequence could stop -- the firewall call, the wait for an IP, the wait for SSH, the image build,
# a Ctrl-C -- aborted under `set -e` and left a running, billed, possibly half-firewalled host on
# the account with nothing written down anywhere (Security's B6 on step 6).
# ---------------------------------------------------------------------------
WREN_DROPLET_ID=""
WREN_FIREWALL_ID=""
WREN_FIREWALL_ID_FILE=""
WREN_DEPLOY_SUCCEEDED=0

rollback_on_failure() {
  local status=$?
  trap - EXIT
  if [ "$WREN_DEPLOY_SUCCEEDED" = "1" ]; then
    return 0
  fi
  # THE FIREWALL EXISTS BEFORE ITS ID IS ASSIGNED. `WREN_FIREWALL_ID="$(create_firewall)"` only
  # assigns when create_firewall EXITS 0, and its readback refusal exits 1 -- so a firewall the
  # deploy had already created was invisible to this trap, and stayed on the account with nothing
  # written down. Being tag-targeted, it also applied to the next droplet born with that tag
  # (Security's N-4 on the second read). do_api.py writes the id into this file the moment the POST
  # returns and deletes the firewall itself before exiting; this reads the same file, so a delete
  # that failed there is retried here rather than lost.
  if [ -z "$WREN_FIREWALL_ID" ] && [ -n "$WREN_FIREWALL_ID_FILE" ] && [ -s "$WREN_FIREWALL_ID_FILE" ]; then
    WREN_FIREWALL_ID="$(tr -d "\n" < "$WREN_FIREWALL_ID_FILE")"
    echo "deploy-droplet.sh: a firewall was created but never returned its id; recovered $WREN_FIREWALL_ID from the id file" >&2
  fi
  if [ -z "$WREN_DROPLET_ID" ] && [ -z "$WREN_FIREWALL_ID" ]; then
    return "$status"
  fi
  echo "deploy-droplet.sh: the deploy did not reach success (exit $status). Destroying what it made rather than leaving it running and billed." >&2
  record_run "rollback-begin" "exit $status"
  if [ -n "$WREN_DROPLET_ID" ]; then
    destroy_droplet "$WREN_DROPLET_ID" \
      || echo "deploy-droplet.sh: WARNING - destroying droplet $WREN_DROPLET_ID failed; it is still on the account and it is in the run record" >&2
  fi
  if [ -n "$WREN_FIREWALL_ID" ]; then
    delete_firewall "$WREN_FIREWALL_ID" \
      || echo "deploy-droplet.sh: WARNING - deleting firewall $WREN_FIREWALL_ID failed; it is still on the account and it is in the run record" >&2
  fi
  record_run "rollback-done" "exit $status"
  return "$status"
}

# ---------------------------------------------------------------------------
# --plan
# ---------------------------------------------------------------------------
# The numbered precondition list --plan prints, straight out of the array cmd_create loops over.
precondition_list() {
  local index=0 entry
  for entry in "${CREATE_PRECONDITIONS[@]}"; do
    index=$((index + 1))
    printf '  %2d. %s\n' "$index" "${entry#*|}"
  done
}

cmd_plan() {
  local desk_ip="${WREN_DESK_IP:-<unset - required for --create>}"
  local do_token_display="<unset - a file path, never printed even when set>"
  local ssh_key_display="<unset - the desk's SSH public key file>"
  [ -n "${DO_TOKEN_FILE:-}" ] && do_token_display="$DO_TOKEN_FILE (path only; contents never read by --plan)"
  [ -n "${SSH_PUBLIC_KEY_FILE:-}" ] && ssh_key_display="$SSH_PUBLIC_KEY_FILE (path only; contents never printed by --plan)"

  # The header of this file has always said --plan renders and ASCII-checks the cloud-init; it did
  # not (Security's note N4). It does now, on the RENDERED copy -- the same bytes --create hands to
  # the API, not the template -- and --plan exits non-zero if that check fails, because a plan whose
  # own user_data would make cloud-init apply nothing is not a plan, it is v1.
  local rendered_tmp rendered_bytes ascii_verdict ascii_status
  rendered_tmp="$(mktemp)"
  render_cloud_init > "$rendered_tmp"
  rendered_bytes="$(wc -c < "$rendered_tmp" | tr -d " ")"
  ascii_status=0
  if ascii_verdict="$(python3 "$CHECK_ASCII" "$rendered_tmp" 2>&1)"; then
    ascii_verdict="PASS - every one of the $rendered_bytes rendered bytes is <= 0x7F${ascii_verdict:+ ($ascii_verdict)}"
  else
    ascii_verdict="FAIL - $ascii_verdict"
    ascii_status=1
  fi
  rm -f "$rendered_tmp"

  cat <<PLAN
deploy-droplet.sh --plan: everything --create would do. No API call is made. Nothing exists yet.

== Droplet (created only by --create, only with WREN_DEPLOY_CONFIRMED=1) ==
  name:        $NAME
  region:      $REGION
  size:        $SIZE (\$4.00/month)
  image slug:  $IMAGE_SLUG
               pinned explicitly (v1's script said debian-12-x64 while its own notes said
               Debian 13); asserted after boot by reading /etc/debian_version over SSH, and by
               check_image_slug, which reads this account's own
               GET /v2/images?type=distribution and refuses if the slug is not listed. That is a
               real precondition now: it was this line's claim and nothing else until Security's
               second read (N-5), which is why the preconditions below are printed from the same
               array cmd_create loops over.
  monitoring:  false (do-agent is never installed; cloud-init purges it defensively if present)
  ssh key:     $WREN_SSH_KEY_NAME
               registered on the DigitalOcean account under this exact name if not already
               present, before create -- the name the Master sees first, per the key ledger.
  do token:    $do_token_display
  ssh pubkey:  $ssh_key_display

== Firewall (created FIRST, before the droplet exists, and targeted by tag) ==
  name:      $NAME-fw
  targets:   tag wren-v2 -- and the droplet is created carrying that tag, so it is inside the
             firewall from its first second. v1's order was droplet-then-firewall, which left the
             host's sshd on the public internet with no cloud firewall for the length of one API
             call: key-only auth guarded that window, but one control rather than two, and
             nothing asserted it.
  inbound:   tcp/22 from $desk_ip only
  outbound:  tcp/443 (fullnode, Resend, apt) and tcp/53 + udp/53 (DNS)
  no other rule, inbound or outbound
  readback:  the API's own echo is compared on protocol, ports, the sorted address list AND the
             three other ways a source or a destination can be widened -- droplet_ids, tags and
             load_balancer_uids, every one of which must be EMPTY in every rule. Both directions,
             as multisets, so a rule the deploy never asked for is a mismatch as loudly as a
             missing one. It is NOT compared as raw objects: DigitalOcean echoes all four
             source/destination keys while the request sends one, which made a correct firewall
             compare unequal every time. The three lists used to be dropped, which meant an echo
             of tcp/22 whose sources carried tags:["wren-v2"] -- a whole tag admitted to port 22
             -- read as a clean match (Security's N-3). lib/firewall_match.py, tested directly.
  on failure: if the readback does not match, lib/do_api.py DELETES the firewall it just created,
             inside the same call, before it exits non-zero -- and the id is written to a file the
             moment the POST returns, so the rollback trap covers it even then. Before this, that
             id never reached the caller and a firewall the deploy made stayed on the account with
             nothing written down, applying to the next droplet born with the tag (N-4).
  before it:  --create refuses at precondition time if any firewall on this account already
             targets this tag.

== The rendered cloud-init, checked here rather than described ==
  rendered bytes: $rendered_bytes
  ASCII guard:    $ascii_verdict
  (scripts/check-ascii.py over the RENDERED user_data, never the template. One byte above 0x7F
   makes cloud-init refuse the whole document and apply NOTHING, which is how v1 booted with root
   open. --plan exits non-zero if this line says FAIL.)

== Host paths (created by cloud-init's runcmd, all before any secret is placed) ==
  /srv/wren                          0751 root:root   (o+x is traversal only, no o+r: the purse
                                                        account is not in group root and must be
                                                        able to reach its own program below)
  /srv/wren/bin                      0755 root:root   (wren-beat, placed at build order step 5)
  /srv/wren/runs                     2770 root:wren  (beat logs AND runs/<beat-id>/intent.json)
  /srv/wren/runs/archive             2770 root:wren  (wren-retention's destination)
  /srv/wren/state                    2770 root:wren  (latest.json and beats.jsonl. NOT the
                                                        watchdog's record any more: this directory
                                                        is bind-mounted read-write into the model's
                                                        container as uid 10001, the group that owns
                                                        it, and the container could forge the
                                                        marker that silences the dead man watching
                                                        it -- Security's N-1 and N-2)
  /srv/wren/keys                     0700 purse:purse (the hot key's home. Created here, at an
                                                        asserted mode, rather than by hand at
                                                        deploy time by whoever noticed first)
  /srv/wren/purse                    0750 purse:purse
  /srv/wren/purse/dist               0750 purse:purse (the signer's compiled server, step 5)
  /srv/wren/policy                   0755 root:root   (world-readable on purpose: the policy is
                                                        pinned by hash in wren-purse.service and
                                                        a rule nobody can read is not a rule)
  /var/lib/wren                      0700 purse:purse (the hash-chained audit log's home)
  /var/lib/wren/audit                0700 purse:purse
  /var/lib/wren-ledger               0700 ledger:ledger (the settlement signer's own audit chain,
                                                        unreadable by the content purse)
  /var/lib/wren-ledger/audit         0700 ledger:ledger
  /var/lib/wren-ledger/state         0700 ledger:ledger (the vault balance seen at the last
                                                        settlement. Read as zero it would book the
                                                        whole vault as one epoch's earnings)
  /var/lib/wren/watchdog             0700 root:root   (the dead man's own memory: alerts.jsonl and
                                                        the degraded marker. Root's alone, outside
                                                        every mount the container is given)
  /srv/wren/image.env                0600 root:root   (empty placeholder; --create writes the
                                                        pinned digest, commit and tarball sha256
                                                        after the host build)
  /srv/wren/chain.json               0600 purse:purse (empty placeholder; wren-purse.service
                                                        names it as --chain and reads it AS purse
                                                        at start. It was created by nothing, and at
                                                        root:root under a 0751 parent the signer
                                                        cannot open it, refuses to start, and the
                                                        beat unit that Requires= it never runs --
                                                        Security's N-6. Build order step 8 writes
                                                        the deployment into it)
  /etc/wren                          0700 root:root
  /etc/wren/creds                    0700 root:root   (the ONE sealed-credential directory on
                                                        this host. Every unit, --seal, the README
                                                        and this plan name it and nothing else)
  /etc/ssh/sshd_config.d/00-wren.conf  0644 root:root (sorts before cloud-init's 50-cloud-init.conf)
  /etc/apt/apt.conf.d/20auto-upgrades   0644 root:root (unattended-upgrades actually enabled, and
                                                        asserted out of apt-config dump in runcmd)
  /etc/systemd/journald.conf.d/00-wren.conf 0644 root:root (SystemMaxUse=200M; logrotate cannot
                                                        rotate the journal, journald bounds itself)
  /etc/logrotate.d/wren              0644 root:root   (installed by --create with the units. It
                                                        bounds /srv/wren/state/beats.jsonl and
                                                        /var/lib/wren/watchdog/alerts.jsonl and
                                                        nothing else -- runs/ is wren-retention's,
                                                        because a per-beat file is the shape
                                                        rotate N cannot bound. That was v1's
                                                        defect 8b)

== Accounts (created by cloud-init only after it asserts both ids are free, and re-asserted after) ==
  wren   gid 10001 / uid 10001  nologin, no home   the uid the container runs as; owns nothing
                                                    but the group on runs/ and state/
  purse   gid 10002 / uid 10002  nologin, no home   wren-purse.service's User=/Group=. The only
                                                    account on this host that ever holds the hot
                                                    key. It was created by nothing before this
                                                    fix: the signer would not start, the beat
                                                    unit Requires= it and so would never run, and
                                                    a hand-made account lands on whatever id is
                                                    free -- the uid collision that scrapped v1,
                                                    this time on the key's own account.
  ledger  gid 10003 / uid 10003  nologin, no home   wren-ledger-purse.service's User=/Group=. The
                                                    settlement signer, and a separate account
                                                    rather than a second policy on 10002: two
                                                    policies under one uid share a credential
                                                    directory, and "one signer per money path"
                                                    would then be a claim about argv rather than
                                                    about the kernel. The settlement key closes
                                                    epochs and books the books and can price
                                                    nothing; the content key prices content and
                                                    records spends and can settle nothing.
  purse is NOT in the wren group and wren is NOT in the purse group; the post-boot check asserts it.
  ops     a login account with NOPASSWD:ALL, said plainly: the desk's SSH key is root on this host.
          disable_root:true bounds the direct-root path only; the bound that matters is the
          firewall and the key living in the Master's own agent. v1's second account, wren-ops,
          carried the same key, was used by nothing, and is removed -- one door.

== Credentials this step seals (ledger row per credential; no value is ever printed) ==
  name       purpose                          source pile                              destination                     mode  encryption                             revocation
  mail-key   send-only Resend key for alerts  ~/.config/protocolx/wren/mail-key        /etc/wren/creds/mail-key.cred  0600  systemd-creds encrypt --with-key=host  revoke at Resend; --seal mail-key again with a fresh key

  The mode row says 0600 because that is what systemd-creds actually writes; this plan said 0400,
  which was a number nobody had read off a host (Security's note N6). What systemd decrypts into
  \$CREDENTIALS_DIRECTORY at unit start is 0400, and that is a different file.

  wren-hot, wren-policy and the OpenRouter model key are build order steps 4 and 8's rows; this
  step only builds the --seal mechanism they will use, unchanged, once those keys exist. Nothing
  in this step generates, reads or touches any of them.

== What --create does ==
  Preconditions first, each one a refusal that names the rule it enforces, in this order. This
  list and the loop cmd_create actually runs are generated from ONE array in this file
  (CREATE_PRECONDITIONS), and a test parses both and refuses if they differ by a row -- because
  this list once named a check the script did not have (Security's N-5).
$(precondition_list)
  Then, and only then:
   A. creates the FIREWALL first, targeted at tag $FIREWALL_TAG, and reads it back through
      lib/firewall_match.py -- refusing on any difference in protocol, ports, addresses or the
      three widening lists, in either direction, and deleting the firewall it just made before it
      exits.
   B. from the line before that call a rollback trap is armed, and it stays armed until the deploy
      declares success: ANY failure or interrupt below destroys the droplet and deletes the
      firewall, after writing the ids to digitalocean/runs/deploy-runs.jsonl first.
   C. registers the SSH key if needed, then creates the droplet with monitoring:false, the rendered
      user_data and the $FIREWALL_TAG tag -- so it is born inside the firewall.
   D. waits for an active public IP, then for SSH.
   E. pipes lib/post-boot-assert.sh over that session. It asserts: cloud-init status --wait --long
      is "status: done" with an empty error list; cloud-init schema --system passes; uid/gid 10001
      is wren and 10002 is purse, and purse is not in the wren group; /etc/debian_version starts
      with 13; /usr/bin/node is executable, and its version is printed; /etc/nsswitch.conf pins
      "hosts: files dns"; 00-wren.conf sorts first in sshd_config.d and the three hardening
      keywords read "no" out of sshd -T's own merged output; every DIRECTORY in the table above at
      its owner and mode; the modes of the three files /srv/wren/image.env, /srv/wren/chain.json
      and /etc/ssh/sshd_config.d/00-wren.conf; and that no credential-shaped file exists anywhere
      under /srv/wren. It asserts no other file's mode, and this sentence says so rather than
      claiming "every path above" -- which is what it used to say while asserting thirteen
      directories and not one file (Security's N-5).
   F. copies the source tarball, verifies its sha256 ON THE HOST before docker build reads it,
      builds the image there, writes /srv/wren/image.env with the image id, the source commit and
      that sha256.
   G. installs digitalocean/systemd/*.{service,timer} to /etc/systemd/system,
      digitalocean/bin/wren-{watchdog,alert,retention} to /usr/local/sbin (0755 root:root) and
      logrotate/wren to /etc/logrotate.d, then \`systemctl daemon-reload\` -- and enables NO timer.
      --smoke is the only thing that ever does that.

== What --create does NOT do ==
  It does not enable a timer, seal a credential, generate or read a key, or place any key material:
  build order steps 7, 8 and 9 do those, in that order, and --seal is the only path a credential
  ever takes onto this host.

  It no longer refuses unconditionally. Until Security's second read of this step, --create stopped
  before its first API call unless WREN_NO_NETWORK=1 was set, which made the sequence above
  unreachable in any real run. The gate is now the Master's word (WREN_DEPLOY_CONFIRMED=1) and the
  preconditions above, and nothing else. WREN_NO_NETWORK=1 is still the test seam and still cannot
  make a real deploy happen: under it every network call goes to a stub directory or refuses.
PLAN
  return "$ascii_status"
}

# ---------------------------------------------------------------------------
# --create preconditions. Each is one function, each fails loud with the rule it enforces named,
# so a test can call the ones that need no network in isolation.
# ---------------------------------------------------------------------------
check_confirmed() {
  if [ "${WREN_DEPLOY_CONFIRMED:-}" != "1" ]; then
    echo "deploy-droplet.sh: refused - WREN_DEPLOY_CONFIRMED is not 1. Nothing was run. This word is the Master's alone." >&2
    return 1
  fi
}

check_ascii_rendered() {
  local tmp
  tmp="$(mktemp)"
  render_cloud_init > "$tmp"
  if ! python3 "$CHECK_ASCII" "$tmp"; then
    rm -f "$tmp"
    echo "deploy-droplet.sh: refused - the RENDERED cloud-init failed the ASCII check above; cloud-init would apply nothing (this is the exact defect Heron v1 shipped)" >&2
    return 1
  fi
  rm -f "$tmp"
}

check_git_clean() {
  local status
  # Scoped to this package, like make-source-tarball.sh: the workspace gate rebuilds tracked
  # source maps in other packages before the tests run, and those are not what ships.
  status="$(git -C "$PKG_DIR" status --porcelain -- .; git -C "$RUNTIME_DIR" status --porcelain -- .)"
  if [ -n "$status" ]; then
    echo "deploy-droplet.sh: refused - git status --porcelain is not empty; there is no committed sha to name as what shipped" >&2
    echo "$status" >&2
    return 1
  fi
}

check_tarball_set_equality() {
  if [ ! -x "$TARBALL_SCRIPT" ]; then
    echo "deploy-droplet.sh: refused - $TARBALL_SCRIPT is missing or not executable" >&2
    return 1
  fi
  ( cd "$RUNTIME_DIR" && "$TARBALL_SCRIPT" ) || {
    echo "deploy-droplet.sh: refused - make-source-tarball.sh itself refused (see its own message above)" >&2
    return 1
  }
  local tgz="$RUNTIME_DIR/agent-runtime-src.tgz"
  local repo_root
  repo_root="$(git -C "$RUNTIME_DIR" rev-parse --show-toplevel)"
  local tar_entries git_entries
  tar_entries="$(mktemp)"
  git_entries="$(mktemp)"
  tar -tf "$tgz" | grep -v '/$' | grep -v '^SOURCE_COMMIT$' | sort > "$tar_entries"
  git -C "$repo_root" ls-tree -r --name-only HEAD -- packages/agent-runtime | sort > "$git_entries"
  if ! diff -q "$tar_entries" "$git_entries" >/dev/null; then
    echo "deploy-droplet.sh: refused - the tarball's entry set does not equal git ls-tree for packages/agent-runtime" >&2
    diff "$tar_entries" "$git_entries" >&2 || true
    rm -f "$tar_entries" "$git_entries"
    return 1
  fi
  rm -f "$tar_entries" "$git_entries"
}

check_ssh_key_file() {
  if [ -z "${SSH_PUBLIC_KEY_FILE:-}" ] || [ ! -f "$SSH_PUBLIC_KEY_FILE" ]; then
    echo "deploy-droplet.sh: refused - SSH_PUBLIC_KEY_FILE is unset or does not exist" >&2
    return 1
  fi
}

check_do_token_file() {
  if [ -z "${DO_TOKEN_FILE:-}" ] || [ ! -f "$DO_TOKEN_FILE" ]; then
    echo "deploy-droplet.sh: refused - DO_TOKEN_FILE is unset or does not exist" >&2
    return 1
  fi
  local mode
  mode="$(stat -f %Lp "$DO_TOKEN_FILE" 2>/dev/null || stat -c %a "$DO_TOKEN_FILE")"
  if [ "$mode" != "600" ]; then
    echo "deploy-droplet.sh: refused - DO_TOKEN_FILE ($DO_TOKEN_FILE) is mode $mode, not 0600" >&2
    return 1
  fi
}

check_desk_ip() {
  if [ -z "${WREN_DESK_IP:-}" ]; then
    echo "deploy-droplet.sh: refused - WREN_DESK_IP is unset; the firewall has nothing to admit 22 from" >&2
    return 1
  fi
}

# The first of the two read-only account reads. --plan has always told the Master this check
# existed; it did not (Security's N-5). It does now, and it is the same sentence in both places
# because both come from CREATE_PRECONDITIONS.
check_image_slug() {
  if is_stubbed; then "$WREN_STUB_DIR/check_image_slug" "$@"; return; fi
  if ! python3 "$DO_API" image-slug "$DO_TOKEN_FILE" "$IMAGE_SLUG"; then
    echo "deploy-droplet.sh: refused - the image slug $IMAGE_SLUG is not listed in this account's own GET /v2/images?type=distribution (see do_api.py's message above). Nothing was created." >&2
    return 1
  fi
}

# The second. A firewall already targeting wren-v2 is either a leftover this deploy's own rollback
# could not delete, or a rule set nobody wrote down -- and either way it applies to the droplet this
# run is about to create, alongside the new one (Security's N-4).
check_no_existing_firewall() {
  if is_stubbed; then "$WREN_STUB_DIR/check_no_existing_firewall" "$@"; return; fi
  if ! python3 "$DO_API" firewall-none "$DO_TOKEN_FILE" "$FIREWALL_TAG"; then
    echo "deploy-droplet.sh: refused - a firewall on this account already targets tag $FIREWALL_TAG (see do_api.py's list above). Nothing was created." >&2
    return 1
  fi
}

# ---------------------------------------------------------------------------
# The one place an SSH target is checked, and every mode that has one uses it.
#
# --seal validated the credential name and then handed $WREN_HOST to ssh unvalidated: a value
# beginning with `-` is read by ssh as an OPTION, and `-oProxyCommand=...` is command execution on
# THIS laptop (Security's N-7 -- A2's own class, one machine to the left). Desk-set, so low, but the
# fix is one function and every caller passes the target after `--` as well, so ssh cannot read it
# as an option even if this were somehow reached.
# ---------------------------------------------------------------------------
validate_ssh_target() {
  local target="$1" what="${2:-WREN_HOST}"
  case "$target" in
    -*)
      echo "deploy-droplet.sh: refused - $what is '$target', which begins with '-'. ssh reads a leading hyphen as an option, and -oProxyCommand= runs a command on this laptop." >&2
      return 1
      ;;
  esac
  if ! [[ "$target" =~ ^([a-z][a-z0-9_-]{0,31}@)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]]; then
    echo "deploy-droplet.sh: refused - $what is '$target'. It must be [user@]host: lower-case letters, digits, dots and hyphens only, no leading or trailing hyphen or dot, and no other character at all." >&2
    return 1
  fi
}

# ---------------------------------------------------------------------------
# --create. Preconditions first, in the order --plan documents; network only after every one
# passes. WREN_DEPLOY_CONFIRMED is checked before anything else is even read, so a caller with
# no other environment set gets exactly one, unambiguous refusal.
# ---------------------------------------------------------------------------
cmd_create() {
  # One loop over CREATE_PRECONDITIONS, which is the same array --plan numbers. Under `set -e` a
  # check that returns non-zero stops the run here, having printed the rule it enforces; nothing
  # below has happened and nothing exists to roll back.
  local entry check
  for entry in "${CREATE_PRECONDITIONS[@]}"; do
    check="${entry%%|*}"
    "$check"
  done

  echo "deploy-droplet.sh --create: all ${#CREATE_PRECONDITIONS[@]} preconditions passed, in the order --plan prints them." >&2

  # THE GATE, and it is now one thing: WREN_DEPLOY_CONFIRMED=1, checked first in the array above.
  #
  # What used to stand here was an unconditional refusal unless WREN_NO_NETWORK=1 was set, which
  # made the whole sequence below unreachable in any real run -- and Security's second read said
  # plainly that lifting it is itself a code change and belongs in the same branch as N-1 to N-5.
  # It is that branch. WREN_NO_NETWORK remains the test seam and nothing else: with it set, every
  # call below goes to a stub directory or refuses outright (see is_stubbed), so it still cannot
  # make a real deploy happen -- it just no longer has to be present for one.
  create_sequence
}

# The sequence itself, as its own function, so the trap's scope is exactly the window in which
# something billable exists.
create_sequence() {
  local key_id droplet_ip

  # THE FIREWALL FIRST, and by tag (Security's A1). v1's order was droplet-then-firewall, which
  # left the host's sshd on the public internet with no cloud firewall for as long as the second
  # call took. Key-only auth means that window was guarded, but it was guarded by one control
  # rather than two and nothing asserted it. A tag-targeted firewall applies to any droplet
  # carrying the tag from the moment the droplet exists, so the window closes entirely: the
  # droplet is born inside it.
  record_run "create-begin" "firewall first, then droplet"

  # ARMED BEFORE THE FIRST BILLABLE CALL, not after it. The id file is what makes that possible: a
  # firewall whose readback fails never returns an id to assign, so arming the trap on the line
  # after the assignment left exactly one billable thing outside the window it claims to cover.
  WREN_FIREWALL_ID_FILE="$(mktemp)"
  export WREN_FIREWALL_ID_FILE
  trap rollback_on_failure EXIT

  WREN_FIREWALL_ID="$(create_firewall)"
  record_run "firewall-created"

  key_id="$(register_ssh_key)"
  WREN_DROPLET_ID="$(create_droplet "$key_id")"
  record_run "droplet-created"

  droplet_ip="$(wait_for_droplet_ip "$WREN_DROPLET_ID")"
  wait_for_ssh "$droplet_ip"
  assert_post_boot "$droplet_ip"
  build_image_on_host "$droplet_ip"
  install_host_units "$droplet_ip"

  # Only here. Anything above this line that fails, for any reason, takes the rollback.
  WREN_DEPLOY_SUCCEEDED=1
  record_run "create-succeeded" "$droplet_ip"
  trap - EXIT
  rm -f "$WREN_FIREWALL_ID_FILE"
  echo "deploy-droplet.sh --create: droplet $WREN_DROPLET_ID at $droplet_ip is up, cloud-init succeeded, the image is built, firewall $WREN_FIREWALL_ID reads back clean. No timer is enabled. Next: --seal mail-key, then build order step 5's units, then --smoke."
}

# ---------------------------------------------------------------------------
# The functions --create calls once every precondition passes. Written and reviewed; never run
# by this step (cmd_create has no early return; it refuses on the word and on each precondition).
# ---------------------------------------------------------------------------
register_ssh_key() {
  if is_stubbed; then "$WREN_STUB_DIR/register_ssh_key" "$@"; return; fi
  python3 - "$DO_TOKEN_FILE" "$WREN_SSH_KEY_NAME" "$SSH_PUBLIC_KEY_FILE" <<'PY'
import json, sys, urllib.request
token, name, key_file = sys.argv[1], sys.argv[2], sys.argv[3]
tok = open(token).read().strip()
pubkey = open(key_file).read().strip()
headers = {"Authorization": "Bearer " + tok, "Content-Type": "application/json"}

req = urllib.request.Request("https://api.digitalocean.com/v2/account/keys", headers=headers)
with urllib.request.urlopen(req, timeout=30) as r:
    existing = json.load(r).get("ssh_keys", [])
for k in existing:
    if k.get("name") == name or k.get("public_key", "").strip() == pubkey:
        print(k["id"]); sys.exit(0)

body = json.dumps({"name": name, "public_key": pubkey}).encode()
req = urllib.request.Request("https://api.digitalocean.com/v2/account/keys", data=body, headers=headers, method="POST")
with urllib.request.urlopen(req, timeout=30) as r:
    print(json.load(r)["ssh_key"]["id"])
PY
}

create_droplet() {
  if is_stubbed; then "$WREN_STUB_DIR/create_droplet" "$@"; return; fi
  local key_id="$1"
  local user_data
  user_data="$(render_cloud_init)"
  python3 - "$DO_TOKEN_FILE" "$NAME" "$REGION" "$SIZE" "$IMAGE_SLUG" "$key_id" "$user_data" <<'PY'
import json, sys, urllib.request
tok = open(sys.argv[1]).read().strip()
name, region, size, image, key_id, user_data = sys.argv[2:8]
body = {
    "name": name, "region": region, "size": size, "image": image,
    "ssh_keys": [int(key_id)], "monitoring": False, "user_data": user_data,
    # wren-v2 is not decoration: the firewall created before this call targets that tag, so the
    # droplet is inside the firewall from its first second rather than from a second API call.
    "tags": ["wren", "wren-v2"],
}
req = urllib.request.Request(
    "https://api.digitalocean.com/v2/droplets",
    data=json.dumps(body).encode(),
    headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=30) as r:
    print(json.load(r)["droplet"]["id"])
PY
}

create_firewall() {
  if is_stubbed; then "$WREN_STUB_DIR/create_firewall" "$@"; return; fi
  # The whole call -- POST, id recorded, readback through lib/firewall_match.py, and DELETE of the
  # firewall it just made if that readback does not match -- is lib/do_api.py, because as a heredoc
  # here the one path that mattered most could not be run anywhere. It is run end to end against a
  # local HTTP server that answers like DigitalOcean in test/host.test.mjs.
  python3 "$DO_API" firewall-create \
    "$DO_TOKEN_FILE" "$WREN_DESK_IP" "$NAME" "$FIREWALL_TAG" "$FIREWALL_MATCH" \
    --id-file "$WREN_FIREWALL_ID_FILE"
}

delete_firewall() {
  if is_stubbed; then "$WREN_STUB_DIR/delete_firewall" "$@"; return; fi
  local firewall_id="$1"
  echo "deploy-droplet.sh: deleting firewall $firewall_id" >&2
  python3 - "$DO_TOKEN_FILE" "$firewall_id" <<'PY'
import sys, urllib.request
tok = open(sys.argv[1]).read().strip()
req = urllib.request.Request(
    f"https://api.digitalocean.com/v2/firewalls/{sys.argv[2]}",
    headers={"Authorization": "Bearer " + tok}, method="DELETE",
)
urllib.request.urlopen(req, timeout=30)
PY
}

wait_for_droplet_ip() {
  if is_stubbed; then "$WREN_STUB_DIR/wait_for_droplet_ip" "$@"; return; fi
  local droplet_id="$1"
  python3 - "$DO_TOKEN_FILE" "$droplet_id" <<'PY'
import json, sys, time, urllib.request
tok = open(sys.argv[1]).read().strip()
droplet_id = sys.argv[2]
headers = {"Authorization": "Bearer " + tok}
for _ in range(60):
    req = urllib.request.Request(f"https://api.digitalocean.com/v2/droplets/{droplet_id}", headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        d = json.load(r)["droplet"]
    if d["status"] == "active":
        for net in d["networks"]["v4"]:
            if net["type"] == "public":
                print(net["ip_address"]); sys.exit(0)
    time.sleep(5)
print("TIMED OUT WAITING FOR AN ACTIVE PUBLIC IP", file=sys.stderr)
sys.exit(1)
PY
}

wait_for_ssh() {
  if is_stubbed; then "$WREN_STUB_DIR/wait_for_ssh" "$@"; return; fi
  local ip="$1"
  local tries=0
  validate_ssh_target "ops@$ip" "the droplet address the API returned"
  until ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -- "ops@$ip" true 2>/dev/null; do
    tries=$((tries + 1))
    if [ "$tries" -gt 60 ]; then
      echo "deploy-droplet.sh: refused - SSH never became reachable at $ip" >&2
      return 1
    fi
    sleep 5
  done
}

assert_post_boot() {
  if is_stubbed; then "$WREN_STUB_DIR/assert_post_boot" "$@"; return; fi
  local ip="$1"
  # The assertions are a FILE, piped over the session, not a heredoc written here. As a heredoc
  # they were a block that only ever ran on a host nobody had built, and every line in them that
  # needed root ran without it: `sshd -T` is in /usr/sbin (off a non-root PATH) and reads
  # 0600 root host keys, `cloud-init status`/`schema --system` read root-only state. Under the
  # heredoc's own `set -euo pipefail` the first of those failures propagated and the deploy
  # destroyed every droplet it created, seconds after boot, while never once reading the three
  # hardening keywords it claimed to assert (Security's B4). lib/post-boot-assert.sh carries sudo
  # on every privileged line and is exercised against a fixture on this laptop by
  # test/host-fixes.test.mjs.
  validate_ssh_target "ops@$ip" "the droplet address the API returned"
  ssh -- "ops@$ip" bash -s < "$POST_BOOT_ASSERT"
}

destroy_droplet() {
  if is_stubbed; then "$WREN_STUB_DIR/destroy_droplet" "$@"; return; fi
  local droplet_id="$1"
  echo "deploy-droplet.sh: destroying droplet $droplet_id rather than leaving a half-built, billed host on the account" >&2
  python3 - "$DO_TOKEN_FILE" "$droplet_id" <<'PY'
import sys, urllib.request
tok = open(sys.argv[1]).read().strip()
req = urllib.request.Request(
    f"https://api.digitalocean.com/v2/droplets/{sys.argv[2]}",
    headers={"Authorization": "Bearer " + tok}, method="DELETE",
)
urllib.request.urlopen(req, timeout=30)
PY
}

build_image_on_host() {
  if is_stubbed; then "$WREN_STUB_DIR/build_image_on_host" "$@"; return; fi
  local ip="$1"
  "$TARBALL_SCRIPT"

  # The tarball's own sha256, computed here and checked there. Nothing asserted that what landed on
  # the host was what left this laptop before `docker build` read it (Security's note N5); the
  # committed sidecar names the COMMIT the tarball was built from, which is provenance, not
  # integrity. Both travel: the sha256 is what the host verifies, SOURCE_COMMIT inside the archive
  # is what a copy that has left this laptop still carries.
  local tgz="$RUNTIME_DIR/agent-runtime-src.tgz"
  local sha256
  sha256="$(shasum -a 256 "$tgz" | cut -d' ' -f1)"
  echo "deploy-droplet.sh: runtime tarball sha256 $sha256 (commit $(cat "$RUNTIME_DIR/agent-runtime-src.sha"))" >&2

  # THE WORKSPACE, as its own archive. The image's mind is the shared runtime; what makes it Wren
  # is workspace/ in this package. It travels with its own sha256 and is laid over the runtime's
  # picoclaw/workspace on the host, before docker build reads the tree. The runtime tarball is
  # git-archive of a committed tree; this one is tar of a committed tree (check_git_clean covers
  # this package too), reproducible by construction: sorted names, fixed mtime, fixed owner.
  # lib/make-workspace-tarball.py, not tar: macOS's bsdtar has no --mtime and the first real
  # --create (2026-09-06) died here on the laptop after the droplet was already up. The script is
  # run on this laptop by test/wren.test.mjs, twice, and the two archives must be identical.
  local ws_tgz ws_sha256 ws_count
  ws_tgz="$(mktemp "${TMPDIR:-/tmp}/wren-workspace.XXXXXX")"
  ws_count="$(python3 "$LIB_DIR/make-workspace-tarball.py" "$WORKSPACE_DIR" "$ws_tgz")"
  ws_sha256="$(shasum -a 256 "$ws_tgz" | cut -d' ' -f1)"
  echo "deploy-droplet.sh: workspace tarball sha256 $ws_sha256 ($ws_count files from packages/wren/workspace)" >&2

  validate_ssh_target "ops@$ip" "the droplet address the API returned"
  scp -- "$tgz" "ops@$ip:/tmp/agent-runtime-src.tgz"
  scp -- "$ws_tgz" "ops@$ip:/tmp/wren-workspace.tgz"
  rm -f "$ws_tgz"
  # shellcheck disable=SC2087
  ssh -- "ops@$ip" sudo bash -s <<REMOTE
set -euo pipefail
ACTUAL="\$(sha256sum /tmp/agent-runtime-src.tgz | cut -d' ' -f1)"
if [ "\$ACTUAL" != "$sha256" ]; then
  echo "host: refused - the runtime tarball on this host hashes \$ACTUAL, not $sha256; nothing is built from it" >&2
  exit 1
fi
echo "host: runtime tarball sha256 verified: \$ACTUAL"
WS_ACTUAL="\$(sha256sum /tmp/wren-workspace.tgz | cut -d' ' -f1)"
if [ "\$WS_ACTUAL" != "$ws_sha256" ]; then
  echo "host: refused - the workspace tarball on this host hashes \$WS_ACTUAL, not $ws_sha256; nothing is built from it" >&2
  exit 1
fi
echo "host: workspace tarball sha256 verified: \$WS_ACTUAL"
rm -rf /tmp/agent-runtime-src && mkdir -p /tmp/agent-runtime-src
tar -xzf /tmp/agent-runtime-src.tgz -C /tmp/agent-runtime-src
SHIPPED_COMMIT="\$(cat /tmp/agent-runtime-src/SOURCE_COMMIT)"
echo "host: building from commit \$SHIPPED_COMMIT"
# The docker client writes its config, buildx state and token seed under \$HOME/.docker. Run as root
# that is /root/.docker, which wren-beat.service (ProtectHome=yes) cannot see and the smoke's
# first gate refuses (twice on 2026-09-05, after the create and after the rebuild). The client
# is pointed at a directory that goes away with the build.
export DOCKER_CONFIG=/tmp/wren-docker-config
rm -rf "\$DOCKER_CONFIG" && mkdir -m 0700 "\$DOCKER_CONFIG"
# git archive keeps the repository path, so the package sits at packages/agent-runtime inside the
# tarball; the fourth real run (2026-09-05) built the extraction root and found no Dockerfile.
BUILD_DIR="\$(dirname "\$(find /tmp/agent-runtime-src -type f -name Dockerfile -path '*/agent-runtime/*' | head -1)")"
[ -f "\$BUILD_DIR/Dockerfile" ] || { echo "host: no Dockerfile under /tmp/agent-runtime-src" >&2; exit 1; }
echo "host: build directory \$BUILD_DIR"
# The overlay: Heron's workspace out, Wren's in, and the result asserted to carry no file the
# runtime shipped -- so the image cannot be built with a mixed mind by a half-extracted archive.
rm -rf "\$BUILD_DIR/picoclaw/workspace" && mkdir -p "\$BUILD_DIR/picoclaw/workspace"
tar -xzf /tmp/wren-workspace.tgz -C "\$BUILD_DIR/picoclaw/workspace"
for f in SOUL.md IDENTITY.md AGENT.md HEARTBEAT.md skills/weir-agent/SKILL.md; do
  [ -f "\$BUILD_DIR/picoclaw/workspace/\$f" ] || { echo "host: refused - the overlaid workspace lacks \$f" >&2; exit 1; }
done
if grep -rqi "handle \\\`heron\\\`" "\$BUILD_DIR/picoclaw/workspace"; then
  echo "host: refused - the overlaid workspace still names Heron's handle; the overlay did not take" >&2
  exit 1
fi
rm -f /tmp/wren-workspace.tgz
echo "host: workspace overlaid from packages/wren/workspace"
docker build -t wren:local "\$BUILD_DIR"
ID="\$(docker inspect --format '{{.Id}}' wren:local)"
printf 'IMAGE=wren:local@%s\n' "\$ID" > /srv/wren/image.env
printf 'SOURCE_COMMIT=%s\n' "\$SHIPPED_COMMIT" >> /srv/wren/image.env
printf 'SOURCE_SHA256=%s\n' "$sha256" >> /srv/wren/image.env
rm -rf "\$DOCKER_CONFIG"
chmod 0600 /srv/wren/image.env
chown root:root /srv/wren/image.env
cat /srv/wren/image.env
REMOTE
}

install_host_units() {
  if is_stubbed; then "$WREN_STUB_DIR/install_host_units" "$@"; return; fi
  local ip="$1"
  validate_ssh_target "ops@$ip" "the droplet address the API returned"
  scp -- "$HERE/logrotate/wren" "ops@$ip:/tmp/wren.logrotate"
  scp -- "$HERE"/systemd/wren-watchdog.service "$HERE"/systemd/wren-watchdog.timer \
      "$HERE"/systemd/wren-alert@.service "$HERE"/systemd/wren-alive.timer \
      "$HERE"/systemd/wren-retention.service "$HERE"/systemd/wren-retention.timer \
      "ops@$ip:/tmp/"
  scp -- "$HERE"/bin/wren-watchdog "$HERE"/bin/wren-alert "$HERE"/bin/wren-retention "ops@$ip:/tmp/"
  # shellcheck disable=SC2087
  ssh -- "ops@$ip" sudo bash -s <<'REMOTE'
set -euo pipefail
mv /tmp/wren-watchdog.service /tmp/wren-watchdog.timer /tmp/wren-alert@.service \
   /tmp/wren-alive.timer /tmp/wren-retention.service /tmp/wren-retention.timer \
   /etc/systemd/system/
chown root:root /etc/systemd/system/wren-*.service /etc/systemd/system/wren-*.timer
chmod 0644 /etc/systemd/system/wren-*.service /etc/systemd/system/wren-*.timer
mv /tmp/wren-watchdog /tmp/wren-alert /tmp/wren-retention /usr/local/sbin/
chown root:root /usr/local/sbin/wren-watchdog /usr/local/sbin/wren-alert /usr/local/sbin/wren-retention
chmod 0755 /usr/local/sbin/wren-watchdog /usr/local/sbin/wren-alert /usr/local/sbin/wren-retention
# logrotate was installed as a package by cloud-init and given no config at all (Security's note
# N7). It bounds the two append-only JSONL sinks and nothing else -- runs/ is wren-retention's,
# because a per-beat file is the exact shape `rotate N` cannot bound.
mv /tmp/wren.logrotate /etc/logrotate.d/wren
chown root:root /etc/logrotate.d/wren
chmod 0644 /etc/logrotate.d/wren
logrotate --debug /etc/logrotate.d/wren >/dev/null
echo "logrotate config installed and parsed clean"
systemctl daemon-reload
echo "units installed; NO timer enabled -- that is --smoke's job"
REMOTE
}

# ---------------------------------------------------------------------------
# --seal <name> [--dry-run]. Pipes a credential from the desk's pile over the live SSH session
# straight into systemd-creds on the host. Plaintext never touches this laptop's disk beyond the
# pile's own copy, and never touches the host's disk at all.
# ---------------------------------------------------------------------------
cmd_seal() {
  local name="${1:-}"
  local dry_run="false"
  shift || true
  for arg in "$@"; do
    [ "$arg" = "--dry-run" ] && dry_run="true"
  done

  # THE NAME IS VALIDATED FIRST, before a path is built, a file is opened or a host is contacted.
  # The name is interpolated into a command that runs as root on the host that holds the hot key:
  # `--seal 'x;curl ...|sh'` was root command execution there (Security's A2). It was not reachable
  # while both branches returned early -- and the code was still offered as "exactly the pipeline a
  # live run performs", which is precisely the kind of claim this rebuild exists to stop making.
  if [ -z "$name" ]; then
    echo "deploy-droplet.sh --seal: refused - a credential name is required" >&2
    return 1
  fi
  if ! [[ "$name" =~ ^[a-z][a-z0-9-]{0,31}$ ]]; then
    echo "deploy-droplet.sh --seal: refused - '$name' is not a credential name. It must match ^[a-z][a-z0-9-]{0,31}\$: lower-case, starting with a letter, digits and hyphens only, at most 32 characters. This name is interpolated into a root command on the host that holds the hot key." >&2
    return 1
  fi

  local pile_path="${WREN_PILE:-$HOME/.config/protocolx/wren}/$name"
  # The key-birth tool (packages/signer/bin/birth-key.ts) writes a born key as <name>.key beside its
  # .pub and .address; a provider token sits in the pile as a bare <name>. Both shapes are the pile's
  # own; the bare name wins when both exist, and the row printed below names the file actually read.
  if [ ! -f "$pile_path" ] && [ -f "$pile_path.key" ]; then
    pile_path="$pile_path.key"
  fi
  local ssh_target="${WREN_HOST:-<unset - set WREN_HOST to ops@<the droplet IP>>}"
  # THE TARGET IS VALIDATED HERE, wherever it came from, before it is printed as a command or
  # handed to ssh (Security's N-7). --dry-run with WREN_HOST unset prints the placeholder above
  # and never reaches this.
  if [ -n "${WREN_HOST:-}" ]; then
    validate_ssh_target "$WREN_HOST" "WREN_HOST"
  fi
  local remote_cmd="sudo systemd-creds encrypt --with-key=host --name=$name - /etc/wren/creds/$name.cred"
  local pipeline="cat $pile_path | ssh -- $ssh_target \"$remote_cmd\""

  if [ "$dry_run" = "true" ]; then
    echo "deploy-droplet.sh --seal $name --dry-run: would run exactly:"
    echo "  $pipeline"
    echo "No credential is read, piped or sent by --dry-run. The pile path above is where it would come from; nothing at that path is opened."
    return 0
  fi

  # The same word --create needs. Sealing a credential onto a host is not a local operation and it
  # is not the desk's to do unasked.
  check_confirmed

  if [ "$ssh_target" != "${WREN_HOST:-}" ] || [ -z "${WREN_HOST:-}" ]; then
    echo "deploy-droplet.sh --seal: refused - WREN_HOST is unset (ops@<droplet ip>)" >&2
    return 1
  fi
  if [ ! -f "$pile_path" ]; then
    echo "deploy-droplet.sh --seal: refused - there is nothing at $pile_path (or $pile_path.key). The pile is the only source; this never generates a credential." >&2
    return 1
  fi
  local pile_mode
  pile_mode="$(stat -f %Lp "$pile_path" 2>/dev/null || stat -c %a "$pile_path")"
  if [ "$pile_mode" != "600" ] && [ "$pile_mode" != "400" ]; then
    echo "deploy-droplet.sh --seal: refused - $pile_path is mode $pile_mode; a credential in the pile is 0600 or 0400" >&2
    return 1
  fi

  # THE PIPELINE. `set -o pipefail` is on (line 44 of this file), so a failure at either end fails
  # the whole thing rather than reporting a sealed credential that was never written.
  #
  # The value crosses in exactly one way: this process's stdout into ssh's stdin into
  # systemd-creds' stdin. It is never an argv on either machine (visible in `ps` to every account),
  # never an environment variable, and never a file on the host -- systemd-creds reads `-` and
  # writes only the encrypted blob, which is sealed to this host's own key and worthless off it.
  echo "deploy-droplet.sh --seal $name: piping from the pile straight into systemd-creds on $ssh_target" >&2
  cat "$pile_path" | ssh -- "$ssh_target" "$remote_cmd"

  # The ledger row, printed as it happens. No value, ever.
  echo "deploy-droplet.sh --seal $name: sealed."
  echo "  ledger row: name=$name source=$pile_path destination=/etc/wren/creds/$name.cred mode=0600 encryption=systemd-creds --with-key=host revocation=revoke at the provider, then --seal $name again with a fresh value"
}

# ---------------------------------------------------------------------------
# --smoke. Build order step 9's gate, and every part of it is a refusal that stops the next part.
#
# The order is the whole point, and it is Security's requirement on the second read: THE MAIL DRILL
# RUNS BEFORE ANY TIMER IS ENABLED, not after. A host whose dead man cannot reach the Master is a
# host that must not be left running unattended, and "we will test the alert once it is live" is
# how that gets discovered by the silence.
#
# 1. lib/smoke-assert.sh over the session: chain.json readable by uid 10002, the docker socket
#    reachable from inside ProtectSystem=strict, no ~/.docker under ProtectHome.
# 2. the effective inbound ruleset for tag wren-v2, read from the ACCOUNT rather than from the one
#    firewall's own echo -- a second firewall on the tag admits what nobody wrote down.
# 3. THE MAIL GATE: wren-alert@smoke.service, a real send, and a message id in the journal. No
#    sealed /etc/wren/creds/mail-key.cred, or no id, and this refuses here with no timer enabled.
# 4. one real beat, and a fresh, parsable state/latest.json.
# 5. only then, the timers.
# ---------------------------------------------------------------------------
cmd_smoke() {
  local ssh_target="${WREN_HOST:-}"
  if [ -z "$ssh_target" ]; then
    echo "deploy-droplet.sh --smoke: refused - WREN_HOST is unset (ops@<droplet ip>)" >&2
    return 1
  fi
  validate_ssh_target "$ssh_target" "WREN_HOST"
  check_do_token_file

  echo "deploy-droplet.sh --smoke: 1/5 the on-host assertions (lib/smoke-assert.sh)" >&2
  smoke_assert_host "$ssh_target"

  echo "deploy-droplet.sh --smoke: 2/5 the effective inbound ruleset for tag $FIREWALL_TAG, read from the account" >&2
  smoke_firewall_effective

  echo "deploy-droplet.sh --smoke: 3/5 the mail gate - a real email through wren-alert@smoke, BEFORE any timer" >&2
  smoke_mail_gate "$ssh_target"

  echo "deploy-droplet.sh --smoke: 4/5 one real beat, and a fresh state/latest.json" >&2
  smoke_beat "$ssh_target"

  echo "deploy-droplet.sh --smoke: 5/5 enabling the timers" >&2
  smoke_enable_timers "$ssh_target"
  echo "deploy-droplet.sh --smoke: timers enabled. The mail gate passed before this line, not after it."
}

smoke_assert_host() {
  if is_stubbed; then "$WREN_STUB_DIR/smoke_assert_host" "$@"; return; fi
  local ssh_target="$1"
  ssh -- "$ssh_target" bash -s < "$SMOKE_ASSERT"
}

smoke_firewall_effective() {
  if is_stubbed; then "$WREN_STUB_DIR/smoke_firewall_effective" "$@"; return; fi
  python3 "$DO_API" firewall-effective "$DO_TOKEN_FILE" "$FIREWALL_TAG"
}

smoke_mail_gate() {
  if is_stubbed; then "$WREN_STUB_DIR/smoke_mail_gate" "$@"; return; fi
  local ssh_target="$1"
  ssh -- "$ssh_target" sudo bash -s <<'REMOTE'
set -euo pipefail
if [ ! -f /etc/wren/creds/mail-key.cred ]; then
  echo "smoke: refused - /etc/wren/creds/mail-key.cred is not sealed on this host. Seal it with --seal mail-key first. NO TIMER IS ENABLED: a host whose dead man cannot reach the desk is not a host to leave running." >&2
  exit 1
fi
# The start time is taken first, so the journal read below is bounded to this run of the unit
# and to nothing older: a oneshot that has finished carries no InvocationID to filter on.
MAIL_START="$(date +%s)"
systemctl start wren-alert@smoke.service || true
RESULT="$(systemctl show -p Result --value wren-alert@smoke.service)"
if [ "$RESULT" != "success" ]; then
  echo "smoke: refused - wren-alert@smoke.service finished '$RESULT', not 'success'. NO TIMER IS ENABLED." >&2
  journalctl -u wren-alert@smoke.service -n 50 --no-pager >&2 || true
  exit 1
fi
# The message id is read from the journal SINCE this run's start, and the read waits for journald:
# the unit's exit and the journal's write are not one event, and a read the instant `systemctl
# start` returned missed the line once (2026-09-05) and refused a send that had happened. Not by
# InvocationID: a oneshot that has finished reports none.
SENT=""
for i in $(seq 1 20); do
  SENT="$(journalctl -u wren-alert@smoke.service --since "@$MAIL_START" --no-pager -o cat 2>/dev/null | grep "wren-alert: sent instance=smoke id=" | tail -1 || true)"
  [ -n "$SENT" ] && break
  sleep 0.5
done
if [ -z "$SENT" ]; then
  echo "smoke: refused - wren-alert@smoke.service exited clean but printed no Resend message id within 10s. The send did not happen. NO TIMER IS ENABLED." >&2
  journalctl -u wren-alert@smoke.service --since "@$MAIL_START" --no-pager >&2 || true
  exit 1
fi
echo "smoke: wren-alert@smoke.service sent a real message: $SENT"
REMOTE
}

smoke_beat() {
  if is_stubbed; then "$WREN_STUB_DIR/smoke_beat" "$@"; return; fi
  local ssh_target="$1" start
  start="$(date -u +%s)"
  ssh -- "$ssh_target" sudo systemctl start wren-beat.service
  # The body goes over stdin to a root shell, with the start time as an argument: `ssh bash -c
  # "<multi-line>"` is word-split by the remote shell (the first real smoke, 2026-09-05, printed
  # "bash: -c: option requires an argument"), and state/ is 2770 root:wren, which ops cannot stat.
  ssh -- "$ssh_target" sudo bash -s -- "$start" <<'REMOTE'
set -euo pipefail
START="$1"
MTIME="$(stat -c %Y /srv/wren/state/latest.json)"
[ "$MTIME" -ge "$START" ] || { echo "smoke: refused - state/latest.json is not newer than the smoke beat start" >&2; exit 1; }
python3 -c 'import json,sys; json.load(open("/srv/wren/state/latest.json"))'
echo "smoke: the beat produced a fresh, parsable state/latest.json:"
cat /srv/wren/state/latest.json
echo "smoke: the last line of state/beats.jsonl:"
tail -n 1 /srv/wren/state/beats.jsonl
REMOTE
}

smoke_enable_timers() {
  if is_stubbed; then "$WREN_STUB_DIR/smoke_enable_timers" "$@"; return; fi
  local ssh_target="$1"
  ssh -- "$ssh_target" sudo systemctl enable --now wren-beat.timer wren-watchdog.timer wren-alive.timer wren-retention.timer
}

# ---------------------------------------------------------------------------
# --install-purse. Build order step 5 on the host: the signer service that holds the hot key.
#
# What ships, and what pins it. The bundle is built here from the COMMITTED purse tree (the tree
# must be clean, so the commit named in the run record is what shipped) with the esbuild version
# the purse package pins; its sha256 goes into the unit as an ExecStartPre check, beside the
# members document's sha256 and the policy's --policy-sha256. All three are root-owned facts in
# /etc/systemd/system; a file on the host that does not hash to them stops the unit before node
# starts. The unit itself is rendered from packages/purse/systemd/wren-purse.service, and a
# rendered unit with any <SUBSTITUTION> left in it is refused before anything is copied.
#
# Nothing here is a rollback of the host: a failed purse install leaves the droplet as it was,
# with whatever partial file it wrote, and records install-purse-failed with the step's name.
# ---------------------------------------------------------------------------
WREN_INSTALL_STEP=""
WREN_INSTALL_SUCCEEDED=0

install_purse_on_exit() {
  local status=$?
  trap - EXIT
  if [ "$WREN_INSTALL_SUCCEEDED" = "1" ]; then return 0; fi
  echo "deploy-droplet.sh --install-purse: did not reach success (exit $status) at step '${WREN_INSTALL_STEP:-preconditions}'. The host is left as it was at that step; nothing is rolled back." >&2
  record_run "install-purse-failed" "step=${WREN_INSTALL_STEP:-preconditions}"
  exit "$status"
}

file_sha256() {
  python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"
}

render_purse_unit() {
  # $1 dist sha256, $2 members-document sha256, $3 policy sha256, $4 Wren's vault id. Prints the unit.
  local dist="$1" multisig="$2" policy="$3" vault="${4:-}"
  for value in "$dist" "$multisig" "$policy"; do
    if ! [[ "$value" =~ ^[0-9a-f]{64}$ ]]; then
      echo "deploy-droplet.sh: refused - '$value' is not a sha256; the unit is not rendered" >&2
      return 1
    fi
  done
  if ! [[ "$vault" =~ ^0x[0-9a-f]{64}$ ]]; then
    echo "deploy-droplet.sh: refused - '$vault' is not a vault id; the unit is not rendered" >&2
    return 1
  fi
  sed -e "s/<DIST_SHA256>/$dist/g" -e "s/<MULTISIG_SHA256>/$multisig/g" -e "s/<POLICY_SHA256>/$policy/g" -e "s/<VAULT_ID>/$vault/g" \
    "$PKG_DIR/systemd/wren-purse.service"
}

cmd_install_purse() {
  local ssh_target="${WREN_HOST:-}"
  if [ -z "$ssh_target" ]; then
    echo "deploy-droplet.sh --install-purse: refused - WREN_HOST is unset (ops@<droplet ip>)" >&2
    return 1
  fi
  validate_ssh_target "$ssh_target" "WREN_HOST"
  check_confirmed

  if [ -n "$(git -C "$PURSE_DIR" status --porcelain -- .)" ] || [ -n "$(git -C "$PKG_DIR" status --porcelain -- .)" ]; then
    echo "deploy-droplet.sh --install-purse: refused - packages/purse or packages/wren has uncommitted changes; there is no committed sha to name as what shipped" >&2
    return 1
  fi
  local commit
  commit="$(git -C "$PURSE_DIR" rev-parse HEAD)"

  for f in "$POLICY_DIR/wren-multisig.json" "$POLICY_DIR/wren-chain.mainnet.json" "$POLICY_DIR/wren-values.json" "$PKG_DIR/systemd/wren-purse.service"; do
    if [ ! -f "$f" ]; then
      echo "deploy-droplet.sh --install-purse: refused - $f is missing" >&2
      return 1
    fi
  done

  # The vault the purse names statements for, read from the committed values document, never typed.
  local vault_id
  vault_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("WREN_VAULT_ID",""))' "$POLICY_DIR/wren-values.json")"
  if ! [[ "$vault_id" =~ ^0x[0-9a-f]{64}$ ]]; then
    echo "deploy-droplet.sh --install-purse: refused - policy/wren-values.json carries no WREN_VAULT_ID; birth the vault first (packages/purse/bin/birth-vault.ts --values-prefix WREN) and commit the values" >&2
    return 1
  fi

  trap install_purse_on_exit EXIT
  record_run "install-purse-begin" "commit=$commit"

  local stage
  stage="$(mktemp -d "${TMPDIR:-/tmp}/wren-purse-stage.XXXXXX")"

  WREN_INSTALL_STEP="build_purse_bundle"
  build_purse_bundle "$stage/server.js"
  # The policy shipped: the rendered mainnet document by default (bin/render-policy.ts over
  # policy/wren-content.json and policy/wren-values.json, committed); WREN_POLICY_FILE names another
  # committed document under packages/wren/policy. Wren has no pre-soul phase: her vault is born
  # before her purse is installed, so the purse starts with statements on.
  local policy_file="${WREN_POLICY_FILE:-wren-content.mainnet.json}"
  if ! [[ "$policy_file" =~ ^[a-z][a-z0-9.-]*\.json$ ]] || [ ! -f "$POLICY_DIR/$policy_file" ]; then
    echo "deploy-droplet.sh --install-purse: refused - WREN_POLICY_FILE '$policy_file' is not a committed document under packages/wren/policy" >&2
    return 1
  fi
  cp "$POLICY_DIR/$policy_file" "$stage/wren-policy.json"
  cp "$POLICY_DIR/wren-multisig.json" "$stage/wren-multisig.json"
  cp "$POLICY_DIR/wren-chain.mainnet.json" "$stage/chain.json"

  local dist_sha multisig_sha policy_sha
  dist_sha="$(file_sha256 "$stage/server.js")"
  multisig_sha="$(file_sha256 "$stage/wren-multisig.json")"
  policy_sha="$(file_sha256 "$stage/wren-policy.json")"

  WREN_INSTALL_STEP="render_purse_unit"
  render_purse_unit "$dist_sha" "$multisig_sha" "$policy_sha" "$vault_id" > "$stage/wren-purse.service"
  # Directive lines only: the unit's comments name the substitution convention itself.
  if grep -v '^[[:space:]]*#' "$stage/wren-purse.service" | grep -q '<[A-Z_]*>'; then
    echo "deploy-droplet.sh --install-purse: refused - the rendered unit still carries a substitution: $(grep -v '^[[:space:]]*#' "$stage/wren-purse.service" | grep -o '<[A-Z_]*>' | sort -u | tr '\n' ' ')" >&2
    return 1
  fi

  echo "deploy-droplet.sh --install-purse: shipping from commit $commit"
  echo "  server.js           sha256 $dist_sha  -> /srv/wren/purse/dist/server.js   0640 purse:purse (pinned in the unit)"
  echo "  wren-multisig.json sha256 $multisig_sha  -> /srv/wren/policy/wren-multisig.json 0644 root:root (pinned in the unit)"
  echo "  wren-policy.json   sha256 $policy_sha  -> /srv/wren/policy/wren-policy.json   0644 root:root (--policy-sha256; from $policy_file)"
  echo "  chain.json          mainnet, v5 package                     -> /srv/wren/chain.json 0600 purse:purse"
  echo "  wren-purse.service rendered, no substitution left           -> /etc/systemd/system/wren-purse.service 0644 root:root"
  echo "  node                v$NODE22_VERSION, sha256 $NODE22_SHA256 -> /opt/node22"

  WREN_INSTALL_STEP="install_node22"
  install_node22 "$ssh_target"
  WREN_INSTALL_STEP="ship_purse_files"
  ship_purse_files "$ssh_target" "$stage" "$dist_sha" "$multisig_sha" "$policy_sha"
  WREN_INSTALL_STEP="start_purse"
  start_purse "$ssh_target" "$policy_sha"
  WREN_INSTALL_STEP="probe_purse"
  probe_purse "$ssh_target"

  WREN_INSTALL_SUCCEEDED=1
  trap - EXIT
  record_run "install-purse-succeeded" "commit=$commit dist=$dist_sha multisig=$multisig_sha policy=$policy_sha"
  rm -rf "$stage"
  echo "deploy-droplet.sh --install-purse: wren-purse.service is active on $ssh_target, listening on /run/wren/purse.sock as Wren's address, under $policy_file (file sha256 $policy_sha). A malformed request was refused and recorded. wren-beat.service is NOT installed by this mode."
}

install_ledger_on_exit() {
  [ -n "${WREN_INSTALL_SUCCEEDED:-}" ] && return 0
  record_run "install-ledger-failed" "step=${WREN_INSTALL_STEP:-unknown}"
  echo "deploy-droplet.sh --install-ledger: FAILED at ${WREN_INSTALL_STEP:-unknown}. Nothing was rolled back: the settlement units are additive and the content purse is untouched." >&2
}

cmd_install_ledger() {
  local ssh_target="${WREN_HOST:-}"
  if [ -z "$ssh_target" ]; then
    echo "deploy-droplet.sh --install-ledger: refused - WREN_HOST is unset (ops@<droplet ip>)" >&2
    return 1
  fi
  validate_ssh_target "$ssh_target" "WREN_HOST"
  check_confirmed

  if [ -n "$(git -C "$PURSE_DIR" status --porcelain -- .)" ] || [ -n "$(git -C "$PKG_DIR" status --porcelain -- .)" ]; then
    echo "deploy-droplet.sh --install-ledger: refused - packages/purse or packages/wren has uncommitted changes; there is no committed sha to name as what shipped" >&2
    return 1
  fi
  local commit
  commit="$(git -C "$PURSE_DIR" rev-parse HEAD)"

  for f in "$POLICY_DIR/wren-ledger.mainnet.json" "$POLICY_DIR/wren-chain.mainnet.json" "$POLICY_DIR/wren-values.json" \
           "$PKG_DIR/systemd/wren-ledger-purse.service" "$PKG_DIR/systemd/wren-ledger.service" "$PKG_DIR/systemd/wren-ledger.timer"; do
    if [ ! -f "$f" ]; then
      echo "deploy-droplet.sh --install-ledger: refused - $f is missing" >&2
      return 1
    fi
  done

  # The credential has to be on the host already: --seal wren-ledger puts it there, and a unit
  # that starts without its key would fail at the first settlement instead of here.
  WREN_INSTALL_STEP="check_credential"
  if ! is_stubbed; then
    ssh -- "$ssh_target" 'sudo test -f /etc/wren/creds/wren-ledger.cred' || {
      echo "deploy-droplet.sh --install-ledger: refused - /etc/wren/creds/wren-ledger.cred is not on the host. Seal it first: WREN_HOST=$ssh_target ./deploy-droplet.sh --seal wren-ledger" >&2
      return 1
    }
  fi

  trap install_ledger_on_exit EXIT
  record_run "install-ledger-begin" "commit=$commit"

  local stage
  stage="$(mktemp -d "${TMPDIR:-/tmp}/wren-ledger-stage.XXXXXX")"

  WREN_INSTALL_STEP="build_purse_bundle"
  build_purse_bundle "$stage/server.js"
  WREN_INSTALL_STEP="build_ledger_tick_bundle"
  build_ledger_tick_bundle "$stage/ledger-tick.js"
  cp "$POLICY_DIR/wren-ledger.mainnet.json" "$stage/wren-ledger.mainnet.json"
  cp "$PKG_DIR/systemd/wren-ledger.timer" "$stage/wren-ledger.timer"
  cp "$POLICY_DIR/wren-chain.mainnet.json" "$stage/chain.json"

  local dist_sha tick_sha policy_sha
  dist_sha="$(file_sha256 "$stage/server.js")"
  tick_sha="$(file_sha256 "$stage/ledger-tick.js")"
  policy_sha="$(file_sha256 "$stage/wren-ledger.mainnet.json")"

  WREN_INSTALL_STEP="render_ledger_units"
  render_ledger_units "$dist_sha" "$policy_sha" signer > "$stage/wren-ledger-purse.service"
  render_ledger_units "$dist_sha" "$policy_sha" run    > "$stage/wren-ledger.service"
  for u in "$stage/wren-ledger-purse.service" "$stage/wren-ledger.service"; do
    if grep -v '^[[:space:]]*#' "$u" | grep -q '<[A-Z_]*>'; then
      echo "deploy-droplet.sh --install-ledger: refused - $(basename "$u") still carries a substitution: $(grep -v '^[[:space:]]*#' "$u" | grep -o '<[A-Z_]*>' | sort -u | tr '\n' ' ')" >&2
      return 1
    fi
  done

  echo "deploy-droplet.sh --install-ledger: shipping from commit $commit"
  echo "  server.js                  sha256 $dist_sha  -> /srv/wren-ledger/dist/server.js      0640 ledger:ledger (pinned in the unit)"
  echo "  ledger-tick.js             sha256 $tick_sha  -> /srv/wren-ledger/dist/ledger-tick.js 0644 root:root"
  echo "  wren-ledger.mainnet.json   sha256 $policy_sha  -> /srv/wren-ledger/policy/wren-ledger.mainnet.json 0644 root:root (--policy-sha256)"
  echo "  chain.json                 mainnet, v5 package                  -> /srv/wren-ledger/chain.json 0600 ledger:ledger"
  echo "  wren-ledger-purse.service  rendered, no substitution left        -> /etc/systemd/system/ 0644 root:root"
  echo "  wren-ledger.service        rendered, no substitution left        -> /etc/systemd/system/ 0644 root:root"
  echo "  wren-ledger.timer          daily, no substitutions               -> /etc/systemd/system/ 0644 root:root"
  echo "  the timer is NOT enabled by this mode: one settlement is run by hand and read on chain first."

  WREN_INSTALL_STEP="ship_ledger_files"
  ship_ledger_files "$ssh_target" "$stage" "$dist_sha" "$tick_sha" "$policy_sha"
  WREN_INSTALL_STEP="start_ledger_purse"
  start_ledger_purse "$ssh_target" "$policy_sha"

  WREN_INSTALL_SUCCEEDED=1
  trap - EXIT
  record_run "install-ledger-succeeded" "commit=$commit dist=$dist_sha tick=$tick_sha policy=$policy_sha"
  rm -rf "$stage"
  echo "deploy-droplet.sh --install-ledger: wren-ledger-purse.service is active on $ssh_target, listening on /run/wren-ledger/purse.sock as the settlement key, under wren-ledger.mainnet.json (file sha256 $policy_sha). wren-ledger.timer is installed and NOT enabled: run one settlement by hand (systemctl start wren-ledger.service), read the transaction on chain, then enable the timer."
}

ship_ledger_files() {
  if is_stubbed; then "$WREN_STUB_DIR/ship_ledger_files" "$@"; return; fi
  local ssh_target="$1" stage="$2" dist_sha="$3" tick_sha="$4" policy_sha="$5"
  ssh -- "$ssh_target" 'rm -rf /tmp/wren-ledger-stage && mkdir -m 0700 /tmp/wren-ledger-stage'
  scp -q -- "$stage/server.js" "$stage/ledger-tick.js" "$stage/wren-ledger.mainnet.json" "$stage/chain.json" \
      "$stage/wren-ledger-purse.service" "$stage/wren-ledger.service" "$stage/wren-ledger.timer" \
      "$ssh_target:/tmp/wren-ledger-stage/"
  ssh -- "$ssh_target" sudo bash -s -- "$dist_sha" "$tick_sha" "$policy_sha" <<'REMOTE'
set -euo pipefail
S=/tmp/wren-ledger-stage
check() { local actual; actual="$(sha256sum "$1" | cut -d' ' -f1)"; [ "$actual" = "$2" ] || { echo "host: refused - $1 hashes $actual, not $2 as shipped" >&2; exit 1; }; }
check "$S/server.js" "$1"
check "$S/ledger-tick.js" "$2"
check "$S/wren-ledger.mainnet.json" "$3"
echo "host: the three shipped files hash as the laptop said"
# The settlement account, uid/gid 10003, created by cloud-init on a fresh droplet. Wren's host was
# built before it existed, so it is created here the same way and asserted the same way.
if ! getent passwd 10003 >/dev/null 2>&1; then
  getent group 10003 >/dev/null 2>&1 || groupadd --gid 10003 --system ledger
  useradd --uid 10003 --gid 10003 --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ledger
fi
[ "$(getent passwd 10003 | cut -d: -f1)" = "ledger" ] || { echo "host: refused - uid 10003 is not ledger" >&2; exit 1; }
install -d -m 0700 -o ledger -g ledger /var/lib/wren-ledger
install -d -m 0700 -o ledger -g ledger /var/lib/wren-ledger/audit
install -d -m 0700 -o ledger -g ledger /var/lib/wren-ledger/state
# Asserted every install, not just created once. Both settlement units declare
# StateDirectory=wren-ledger, and systemd chowns that directory to whatever user the unit runs
# as. A single run of either unit under the wrong user takes the tree with it and the other unit
# then cannot write its audit chain — which is exactly how this line came to exist.
chown -R ledger:ledger /var/lib/wren-ledger
# The settlement signer's own tree. 0750 ledger:ledger, and the content purse cannot read into
# it any more than this account can read into /srv/wren/purse.
install -d -m 0750 -o ledger -g ledger /srv/wren-ledger
install -d -m 0750 -o ledger -g ledger /srv/wren-ledger/dist
install -d -m 0755 -o root -g root /srv/wren-ledger/policy
install -m 0640 -o ledger -g ledger "$S/server.js" /srv/wren-ledger/dist/server.js
install -m 0644 -o root -g root "$S/ledger-tick.js" /srv/wren-ledger/dist/ledger-tick.js
install -m 0644 -o root -g root "$S/wren-ledger.mainnet.json" /srv/wren-ledger/policy/wren-ledger.mainnet.json
# Its own chain document: /srv/wren/chain.json is 0600 purse:purse and unreadable here.
install -m 0600 -o ledger -g ledger "$S/chain.json" /srv/wren-ledger/chain.json
install -m 0644 -o root -g root "$S/wren-ledger-purse.service" /etc/systemd/system/wren-ledger-purse.service
install -m 0644 -o root -g root "$S/wren-ledger.service" /etc/systemd/system/wren-ledger.service
install -m 0644 -o root -g root "$S/wren-ledger.timer" /etc/systemd/system/wren-ledger.timer
rm -rf "$S"
echo "host: ledger files installed with their modes, uid 10003 confirmed to be ledger"
REMOTE
}

start_ledger_purse() {
  if is_stubbed; then "$WREN_STUB_DIR/start_ledger_purse" "$@"; return; fi
  local ssh_target="$1" policy_hash="${2:-}"
  ssh -- "$ssh_target" sudo bash -s -- "$policy_hash" <<'REMOTE'
set -euo pipefail
POLICY_HASH_EXPECTED="${1:-}"
systemctl daemon-reload
systemctl enable wren-ledger-purse.service >/dev/null 2>&1 || true
systemctl restart wren-ledger-purse.service >/dev/null 2>&1 || true
for i in $(seq 1 30); do
  [ "$(systemctl is-active wren-ledger-purse.service)" = "active" ] && break
  sleep 1
done
if [ "$(systemctl is-active wren-ledger-purse.service)" != "active" ]; then
  echo "host: refused - wren-ledger-purse.service is $(systemctl is-active wren-ledger-purse.service), not active. The journal:" >&2
  journalctl -u wren-ledger-purse.service -n 40 --no-pager >&2 || true
  exit 1
fi
SOCK="$(stat -c '%a %U %G' /run/wren-ledger/purse.sock)"
[ "$SOCK" = "660 ledger ledger" ] || { echo "host: refused - /run/wren-ledger/purse.sock is '$SOCK', not '660 ledger ledger'" >&2; exit 1; }
LINE="$(journalctl -u wren-ledger-purse.service -n 30 --no-pager -o cat | grep 'wren-ledger-purse: listening on /run/wren-ledger/purse.sock for 0x' | tail -1 || true)"
case "$LINE" in
  *"file $POLICY_HASH_EXPECTED"*) ;;
  *) [ -z "$POLICY_HASH_EXPECTED" ] || { echo "host: refused - the settlement purse is listening under a policy file other than the one just shipped" >&2; echo "host: $LINE" >&2; exit 1; } ;;
esac
[ -n "$LINE" ] || { echo "host: refused - the settlement purse is active but never printed its listening line" >&2; journalctl -u wren-ledger-purse.service -n 40 --no-pager >&2; exit 1; }
echo "host: $LINE"
echo "host: wren-ledger-purse.service active, enabled at boot, socket 660 ledger:ledger"
REMOTE
}

render_ledger_units() {
  # $1 dist sha256, $2 ledger policy sha256, $3 which unit: `signer` or `run`. Prints ONE unit.
  #
  # One at a time rather than both with a separator between them: the separator wanted splitting on
  # the far side, and `csplit` is not the same program on macOS as it is on Debian. A function that
  # prints one whole file needs no parser at all.
  #
  # Everything the run unit names is read from the committed values document, never typed here: the
  # cap is an object REFERENCE (id, version and digest) because the purse is handed fully-resolved
  # references and never resolves an id against a fullnode itself.
  local dist="$1" policy="$2" which="${3:-}"
  case "$which" in
    signer|run) ;;
    *) echo "deploy-droplet.sh: refused - render_ledger_units takes 'signer' or 'run', not '$which'" >&2; return 1 ;;
  esac
  for value in "$dist" "$policy"; do
    if ! [[ "$value" =~ ^[0-9a-f]{64}$ ]]; then
      echo "deploy-droplet.sh: refused - '$value' is not a sha256; the units are not rendered" >&2
      return 1
    fi
  done

  local v="$POLICY_DIR/wren-values.json"
  local pkg registry registry_v soul soul_v vault cap cap_v cap_d burn
  pkg="$(values_get "$v" SOUL_PACKAGE_ID)"
  registry="$(values_get "$v" SOUL_REGISTRY_ID)"
  registry_v="$(values_get "$v" SOUL_REGISTRY_VERSION)"
  soul="$(values_get "$v" WREN_SOUL_ID)"
  soul_v="$(values_get "$v" WREN_SOUL_VERSION)"
  vault="$(values_get "$v" WREN_VAULT_ID)"
  cap="$(values_get "$v" LEDGER_CAP_ID)"
  cap_v="$(values_get "$v" LEDGER_CAP_VERSION)"
  cap_d="$(values_get "$v" LEDGER_CAP_DIGEST)"
  burn="$(values_get "$v" WREN_BURN_PER_EPOCH_MIST)"

  for pair in "SOUL_PACKAGE_ID:$pkg" "SOUL_REGISTRY_ID:$registry" "WREN_SOUL_ID:$soul" "WREN_VAULT_ID:$vault" "LEDGER_CAP_ID:$cap"; do
    if ! [[ "${pair#*:}" =~ ^0x[0-9a-f]{64}$ ]]; then
      echo "deploy-droplet.sh: refused - policy/wren-values.json carries no ${pair%%:*}" >&2
      return 1
    fi
  done
  for pair in "SOUL_REGISTRY_VERSION:$registry_v" "WREN_SOUL_VERSION:$soul_v" "LEDGER_CAP_VERSION:$cap_v" "WREN_BURN_PER_EPOCH_MIST:$burn"; do
    if ! [[ "${pair#*:}" =~ ^(0|[1-9][0-9]{0,19})$ ]]; then
      echo "deploy-droplet.sh: refused - policy/wren-values.json carries no ${pair%%:*} as a u64" >&2
      return 1
    fi
  done
  if ! [[ "$cap_d" =~ ^[1-9A-HJ-NP-Za-km-z]{32,64}$ ]]; then
    echo "deploy-droplet.sh: refused - policy/wren-values.json carries no LEDGER_CAP_DIGEST as base58" >&2
    return 1
  fi
  # A burn of zero would make every settlement report a non-negative net whatever the citizen
  # earned, which is the survival rule switched off while looking switched on.
  if [ "$burn" = "0" ]; then
    echo "deploy-droplet.sh: refused - WREN_BURN_PER_EPOCH_MIST is 0; the survival rule could never bite" >&2
    return 1
  fi

  if [ "$which" = "signer" ]; then
    sed -e "s/<DIST_SHA256>/$dist/g" -e "s/<LEDGER_POLICY_SHA256>/$policy/g" \
      "$PKG_DIR/systemd/wren-ledger-purse.service"
    return 0
  fi

  sed -e "s/<SOUL_PACKAGE_ID>/$pkg/g" -e "s/<SOUL_REGISTRY_ID>/$registry/g" \
      -e "s/<SOUL_REGISTRY_VERSION>/$registry_v/g" -e "s/<WREN_SOUL_ID>/$soul/g" \
      -e "s/<WREN_SOUL_VERSION>/$soul_v/g" -e "s/<WREN_VAULT_ID>/$vault/g" \
      -e "s/<LEDGER_CAP_ID>/$cap/g" -e "s/<LEDGER_CAP_VERSION>/$cap_v/g" \
      -e "s/<LEDGER_CAP_DIGEST>/$cap_d/g" -e "s/<WREN_BURN_PER_EPOCH_MIST>/$burn/g" \
    "$PKG_DIR/systemd/wren-ledger.service"
}

values_get() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2],""))' "$1" "$2"
}

build_ledger_tick_bundle() {
  if is_stubbed; then "$WREN_STUB_DIR/build_ledger_tick_bundle" "$@"; return; fi
  local out="$1"
  (cd "$PURSE_DIR" && pnpm exec esbuild bin/ledger-tick.ts --bundle --platform=node --format=esm --target=node22 \
      --banner:js="import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);" \
      --log-level=warning --outfile="$out")
  [ -s "$out" ] || { echo "deploy-droplet.sh: the bundle at $out is empty or missing" >&2; return 1; }
}

build_purse_bundle() {
  if is_stubbed; then "$WREN_STUB_DIR/build_purse_bundle" "$@"; return; fi
  local out="$1"
  # One file, ESM, node 22. The banner gives CommonJS dependencies inside the bundle a `require`.
  (cd "$PURSE_DIR" && pnpm exec esbuild src/server.ts --bundle --platform=node --format=esm --target=node22 \
      --banner:js="import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);" \
      --log-level=warning --outfile="$out")
  [ -s "$out" ] || { echo "deploy-droplet.sh: the bundle at $out is empty or missing" >&2; return 1; }
}

install_node22() {
  if is_stubbed; then "$WREN_STUB_DIR/install_node22" "$@"; return; fi
  local ssh_target="$1"
  ssh -- "$ssh_target" sudo bash -s -- "$NODE22_VERSION" "$NODE22_SHA256" <<'REMOTE'
set -euo pipefail
VERSION="$1"; EXPECTED="$2"
if [ -x /opt/node22/bin/node ] && [ "$(/opt/node22/bin/node -v)" = "v$VERSION" ]; then
  echo "host: node v$VERSION already at /opt/node22"
  exit 0
fi
TGZ="/tmp/node-v$VERSION-linux-x64.tar.gz"
python3 - "$VERSION" "$TGZ" <<'PY'
import sys, urllib.request
version, out = sys.argv[1], sys.argv[2]
url = f"https://nodejs.org/dist/v{version}/node-v{version}-linux-x64.tar.gz"
with urllib.request.urlopen(url, timeout=120) as r, open(out, "wb") as f:
    while True:
        chunk = r.read(1 << 20)
        if not chunk: break
        f.write(chunk)
PY
ACTUAL="$(sha256sum "$TGZ" | cut -d' ' -f1)"
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "host: refused - node tarball hashes $ACTUAL, not the literal $EXPECTED; nothing installed" >&2
  rm -f "$TGZ"
  exit 1
fi
echo "host: node tarball sha256 verified against the literal: $ACTUAL"
mkdir -p /opt
tar -xzf "$TGZ" -C /opt
rm -f "$TGZ"
chown -R root:root "/opt/node-v$VERSION-linux-x64"
ln -sfn "/opt/node-v$VERSION-linux-x64" /opt/node22
echo "host: /opt/node22/bin/node is $(/opt/node22/bin/node -v)"
REMOTE
}

ship_purse_files() {
  if is_stubbed; then "$WREN_STUB_DIR/ship_purse_files" "$@"; return; fi
  local ssh_target="$1" stage="$2" dist_sha="$3" multisig_sha="$4" policy_sha="$5"
  ssh -- "$ssh_target" 'rm -rf /tmp/wren-purse-stage && mkdir -m 0700 /tmp/wren-purse-stage'
  scp -q -- "$stage/server.js" "$stage/wren-policy.json" "$stage/wren-multisig.json" "$stage/chain.json" \
      "$stage/wren-purse.service" "$ssh_target:/tmp/wren-purse-stage/"
  ssh -- "$ssh_target" sudo bash -s -- "$dist_sha" "$multisig_sha" "$policy_sha" <<'REMOTE'
set -euo pipefail
S=/tmp/wren-purse-stage
check() { local actual; actual="$(sha256sum "$1" | cut -d' ' -f1)"; [ "$actual" = "$2" ] || { echo "host: refused - $1 hashes $actual, not $2 as shipped" >&2; exit 1; }; }
check "$S/server.js" "$1"
check "$S/wren-multisig.json" "$2"
check "$S/wren-policy.json" "$3"
echo "host: the three shipped files hash as the laptop said"
install -m 0640 -o purse -g purse "$S/server.js" /srv/wren/purse/dist/server.js
install -m 0644 -o root -g root "$S/wren-multisig.json" /srv/wren/policy/wren-multisig.json
install -m 0644 -o root -g root "$S/wren-policy.json" /srv/wren/policy/wren-policy.json
install -m 0600 -o purse -g purse "$S/chain.json" /srv/wren/chain.json
install -m 0644 -o root -g root "$S/wren-purse.service" /etc/systemd/system/wren-purse.service
rm -rf "$S"
echo "host: purse files installed with their modes"
REMOTE
}

start_purse() {
  if is_stubbed; then "$WREN_STUB_DIR/start_purse" "$@"; return; fi
  local ssh_target="$1" policy_hash="${2:-}"
  ssh -- "$ssh_target" sudo bash -s -- "$policy_hash" <<'REMOTE'
set -euo pipefail
POLICY_HASH_EXPECTED="${1:-}"
systemctl daemon-reload
# restart, not enable --now: a purse already running keeps its old policy and pins until it is
# restarted, and a policy change is exactly a redeploy (packages/purse/README.md).
systemctl enable wren-purse.service >/dev/null 2>&1 || true
systemctl restart wren-purse.service >/dev/null 2>&1 || true
for i in $(seq 1 30); do
  if [ "$(systemctl is-active wren-purse.service)" = "active" ]; then break; fi
  sleep 1
done
if [ "$(systemctl is-active wren-purse.service)" != "active" ]; then
  echo "host: refused - wren-purse.service is $(systemctl is-active wren-purse.service), not active. The journal:" >&2
  journalctl -u wren-purse.service -n 40 --no-pager >&2 || true
  exit 1
fi
SOCK="$(stat -c '%a %U %G' /run/wren/purse.sock)"
[ "$SOCK" = "660 purse purse" ] || { echo "host: refused - /run/wren/purse.sock is '$SOCK', not '660 purse purse'" >&2; exit 1; }
LINE="$(journalctl -u wren-purse.service -n 30 --no-pager -o cat | grep 'wren-purse: listening on /run/wren/purse.sock for 0x' | tail -1 || true)"
# The listening line carries two hashes: `policy <canonical json>` and `file <bytes on disk>`. The
# deploy knows the bytes it shipped, so it is the file hash it checks.
case "$LINE" in
  *"file $POLICY_HASH_EXPECTED"*) ;;
  *) [ -z "$POLICY_HASH_EXPECTED" ] || { echo "host: refused - the purse is listening under a policy file other than the one just shipped" >&2; echo "host: $LINE" >&2; exit 1; } ;;
esac
[ -n "$LINE" ] || { echo "host: refused - the purse is active but never printed its listening line" >&2; journalctl -u wren-purse.service -n 40 --no-pager >&2; exit 1; }
echo "host: $LINE"
echo "host: wren-purse.service active, enabled at boot, socket 660 purse:purse"
REMOTE
}

probe_purse() {
  if is_stubbed; then "$WREN_STUB_DIR/probe_purse" "$@"; return; fi
  local ssh_target="$1"
  ssh -- "$ssh_target" sudo bash -s <<'REMOTE'
set -euo pipefail
ANSWER="$(python3 - <<'PY'
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(30)
s.connect("/run/wren/purse.sock")
s.sendall(b'{"ping": 1}\n')
s.shutdown(socket.SHUT_WR)
data = b""
while True:
    chunk = s.recv(65536)
    if not chunk: break
    data += chunk
print(data.decode("utf-8", "replace").strip())
PY
)"
echo "host: the purse answered: ${ANSWER:0:200}"
echo "$ANSWER" | grep -q '"request-malformed"' || { echo "host: refused - the answer to a malformed request was not a request-malformed refusal" >&2; exit 1; }
LAST="$(tail -n 1 /var/lib/wren/audit/audit.jsonl)"
echo "host: last audit line: ${LAST:0:220}"
echo "$LAST" | grep -q '"outcome": *"refused"' || { echo "host: refused - the audit chain did not record the refusal" >&2; exit 1; }
echo "host: a malformed request was refused as a value and recorded in the chain"
REMOTE
}

# ---------------------------------------------------------------------------
# --install-beat. Build order step 9's beat on the host: the launcher, phase two, the flags, the
# template, the two units. Nothing is started and no timer is enabled here; --smoke runs one real
# beat and only then enables the timers, in that order, because that order is the whole point.
# ---------------------------------------------------------------------------
render_wren_beat() {
  # $1 phase-two bundle sha256. Prints the launcher.
  #
  # The soul is substituted here from the committed values document, never typed: the beat books
  # what it spends against THAT soul, and a wrong id would either abort on chain or, worse, book
  # one citizen's spending against another's allowance.
  local sha="$1"
  if ! [[ "$sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "deploy-droplet.sh: refused - '$sha' is not a sha256; the launcher is not rendered" >&2
    return 1
  fi
  local v="$POLICY_DIR/wren-values.json"
  local pkg soul soul_v
  pkg="$(values_get "$v" SOUL_PACKAGE_ID)"
  soul="$(values_get "$v" WREN_SOUL_ID)"
  soul_v="$(values_get "$v" WREN_SOUL_VERSION)"
  for pair in "SOUL_PACKAGE_ID:$pkg" "WREN_SOUL_ID:$soul"; do
    if ! [[ "${pair#*:}" =~ ^0x[0-9a-f]{64}$ ]]; then
      echo "deploy-droplet.sh: refused - policy/wren-values.json carries no ${pair%%:*}; the beat would book nothing" >&2
      return 1
    fi
  done
  if ! [[ "$soul_v" =~ ^(0|[1-9][0-9]{0,19})$ ]]; then
    echo "deploy-droplet.sh: refused - policy/wren-values.json carries no WREN_SOUL_VERSION as a u64" >&2
    return 1
  fi
  sed -e "s/<PHASE2_SHA256>/$sha/g" -e "s/<SOUL_PACKAGE_ID>/$pkg/g" \
      -e "s/<WREN_SOUL_ID>/$soul/g" -e "s/<WREN_SOUL_VERSION>/$soul_v/g" \
    "$HERE/bin/wren-beat"
}

cmd_install_beat() {
  local ssh_target="${WREN_HOST:-}"
  if [ -z "$ssh_target" ]; then
    echo "deploy-droplet.sh --install-beat: refused - WREN_HOST is unset (ops@<droplet ip>)" >&2
    return 1
  fi
  validate_ssh_target "$ssh_target" "WREN_HOST"
  check_confirmed

  if [ -n "$(git -C "$PURSE_DIR" status --porcelain -- .)" ] || [ -n "$(git -C "$PKG_DIR" status --porcelain -- .)" ] || [ -n "$(git -C "$RUNTIME_DIR" status --porcelain -- .)" ]; then
    echo "deploy-droplet.sh --install-beat: refused - packages/purse, packages/wren or packages/agent-runtime has uncommitted changes; there is no committed sha to name as what shipped" >&2
    return 1
  fi
  local commit
  commit="$(git -C "$PKG_DIR" rev-parse HEAD)"

  for f in "$HERE/bin/wren-beat" "$PKG_DIR/run-flags.txt" "$RUNTIME_DIR/picoclaw/config.template.json" \
           "$PKG_DIR/systemd/wren-beat.service" "$PKG_DIR/systemd/wren-beat.timer" "$PURSE_DIR/bin/beat-phase2.ts" "$PKG_DIR/profile.json"; do
    if [ ! -f "$f" ]; then
      echo "deploy-droplet.sh --install-beat: refused - $f is missing" >&2
      return 1
    fi
  done

  WREN_INSTALL_STEP=""
  trap install_beat_on_exit EXIT
  record_run "install-beat-begin" "commit=$commit"

  local stage
  stage="$(mktemp -d "${TMPDIR:-/tmp}/wren-beat-stage.XXXXXX")"

  WREN_INSTALL_STEP="build_phase2_bundle"
  build_phase2_bundle "$stage/beat-phase2.js"
  local phase2_sha
  phase2_sha="$(file_sha256 "$stage/beat-phase2.js")"

  WREN_INSTALL_STEP="render_wren_beat"
  render_wren_beat "$phase2_sha" > "$stage/wren-beat"
  if grep -v '^[[:space:]]*#' "$stage/wren-beat" | grep -q '<[A-Z_0-9]*>'; then
    echo "deploy-droplet.sh --install-beat: refused - the rendered launcher still carries a substitution" >&2
    return 1
  fi
  bash -n "$stage/wren-beat"
  cp "$PKG_DIR/run-flags.txt" "$stage/run-flags.txt"
  cp "$RUNTIME_DIR/picoclaw/config.template.json" "$stage/config.template.json"
  cp "$PKG_DIR/systemd/wren-beat.service" "$stage/wren-beat.service"
  cp "$PKG_DIR/systemd/wren-beat.timer" "$stage/wren-beat.timer"
  cp "$PKG_DIR/profile.json" "$stage/profile.json"
  local launcher_sha
  launcher_sha="$(file_sha256 "$stage/wren-beat")"

  echo "deploy-droplet.sh --install-beat: shipping from commit $commit"
  echo "  beat-phase2.js       sha256 $phase2_sha  -> /srv/wren/purse/dist/beat-phase2.js 0644 root:root (pinned in the launcher)"
  echo "  wren-beat           sha256 $launcher_sha  -> /srv/wren/bin/wren-beat 0755 root:root"
  echo "  run-flags.txt                                              -> /srv/wren/run-flags.txt 0644 root:root"
  echo "  config.template.json                                       -> /srv/wren/picoclaw/config.template.json 0644 root:root"
  echo "  profile.json                                               -> /srv/wren/profile.json 0644 root:root (the name and bio phase two files)"
  echo "  wren-beat.service, wren-beat.timer                       -> /etc/systemd/system/ 0644 root:root (not enabled, not started)"

  WREN_INSTALL_STEP="ship_beat_files"
  ship_beat_files "$ssh_target" "$stage" "$phase2_sha" "$launcher_sha"

  WREN_INSTALL_SUCCEEDED=1
  trap - EXIT
  record_run "install-beat-succeeded" "commit=$commit phase2=$phase2_sha launcher=$launcher_sha"
  rm -rf "$stage"
  echo "deploy-droplet.sh --install-beat: the beat is installed on $ssh_target and NOT started. Next: --smoke, whose fourth gate runs one real beat and whose fifth enables the timers."
}

install_beat_on_exit() {
  local status=$?
  trap - EXIT
  if [ "$WREN_INSTALL_SUCCEEDED" = "1" ]; then return 0; fi
  echo "deploy-droplet.sh --install-beat: did not reach success (exit $status) at step '${WREN_INSTALL_STEP:-preconditions}'. The host is left as it was at that step; nothing is rolled back." >&2
  record_run "install-beat-failed" "step=${WREN_INSTALL_STEP:-preconditions}"
  exit "$status"
}

build_phase2_bundle() {
  if is_stubbed; then "$WREN_STUB_DIR/build_phase2_bundle" "$@"; return; fi
  local out="$1"
  (cd "$PURSE_DIR" && pnpm exec esbuild bin/beat-phase2.ts --bundle --platform=node --format=esm --target=node22 \
      --banner:js="import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);" \
      --log-level=warning --outfile="$out")
  [ -s "$out" ] || { echo "deploy-droplet.sh: the bundle at $out is empty or missing" >&2; return 1; }
}

ship_beat_files() {
  if is_stubbed; then "$WREN_STUB_DIR/ship_beat_files" "$@"; return; fi
  local ssh_target="$1" stage="$2" phase2_sha="$3" launcher_sha="$4"
  ssh -- "$ssh_target" 'rm -rf /tmp/wren-beat-stage && mkdir -m 0700 /tmp/wren-beat-stage'
  scp -q -- "$stage/beat-phase2.js" "$stage/wren-beat" "$stage/run-flags.txt" "$stage/config.template.json" \
      "$stage/wren-beat.service" "$stage/wren-beat.timer" "$stage/profile.json" "$ssh_target:/tmp/wren-beat-stage/"
  ssh -- "$ssh_target" sudo bash -s -- "$phase2_sha" "$launcher_sha" <<'REMOTE'
set -euo pipefail
S=/tmp/wren-beat-stage
check() { local actual; actual="$(sha256sum "$1" | cut -d' ' -f1)"; [ "$actual" = "$2" ] || { echo "host: refused - $1 hashes $actual, not $2 as shipped" >&2; exit 1; }; }
check "$S/beat-phase2.js" "$1"
check "$S/wren-beat" "$2"
echo "host: the shipped bundle and launcher hash as the laptop said"
install -d -m 0755 -o root -g root /srv/wren/picoclaw
install -m 0644 -o root -g root "$S/beat-phase2.js" /srv/wren/purse/dist/beat-phase2.js
install -m 0755 -o root -g root "$S/wren-beat" /srv/wren/bin/wren-beat
install -m 0644 -o root -g root "$S/run-flags.txt" /srv/wren/run-flags.txt
install -m 0644 -o root -g root "$S/config.template.json" /srv/wren/picoclaw/config.template.json
install -m 0644 -o root -g root "$S/profile.json" /srv/wren/profile.json
install -m 0644 -o root -g root "$S/wren-beat.service" /etc/systemd/system/wren-beat.service
install -m 0644 -o root -g root "$S/wren-beat.timer" /etc/systemd/system/wren-beat.timer
rm -rf "$S"
systemctl daemon-reload
bash -n /srv/wren/bin/wren-beat
systemd-analyze verify /etc/systemd/system/wren-beat.service 2>&1 | grep -v "^$" | head -5 || true
echo "host: beat files installed with their modes; wren-beat.service loaded, not started, no timer enabled"
REMOTE
}

# ---------------------------------------------------------------------------
# --rebuild-image. The image on the host is built once by --create and then frozen by its id in
# image.env; a change to the runtime package (the first real beat, 2026-09-05, ran an image whose
# beat.sh predated the workspace seeding) needs the same build again, from the committed tree,
# through the same tarball and sha256 check. Nothing else on the host is touched.
# ---------------------------------------------------------------------------
cmd_rebuild_image() {
  local ssh_target="${WREN_HOST:-}"
  if [ -z "$ssh_target" ]; then
    echo "deploy-droplet.sh --rebuild-image: refused - WREN_HOST is unset (ops@<droplet ip>)" >&2
    return 1
  fi
  validate_ssh_target "$ssh_target" "WREN_HOST"
  check_confirmed
  check_git_clean
  local ip="${ssh_target#*@}"
  record_run "rebuild-image-begin" "commit=$(git -C "$PKG_DIR" rev-parse HEAD)"
  build_image_on_host "$ip"
  record_run "rebuild-image-succeeded" "commit=$(git -C "$PKG_DIR" rev-parse HEAD)"
  echo "deploy-droplet.sh --rebuild-image: the image on $ssh_target is rebuilt from the committed tree and image.env carries its new id. No beat ran, no timer changed."
}

# ---------------------------------------------------------------------------
# --status. Read-only: what is on the host, and what the ACCOUNT says applies to it.
# ---------------------------------------------------------------------------
cmd_status() {
  local ssh_target="${WREN_HOST:-}"
  if [ -z "$ssh_target" ]; then
    echo "deploy-droplet.sh --status: refused - WREN_HOST is unset (ops@<droplet ip>)" >&2
    return 1
  fi
  validate_ssh_target "$ssh_target" "WREN_HOST"
  status_host "$ssh_target"
  if [ -n "${DO_TOKEN_FILE:-}" ]; then
    smoke_firewall_effective
  else
    echo "deploy-droplet.sh --status: DO_TOKEN_FILE is unset, so the account's own view of the firewall was NOT read. Set it to see the effective inbound ruleset for tag $FIREWALL_TAG." >&2
  fi
}

status_host() {
  if is_stubbed; then "$WREN_STUB_DIR/status_host" "$@"; return; fi
  local ssh_target="$1"
  ssh -- "$ssh_target" sudo bash -s <<'REMOTE'
systemctl list-timers 'wren-*' --no-pager
echo '--- wren-purse.service, wren-beat.service ---'
systemctl is-active wren-purse.service wren-beat.service 2>/dev/null | paste -sd' ' -
echo '--- state/latest.json ---'
cat /srv/wren/state/latest.json 2>/dev/null || echo '(none yet)'
echo '--- state/beats.jsonl, last 3 ---'
tail -n 3 /srv/wren/state/beats.jsonl 2>/dev/null || echo '(no beat recorded yet)'
echo '--- the watchdog record ---'
tail -n 5 /var/lib/wren/watchdog/alerts.jsonl 2>/dev/null || echo '(no notice has ever been recorded)'
REMOTE
}

# ---------------------------------------------------------------------------
main() {
  case "${1:-}" in
    --plan) cmd_plan ;;
    --create) cmd_create ;;
    --seal) shift; cmd_seal "$@" ;;
    --smoke) cmd_smoke ;;
    --status) cmd_status ;;
    --install-purse) cmd_install_purse ;;
    --install-ledger) cmd_install_ledger ;;
    --render-purse-unit) shift; render_purse_unit "$@" ;;
    --render-ledger-units) shift; render_ledger_units "$@" ;;
    --install-beat) cmd_install_beat ;;
    --rebuild-image) cmd_rebuild_image ;;
    --render-wren-beat) shift; render_wren_beat "$@" ;;
    --render-cloud-init) render_cloud_init ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
