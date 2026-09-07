// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * A real `SuiGrpcClient`, built by the real `createClient`, in a real node process started with the
 * flags the unit's own ExecStart carries. No fixture, no double, no recorded response.
 *
 * # The hole this fills
 *
 * `src/server.ts` reads its client as `args.recorded?.client ?? createClient(chain.value)`, and
 * every suite in this package supplies `recorded`. That seam is right — the other tests are about
 * the decision, and a decision test must not depend on a fullnode — but it means the expression on
 * the right of the `??` had never been evaluated by a test, on any node, under any flags. The whole
 * suite was green while the purse's first PAID post on the droplet died the moment it tried to
 * simulate, because `--jitless` in the unit removes `WebAssembly` from the runtime and node 22's
 * fetch parses HTTP with a WebAssembly build of llhttp. Every check the estate had asserted the
 * flag was PRESENT; `units.test.ts` defended the defect it was supposed to catch.
 *
 * A test that mocks the client cannot see this, and neither can a test that reads the unit file:
 * the failure is not in the argv and not in the code, it is in what the argv leaves of the runtime
 * the code needs. The only thing that sees it is a process started the way systemd starts it, with
 * the real client in it. That is all this file does.
 *
 * # Pass and fail, stated precisely, because the network is not a condition of this test
 *
 *   PASS  the client is constructed and gets far enough to attempt a request, and the request fails
 *         on DNS or on the connection. `CHAIN.grpcUrl` is `.invalid`, a TLD the DNS root guarantees
 *         will never resolve, so the reachable outcome is exactly the unreachable one and this test
 *         behaves the same on a laptop, in CI and on an air-gapped box.
 *   FAIL  anything in the failure names WebAssembly, or the child dies rather than answering. That
 *         is the production crash, and it is the only thing being asserted.
 *
 * A network error is not a weaker result here. Constructing the client and reaching the transport
 * is the entire distance between "the purse can sign" and what the droplet did; the fullnode's
 * answer adds nothing to it and would add a dependency on somebody else's uptime.
 *
 * # Which node runs the child, and why that is its own test
 *
 * The unit names `/opt/node22/bin/node`, and node 22 is the runtime this defect is fatal on: from
 * node 24 the built-in HTTP parser is native rather than a WebAssembly module, so `--jitless` no
 * longer takes fetch down with it and the crash hides on a modern laptop. A host without that
 * interpreter therefore cannot run this check at all; it can only run a differently-shaped check
 * that happens to be green.
 *
 * The first pass of this file printed a stderr warning in that case and passed. That is the same
 * mistake in a smaller font. `scripts/check-all.py` states the house rule for exactly this:
 * "A declared gate whose tool is missing is a FAILURE, not a skip", and the rung it adds under
 * everything else — "measured, versus assumed because nothing said otherwise". A warning next to a
 * green tick is an assumption; nobody reads it, and CI reads it least of all.
 *
 * So the two claims are two tests, because they are two different facts and they fail for two
 * different reasons:
 *
 *   1. `the real chain client ... is constructed and reaches the transport` — a claim about the
 *      code, on whatever runtime was actually available. It is true and useful on any node.
 *   2. `the interpreter the unit names is the one this ran on` — a claim about the measurement
 *      itself. It is false on a host without `/opt/node22/bin/node`, and false is the honest
 *      answer, because on such a host test 1's green says nothing whatever about the droplet.
 *
 * Splitting them means a laptop run reads "the client is fine; the droplet's runtime was not
 * measured here" instead of one green tick that quietly means both. Merging them would have made
 * test 1 red for a reason that is not a defect in the code, which is how a real gate gets deleted.
 * Both are the same child process, run once and shared.
 *
 * # Why the flags are read out of the unit rather than written here
 *
 * A literal `--jitless` in this file would pin what somebody typed once. Reading ExecStart pins
 * what the deploy will actually run: reintroduce the flag in the unit and this test starts the
 * child with it, on the runtime the unit names, and the WebAssembly failure comes back.
 */

import { describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { access, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { directive, parseUnit } from '../src/units.js';
import { CHAIN, PACKAGE, temporaryDirectory } from './helpers.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const UNIT = join(HERE, '..', 'systemd', 'heron-purse.service');

/** `createClient` as the compiled artefact, which is what `dist/server.js` imports on the droplet. */
const SDK_ENTRY = pathToFileURL(
  join(HERE, '..', 'node_modules', '@projectx-social', 'sdk', 'dist', 'index.js'),
).href;

interface ExecStart {
  /** The interpreter the unit names, absolute, as written. */
  readonly interpreter: string;
  /** Every argument between the interpreter and the script — the flags node itself is given. */
  readonly flags: readonly string[];
  /** The script the unit runs. */
  readonly script: string;
}

/**
 * Split ExecStart into interpreter, node's own flags, and the script.
 *
 * systemd tokenises Exec lines on whitespace and `parseUnit` has already rejoined the wrapped
 * lines, so the first token is the interpreter and everything up to the first `.js` belongs to
 * node. The purse's own arguments come after and are not this test's business.
 */
function execStart(text: string): ExecStart {
  const line = directive(parseUnit(text), 'Service', 'ExecStart').join(' ');
  const tokens = line.split(' ').filter((token) => token !== '');
  const script = tokens.findIndex((token) => token.endsWith('.js'));
  expect(script, `ExecStart names no script: ${line}`).toBeGreaterThan(0);
  return {
    interpreter: tokens[0]!,
    flags: tokens.slice(1, script),
    script: tokens[script]!,
  };
}

/**
 * The child, written out rather than passed with `-e`.
 *
 * `-e` puts the program into `process.execArgv`, and this test asserts against `execArgv` to prove
 * the flags actually reached the child; a file keeps that assertion about the unit's flags and
 * nothing else. Everything is caught and reported as JSON on stdout, so a WebAssembly failure
 * arrives here as a described cause chain instead of as a stack trace and an exit code.
 */
const CHILD = `
const causes = (error) => {
  const out = [];
  let current = error;
  while (current !== undefined && current !== null && out.length < 8) {
    out.push(\`\${current?.constructor?.name ?? typeof current}: \${String(current?.message ?? current)}\`);
    current = current.cause;
  }
  return out;
};

const report = {
  execArgv: process.execArgv,
  version: process.version,
  webAssembly: typeof WebAssembly,
  constructed: false,
  reachedTransport: false,
  failure: [],
};

try {
  const { createClient } = await import(process.argv[2]);
  const client = createClient(JSON.parse(process.argv[3]));
  report.constructed = typeof client.simulateTransaction === 'function';
  try {
    await client.getObject({ objectId: process.argv[4], include: { content: true } });
    report.reachedTransport = true;
  } catch (error) {
    // Reaching the transport and being refused by it IS the pass. The refusal is described, not
    // swallowed, so the assertion below can tell a name lookup apart from a missing runtime.
    report.reachedTransport = true;
    report.failure = causes(error);
  }
} catch (error) {
  report.failure = causes(error);
}

process.stdout.write(JSON.stringify(report));
`;

interface Report {
  readonly execArgv: readonly string[];
  readonly version: string;
  readonly webAssembly: string;
  readonly constructed: boolean;
  readonly reachedTransport: boolean;
  readonly failure: readonly string[];
}

interface Run {
  readonly report: Report | null;
  /** The interpreter that actually started the child. */
  readonly runtime: string;
  /** The interpreter the unit's ExecStart names, whether or not this host has it. */
  readonly named: string;
  /** True only when `runtime` is `named` — i.e. when this run measured what the unit deploys. */
  readonly measuredTheUnitsRuntime: boolean;
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function runUnderUnitFlags(): Promise<Run> {
  const { interpreter, flags } = execStart(await readFile(UNIT, 'utf8'));
  const present = await exists(interpreter);
  const runtime = present ? interpreter : process.execPath;

  const dir = await temporaryDirectory('heron-purse-smoke-');
  const childPath = join(dir, 'construct-client.mjs');
  await writeFile(childPath, CHILD, 'utf8');

  const config = JSON.stringify({
    network: CHAIN.network,
    grpcUrl: CHAIN.grpcUrl,
    packageId: CHAIN.packageId,
    latestPackageId: CHAIN.latestPackageId,
    platformId: CHAIN.platformId,
    registryId: CHAIN.registryId,
  });

  return new Promise<Run>((resolve) => {
    execFile(
      runtime,
      [...flags, childPath, SDK_ENTRY, config, PACKAGE],
      { timeout: 60_000, maxBuffer: 4 * 1024 * 1024 },
      (error, stdout, stderr) => {
        let report: Report | null = null;
        try {
          report = JSON.parse(stdout) as Report;
        } catch {
          // Left null. The assertions report the raw streams, which is what a child that died
          // before it could answer leaves behind.
        }
        const code = error === null ? 0 : ((error as { code?: number }).code ?? null);
        resolve({
          report,
          runtime,
          named: interpreter,
          measuredTheUnitsRuntime: present && runtime === interpreter,
          code,
          stdout,
          stderr,
        });
      },
    );
  });
}

/**
 * One child process, shared by both tests below.
 *
 * They assert about the same run — the client's behaviour, and whether that run was on the runtime
 * the unit deploys — so running the child twice would let the two answers disagree.
 */
let once: Promise<Run> | undefined;
function theRun(): Promise<Run> {
  once ??= runUnderUnitFlags();
  return once;
}

/** Everything the child said, for a failure message that names the runtime it was said on. */
function transcript(run: Run): string {
  return [
    `runtime: ${run.runtime}`,
    `unit names: ${run.named}`,
    `node: ${run.report?.version ?? 'unknown'}`,
    `exit: ${String(run.code)}`,
    `WebAssembly: ${run.report?.webAssembly ?? 'unknown'}`,
    `failure: ${(run.report?.failure ?? []).join(' <- ') || '(none)'}`,
    `stderr: ${run.stderr.trim() || '(empty)'}`,
  ].join('\n');
}

const NAMES_WEBASSEMBLY = /WebAssembly|WASM/i;

describe('the real chain client, under the unit\'s own node flags', () => {
  it('is constructed and reaches the transport, and never dies on a missing WebAssembly', async () => {
    const run = await theRun();
    const detail = transcript(run);

    // The child answered at all. A process that dies under these flags has already failed the
    // thing this test exists for, and it must not be able to do so quietly.
    expect(run.report, `the child wrote no report.\n${detail}\nstdout: ${run.stdout}`).not.toBeNull();
    const report = run.report!;
    expect(run.code, `the child exited non-zero.\n${detail}`).toBe(0);

    // The flags really reached it. Without this a green run could mean the child was started
    // plainly and the unit's flags were never exercised at all — the same shape of blind spot
    // that let --jitless through in the first place.
    const { flags } = execStart(await readFile(UNIT, 'utf8'));
    expect(report.execArgv, `the unit's flags did not reach the child.\n${detail}`).toEqual([
      ...flags,
    ]);

    expect(report.constructed, `createClient did not produce a usable client.\n${detail}`).toBe(true);
    expect(report.reachedTransport, `the client never attempted a request.\n${detail}`).toBe(true);

    /*
      Whether this runtime could have reproduced the droplet at all is NOT asserted here — it is
      the second test in this file, so that "the client is fine" and "we measured the runtime the
      unit ships" fail separately and say different things. See the header.
    */

    // The one failure this test is about. A DNS or connection error is expected and is a pass;
    // a runtime that cannot compile WebAssembly is the droplet's crash and is not.
    for (const cause of report.failure) {
      expect(
        NAMES_WEBASSEMBLY.test(cause),
        `the client failed on WebAssembly, not on the network — this is the crash the purse ` +
          `died of on 2026-09-05, and the unit's flags reproduce it.\n${detail}`,
      ).toBe(false);
    }
    expect(
      NAMES_WEBASSEMBLY.test(run.stderr),
      `the child printed a WebAssembly failure.\n${detail}`,
    ).toBe(false);
  }, 90_000);

  /*
    The gate on the measurement itself.

    The test above can be green on any node in existence. It means what it says about the droplet
    only if the child ran on the interpreter the droplet runs, because `--jitless` is fatal to fetch
    on node 22's WebAssembly HTTP parser and harmless on node 24+'s native one. On a host without
    `/opt/node22/bin/node` the test above measured a different runtime and proved a different thing.

    `scripts/check-all.py`: "A declared gate whose tool is missing is a FAILURE, not a skip." The
    tool this gate declares is the unit's own interpreter. It is missing here, so this is red, and
    red is the true answer — the previous pass printed this as a warning and stayed green, which is
    the same silence that let `--jitless` ship.
  */
  it('ran on the interpreter the unit names, so this suite measured the droplet\'s runtime', async () => {
    const run = await theRun();

    expect(
      run.measuredTheUnitsRuntime,
      [
        'NOT MEASURED: the crash this file exists for was not exercised on this host.',
        '',
        `The unit's ExecStart names ${run.named}; this host does not have it, so the child ran on`,
        `${run.runtime} (${run.report?.version ?? 'unknown'}) instead.`,
        '',
        'What that leaves unmeasured: --jitless removes WebAssembly from every node, but only a node',
        "whose HTTP parser is a WebAssembly module dies of it. That is node 22 — the version the unit",
        'names. From node 24 the parser is native, so fetch survives the flag and the droplet crash of',
        "2026-09-05 cannot reproduce here. The preceding test's green describes this laptop's runtime",
        'and vouches for no other.',
        '',
        'How to measure it — either is sufficient:',
        `  1. Install the runtime the unit names, at that exact path, and re-run:`,
        `       curl -fsSLO https://nodejs.org/dist/v22.x.y/node-v22.x.y-<platform>.tar.xz`,
        `       # verify against SHASUMS256.txt, then unpack so that ${run.named} exists`,
        '       pnpm --filter @projectx-social/purse test',
        '  2. Or run this suite on the droplet, where /opt/node22/bin/node is what systemd starts.',
        '',
        'Do not delete this assertion to get a green suite. A check that cannot fail is not a check.',
      ].join('\n'),
    ).toBe(true);

    // Present is not enough: it must also be the node the unit's comment justifies. A /opt/node22
    // that is secretly node 24 would satisfy the path and measure nothing, which is the same defect
    // wearing the right filename.
    const version = run.report?.version ?? '';
    expect(
      /^v22\./.test(version),
      `${run.named} exists but reports ${version || 'no version'}. The unit installs node 22 there ` +
        `because @mysten/sui requires it and because 22's HTTP parser is the WebAssembly one this ` +
        `test is about. A different major at that path measures a different runtime under the ` +
        `unit's own name.`,
    ).toBe(true);
  }, 90_000);
});
