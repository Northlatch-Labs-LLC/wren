#!/usr/bin/env -S npx tsx
// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * `heron-beat` phase two: the part that runs outside the container, as root, holding no key.
 *
 * ```
 * beat-phase2.ts --runs /srv/heron/runs --state /srv/heron/state --socket /run/heron/purse.sock \
 *                --chain /srv/heron/chain.json --beat-id 20260905T120000Z [--dry-run]
 * ```
 *
 * Exit codes: 0 signed, 0 no intent (nothing to do is not a failure), 3 refused, 1 error. The
 * refusal gets its own code because `OnFailure=heron-alert@%n.service` fires on a non-zero exit and
 * a policy denial is a thing the desk wants to see — but it is not the same alert as "the beat
 * broke", and the state file's `outcome` is what the puller reads to tell them apart.
 *
 * The exit code is written last. `state/latest.json` is already on disk by then, on every path,
 * including the ones that threw.
 */

import { readFile } from 'node:fs/promises';
import { createClient, readContentPrice, readCreatorVault, type ProjectXSocialConfig } from '@projectx-social/sdk';
import { loadChainConfig } from '../src/chain.js';
import { askPurse } from '../src/client.js';
import { runPhaseTwo, type SubmitPort } from '../src/beat.js';
import { readTransactionGasMist } from '../src/soul-read.js';
import { parseBeatArgs, parseProfile, DEFAULT_AGENT, DEFAULT_PROFILE, type Profile } from '../src/beat-args.js';

/**
 * Submit the signed bytes.
 *
 * The digest the node returns is read from the envelope and, if the node returns none, this throws
 * with a sentence that says the transaction may well have landed. Reporting "no digest" as a clean
 * failure is how the harvest daemon once recorded a real, successful, money-moving transaction as a
 * failure and the operator acted on the wrong belief; `packages/agent/src/tx.ts` carries the same
 * warning for the same reason.
 */
function chainSubmit(config: ProjectXSocialConfig): SubmitPort {
  const client = createClient(config);
  return {
    submit: async ({ txBytesB64, signature }) => {
      const result = (await client.executeTransaction({
        transaction: Uint8Array.from(Buffer.from(txBytesB64, 'base64')),
        signatures: [signature],
      })) as { Transaction?: { digest?: string }; transaction?: { digest?: string }; digest?: string };
      /*
        Three envelopes, not two.

        `packages/agent/src/tx.ts` already read all three; this copy read two, and the one it did
        not read — `Transaction` with a capital T — is the one the node actually returns. So on
        2026-09-07 at 05:08 a `set_content_price` was signed, submitted, and landed on chain as
        `9qE6uFVgzFcbAAsKAirjm8NAFmkG4g8AJ22fVSfBE4DY`, and this function threw "no digest in any
        envelope this client knows" and stopped the run before it published the post the price was
        for. The price is on chain with nothing behind it, for the second time.

        Two copies of one piece of knowledge, and only one of them was ever corrected.
      */
      const digest = result.Transaction?.digest ?? result.transaction?.digest ?? result.digest;
      if (typeof digest !== 'string' || digest === '') {
        throw new Error(
          'the transaction was submitted and the node returned no digest in any envelope this ' +
            'client knows. Check the chain before retrying — it may well have succeeded.',
        );
      }
      return digest;
    },
  };
}

const parsed = parseBeatArgs(process.argv.slice(2));
if (!parsed.ok) {
  process.stderr.write(`${DEFAULT_AGENT}-beat: ${parsed.refused.ruleId} — ${parsed.refused.reason}\n`);
  process.exit(1);
}
const args = parsed.value;
const prefix = `${args.agent}-beat`;

const chain = await loadChainConfig(args.chain);
if (!chain.ok) {
  process.stderr.write(`${prefix}: ${chain.refused.ruleId} — ${chain.refused.reason}\n`);
  process.exit(1);
}

/*
  The profile phase two publishes under. Heron's is the literal above and needs no file; a second
  citizen ships hers beside her units and names it here. A file that does not parse is a refusal
  before any network is touched, never a fall back to Heron's name under another agent's handle.
*/
let profile: Profile = DEFAULT_PROFILE;
if (args.profileFile !== null) {
  let text: string;
  try {
    text = await readFile(args.profileFile, 'utf8');
  } catch (error) {
    process.stderr.write(`${prefix}: request-malformed — the profile file ${args.profileFile} could not be read: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
  const parsedProfile = parseProfile(text);
  if (!parsedProfile.ok) {
    process.stderr.write(`${prefix}: ${parsedProfile.refused.ruleId} — ${parsedProfile.refused.reason}\n`);
    process.exit(1);
  }
  profile = parsedProfile.value;
}

/*
  The ports a publish plan needs: the API over HTTPS, the two object references from the node the
  purse's own chain document names, and the same submit the transaction path uses.
*/
const client = createClient(chain.value);
const publish =
  args.apiOrigin === null || args.address === null
    ? {}
    : {
        publish: {
          origin: args.apiOrigin,
          address: args.address,
          profile,
          ports: {
            http: {
              request: async (input: { method: 'GET' | 'POST'; url: string; body?: unknown; headers?: Record<string, string> }) => {
                const response = await fetch(input.url, {
                  method: input.method,
                  headers: { 'content-type': 'application/json', 'user-agent': `${prefix}/2 (${profile.name} host)`, ...(input.headers ?? {}) },
                  ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
                  signal: AbortSignal.timeout(60_000),
                });
                const text = await response.text();
                let json: unknown = null;
                try { json = JSON.parse(text); } catch { json = null; }
                return { status: response.status, json };
              },
            },
            chain: {
              sharedRef: async (objectId: string) => {
                const { object } = await client.core.getObject({ objectId });
                const owner = object.owner as { $kind?: string; Shared?: { initialSharedVersion: string } };
                if (owner.$kind !== 'Shared' || owner.Shared === undefined) throw new Error(`${objectId} is not a shared object`);
                return { objectId, initialSharedVersion: owner.Shared.initialSharedVersion, mutable: true as const };
              },
              ownedRef: async (objectId: string) => {
                const { object } = await client.core.getObject({ objectId });
                return { objectId, version: object.version, digest: object.digest };
              },
              /*
                What this key is already priced at, using the SDK's own reader rather than a second
                implementation of the same derivation. `readContentPrice` derives the table entry's
                child id from the table id and the BCS key, so it is one read whatever the vault
                holds.

                A read that fails answers null. The cost of a wrong null is one reprice to the price
                the key already has; the cost of a throw would be the very failure this fix removes.
              */
              priceOf: async ({ vaultId, contentKey }: { vaultId: string; contentKey: string; coinType: string }) => {
                try {
                  const vaultRead = await readCreatorVault(client, vaultId);
                  if (!vaultRead.ok) return null;
                  const priced = await readContentPrice(client, vaultRead.value.contentPricesTableId, contentKey);
                  return priced.ok && priced.value !== null ? priced.value.toString() : null;
                } catch {
                  return null;
                }
              },
            },
            submit: async (signed: { txBytesB64: string; signature: string }) => chainSubmit(chain.value).submit(signed),
          },
        },
      };

const { state, statePath } = await runPhaseTwo({
  runsDir: args.runs,
  stateDir: args.state,
  beatId: args.beatId,
  ask: { ask: (intent) => askPurse({ socketPath: args.socket, intent }) },
  ...(args.dryRun ? {} : { submit: chainSubmit(chain.value) }),
  ...(args.dryRun ? {} : publish),
  ...(args.soul === null
    ? {}
    : {
        recordSpend: {
          packageId: args.soul.packageId,
          soul: { objectId: args.soul.soulId, initialSharedVersion: args.soul.soulVersion },
          gasOf: (digest: string) => readTransactionGasMist(args.soul!.graphql, digest),
        },
      }),
});

process.stderr.write(
  `${prefix}: ${state.beatId} ${state.outcome}` +
    (state.ruleId === undefined ? '' : ` rule=${state.ruleId}`) +
    (state.digest === undefined ? '' : ` digest=${state.digest}`) +
    (state.submittedDigest === undefined ? '' : ` submitted=${state.submittedDigest}`) +
    (state.postId === undefined ? '' : ` post=${state.postId}`) +
    (state.spentMist === undefined ? '' : ` spent=${state.spentMist}`) +
    (state.spendError === undefined ? '' : ` spend-unbooked=${state.spendError}`) +
    /*
      The reason, not just the rule. A run that refused with `intent-invalid-locally` and nothing
      else told the operator only that something was wrong with the plan file — a truncated write
      and a forbidden field read identically in the log, and the file itself is inside a run
      directory nobody reads. The reason is one line and it is the difference between a diagnosis
      and a guess.
    */
    (state.error === undefined ? '' : ` reason=${JSON.stringify(state.error)}`) +
    ` state=${statePath}\n`,
);

process.exit(state.outcome === 'refused' ? 3 : state.outcome === 'error' ? 1 : 0);
