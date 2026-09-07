// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * `@projectx-social/purse` — the one process on Heron's host that holds the hot key.
 *
 * Heron's address is a **1-of-2 multisig** (the Master's ruling, 2026-09-05): the hot key signs
 * alone behind the policy, and the second member is the brake, held by his hand and never on this
 * laptop or on the host. So there is no co-signing purse and there is no second host. The bound on
 * a leaked hot key is one epoch's allowance until it is swept, and that cost was accepted on the
 * page rather than engineered away.
 *
 * Everything that makes that acceptable lives here: the container never holds a key and never
 * produces bytes; the purse builds the transaction from a typed intent; `policySigner` runs its
 * five steps; every decision, including the refusals that never reached the signer, lands in a
 * hash-chained file.
 */

export {
  AuditFile,
  GENESIS_HASH,
  entryPreimage,
  hashEntry,
  readAuditFile,
  verifyAuditLines,
  type ChainVerdict,
  type PurseAuditFields,
  type PurseAuditLine,
  type PurseOutcomeName,
  type ReadAuditResult,
} from './audit-file.js';

export { buildIntent, fixedGas, nodeGas, type GasCoinRef, type GasPort } from './build.js';

export { chainConfigSchema, loadChainConfig, type ChainConfig } from './chain.js';

export {
  loadMultisigDoc,
  multisigDocSchema,
  wrapAsMultisig,
  type LoadedMultisig,
  type MultisigDoc,
  type MultisigWrapped,
} from './multisig-file.js';

export { askPurse, type AskOptions } from './client.js';

export {
  INTENT_FILE,
  runPhaseTwo,
  type AskPort,
  type PhaseTwoOptions,
  type PhaseTwoResult,
  type SubmitPort,
} from './beat.js';

export {
  canonicalJson,
  intentHash,
  intentSchema,
  ownedObjectRef,
  parseIntent,
  postIntent,
  priceIntent,
  settleEpochIntent,
  sharedObjectRef,
  type Intent,
  type IntentKind,
  type OwnedObjectRef,
  type SharedObjectRef,
} from './intent.js';

export {
  CREDENTIAL_NAME,
  loadHotKey,
  refuseKeyInProcessSurface,
  type KeySource,
  type LoadedKey,
} from './key.js';

export { SpendLedger, outflowsOf } from './ledger-file.js';

export {
  PURSE_REFUSAL_IDS,
  allow,
  refuse,
  ruleIdIn,
  type Outcome,
  type Refusal,
  type RefusalId,
  type PurseRefusalId,
} from './outcome.js';

export { loadPinnedPolicy, policyDocSchema, type PinnedPolicy } from './policy-file.js';

export {
  MAX_REQUEST_BYTES,
  requestSchema,
  type PurseResponse,
  type RefusedResponse,
  type SignedResponse,
} from './protocol.js';

export { createPurse, type Purse, type PurseOptions } from './purse.js';

export { parseServerArgs, startPurse, type RunningPurse, type ServerArgs } from './server.js';

export { STATE_FILE, writeState, type BeatOutcome, type BeatState } from './state.js';

export { directive, onlyValue, parseUnit, type ParsedUnit } from './units.js';
