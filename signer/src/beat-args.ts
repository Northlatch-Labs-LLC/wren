// Built-by: @projectx.sui
/**
 * Phase two's argument parsing and the profile it publishes under, as a module with no side
 * effects: `bin/beat-phase2.ts` runs at import (it is the process), so anything a test needs to
 * call lives here instead. The defaults are Heron's, unchanged; a second citizen names hers by
 * flag (`--agent wren --profile-file /srv/wren/profile.json`).
 */

import { allow, refuse, type Outcome } from './outcome.js';

export interface BeatArgs {
  readonly runs: string;
  readonly state: string;
  readonly socket: string;
  readonly chain: string;
  readonly beatId: string;
  readonly dryRun: boolean;
  /** Both or neither: with them a publish plan runs; without them it is refused locally. */
  readonly apiOrigin: string | null;
  readonly address: string | null;
  /** The agent's name: the log prefix and the User-Agent. `heron` when not given. */
  readonly agent: string;
  /** A JSON file `{ "name", "bio" }` phase two publishes under; Heron's literal when not given. */
  readonly profileFile: string | null;
  /** All four together, or null. See the note where they are parsed. */
  readonly soul: {
    readonly packageId: string;
    readonly soulId: string;
    readonly soulVersion: string;
    readonly graphql: string;
  } | null;
}

const FLAGS = ['--runs', '--state', '--socket', '--chain', '--beat-id', '--api-origin', '--address', '--agent', '--profile-file', '--soul', '--soul-version', '--soul-package', '--graphql'] as const;
// The soul flags are optional together: a deployment without a soul books no spend and is a real
// deployment, not a broken one. Their all-or-nothing rule is enforced below, not here.
const OPTIONAL = new Set<string>([
  '--api-origin', '--address', '--agent', '--profile-file',
  '--soul', '--soul-version', '--soul-package', '--graphql',
]);
export const DEFAULT_AGENT = 'heron';
const AGENT_NAME = /^[a-z][a-z0-9-]{0,31}$/;
/** Heron's, unchanged: the profile the first citizen has always published under. */
export const DEFAULT_PROFILE = {
  name: 'Heron',
  bio: 'A Northlatch Labs agent. It reads the network, writes what it sees, and prices its own writing; every signature it produces is bounded by a policy under a human operator.',
} as const;
/** The profile route's own limits (packages/web), pinned by test in publish.test.ts. */
const PROFILE_NAME_MAX = 60;
const PROFILE_BIO_MAX = 280;

export interface Profile {
  readonly name: string;
  readonly bio: string;
}

/** Read and validate a profile file. A refusal names the field; it never echoes the file. */
export function parseProfile(text: string): Outcome<Profile> {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return refuse('request-malformed', 'the profile file is not JSON.');
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return refuse('request-malformed', 'the profile file is not an object.');
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.join(',') !== 'bio,name') return refuse('request-malformed', 'the profile file carries exactly "name" and "bio" and nothing else.');
  const name = record['name'];
  const bio = record['bio'];
  if (typeof name !== 'string' || name.trim() === '' || name.length > PROFILE_NAME_MAX || /[\r\n\u0000-\u001f\u007f]/.test(name)) {
    return refuse('request-malformed', `profile.name is one line of at most ${String(PROFILE_NAME_MAX)} characters.`);
  }
  if (typeof bio !== 'string' || bio.trim() === '' || bio.length > PROFILE_BIO_MAX || /[\r\n\u0000-\u001f\u007f]/.test(bio)) {
    return refuse('request-malformed', `profile.bio is one line of at most ${String(PROFILE_BIO_MAX)} characters.`);
  }
  return allow({ name, bio });
}

export function parseBeatArgs(argv: readonly string[]): Outcome<BeatArgs> {
  const values = new Map<string, string>();
  let dryRun = false;

  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i]!;
    if (flag === '--dry-run') {
      dryRun = true;
      continue;
    }
    if (!FLAGS.includes(flag as (typeof FLAGS)[number])) {
      return refuse(
        'request-malformed',
        `${flag} is not a flag this takes. It takes: ${FLAGS.join(' ')} [--dry-run].`,
      );
    }
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) {
      return refuse('request-malformed', `${flag} needs a value.`);
    }
    values.set(flag, value);
    i += 1;
  }

  for (const flag of FLAGS) {
    if (!OPTIONAL.has(flag) && !values.has(flag)) return refuse('request-malformed', `${flag} is required.`);
  }
  const apiOrigin = values.get('--api-origin') ?? null;
  const address = values.get('--address') ?? null;
  if ((apiOrigin === null) !== (address === null)) {
    return refuse('request-malformed', '--api-origin and --address are given together or not at all.');
  }
  if (apiOrigin !== null && !/^https:\/\/[a-z0-9.-]+$/.test(apiOrigin)) return refuse('request-malformed', '--api-origin is an https origin with no path.');
  if (address !== null && !/^0x[0-9a-f]{64}$/.test(address)) return refuse('request-malformed', '--address is a full lower-case Sui address.');
  const agent = values.get('--agent') ?? DEFAULT_AGENT;
  if (!AGENT_NAME.test(agent)) return refuse('request-malformed', '--agent is a name matching ^[a-z][a-z0-9-]{0,31}$.');
  const profileFile = values.get('--profile-file') ?? null;

  /*
    The soul, or none of it. Booking a spend needs four facts — the package, the soul's id and its
    shared version, and a chain endpoint to read the gas from. Three of the four is a deployment
    that would book nothing and report nothing, so it is refused here where somebody is reading the
    error, rather than at 03:00 in a journal nobody opens.
  */
  const soulFlags = ['--soul', '--soul-version', '--soul-package', '--graphql'] as const;
  const present = soulFlags.filter((flag) => values.has(flag));
  if (present.length !== 0 && present.length !== soulFlags.length) {
    return refuse(
      'request-malformed',
      `${soulFlags.join(', ')} are given together or not at all; ${present.join(', ')} alone books nothing.`,
    );
  }
  const soul =
    present.length === 0
      ? null
      : {
          packageId: values.get('--soul-package')!,
          soulId: values.get('--soul')!,
          soulVersion: values.get('--soul-version')!,
          graphql: values.get('--graphql')!,
        };
  if (soul !== null) {
    if (!/^0x[0-9a-f]{1,64}$/.test(soul.packageId)) return refuse('request-malformed', '--soul-package is a lower-case Sui id.');
    if (!/^0x[0-9a-f]{1,64}$/.test(soul.soulId)) return refuse('request-malformed', '--soul is a lower-case Sui id.');
    if (!/^(0|[1-9][0-9]{0,19})$/.test(soul.soulVersion)) return refuse('request-malformed', '--soul-version is a u64 decimal string.');
    if (!/^https:\/\/[a-z0-9.-]+\/[a-z]*$/.test(soul.graphql)) return refuse('request-malformed', '--graphql is an https endpoint.');
  }

  return allow({
    runs: values.get('--runs')!,
    state: values.get('--state')!,
    socket: values.get('--socket')!,
    chain: values.get('--chain')!,
    beatId: values.get('--beat-id')!,
    dryRun,
    apiOrigin,
    address,
    agent,
    profileFile,
    soul,
  });
}

