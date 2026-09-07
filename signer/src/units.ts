// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * A small reader for systemd unit files, so the hardening can be a test rather than a promise.
 *
 * # Why parse them at all
 *
 * v1 shipped an SSH hardening file named `99-heron.conf` that sorted *after* cloud-init's own and
 * lost every keyword it set. Nobody noticed, because nothing read the file back. A directive that
 * is only in a file nobody parses is a directive that is only in a comment.
 *
 * `test/units.test.ts` reads the three units in `systemd/` and asserts the directives the CISO's §2
 * names. It is not a systemd implementation and does not try to be: it does not resolve drop-ins,
 * does not expand specifiers, and does not know which directives conflict. It answers one question —
 * "is this directive in this file with this value" — which is the question the review asks.
 *
 * # What it does handle, because unit files really do this
 *
 * `key=value`, sections, `#` and `;` comments, line continuations with a trailing backslash, and a
 * key appearing more than once (which for most systemd directives means a list, so values are
 * collected rather than overwritten). An empty value — `ExecStart=` on its own — is systemd's way
 * of resetting a list and is preserved as an empty string rather than dropped.
 */

export interface ParsedUnit {
  /** Section name to directives; a directive maps to every value it was given, in order. */
  readonly sections: ReadonlyMap<string, ReadonlyMap<string, readonly string[]>>;
}

export function parseUnit(text: string): ParsedUnit {
  const sections = new Map<string, Map<string, string[]>>();
  let current = '';

  const logical: string[] = [];
  let pending = '';
  let continued = false;
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (line.endsWith('\\')) {
      pending += `${line.slice(0, -1)} `;
      continued = true;
      continue;
    }
    // A continued line is re-joined with single spaces. systemd tokenises `ExecStart` on
    // whitespace, so the indentation a human used to wrap the line is not part of the value; a
    // reader that kept it would compare unequal to the same command written on one line.
    logical.push(continued ? (pending + line).replace(/[ \t]+/g, ' ').trim() : pending + line);
    pending = '';
    continued = false;
  }
  if (pending !== '') logical.push(pending.replace(/[ \t]+/g, ' ').trim());

  for (const line of logical) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;

    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      current = trimmed.slice(1, -1);
      if (!sections.has(current)) sections.set(current, new Map());
      continue;
    }

    const equals = trimmed.indexOf('=');
    if (equals === -1) continue;
    const key = trimmed.slice(0, equals).trim();
    const value = trimmed.slice(equals + 1).trim();

    let section = sections.get(current);
    if (section === undefined) {
      section = new Map();
      sections.set(current, section);
    }
    const existing = section.get(key);
    if (existing === undefined) section.set(key, [value]);
    else existing.push(value);
  }

  return { sections };
}

/** Every value given for a directive in a section; empty when it was never given. */
export function directive(unit: ParsedUnit, section: string, key: string): readonly string[] {
  return unit.sections.get(section)?.get(key) ?? [];
}

/** The single value of a directive, or `null` when it was not given exactly once. */
export function onlyValue(unit: ParsedUnit, section: string, key: string): string | null {
  const values = directive(unit, section, key);
  return values.length === 1 ? values[0]! : null;
}
