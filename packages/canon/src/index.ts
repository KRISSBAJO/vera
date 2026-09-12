import { createHash } from 'node:crypto';
import canonicalize from 'canonicalize';

/**
 * Canonical action form and hash (brief §6.3, threat T02, SR-02).
 *
 * The hash covers exactly: canon version, action class, tool, arguments, target kind+id, environment.
 * Nothing VERA enriches (sensitivity, context, evidence) is included, so an adapter and the server
 * always compute the same hash from the same tool call.
 *
 * Normalization rules (versioned by CANON_VERSION — bump on any change):
 *   1. Object keys are NFC-normalized. Values are never normalized: strings are hashed byte-exact.
 *   2. `undefined` properties are dropped; `null` is kept.
 *   3. Arrays keep their order.
 *   4. Serialization is RFC 8785 JCS (sorted keys, ES number formatting, minimal escapes).
 *   5. Digest is SHA-256 over the UTF-8 bytes of the JCS string, rendered as `sha256:<hex>`.
 *
 * Consequence of rule 1 + 4: `1` and `1.0` hash identically (they are the same JSON number), while
 * `"1"` and `1` differ. Trailing whitespace, homoglyphs, and expansion syntax in a shell string all
 * produce different hashes — that is the point.
 */
export const CANON_VERSION = 1;

export interface CanonInput {
  class: string;
  tool: string;
  arguments: Record<string, unknown>;
  target?: { kind: string; id: string } | undefined;
  environment?: string | undefined;
}

export interface CanonicalAction {
  v: number;
  class: string;
  tool: string;
  arguments: unknown;
  target: { kind: string; id: string } | null;
  environment: string | null;
}

/** Recursively drop `undefined`, NFC-normalize keys, leave values untouched. */
export function normalizeValue(value: unknown): unknown {
  if (value === undefined) return undefined;
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((v) => (v === undefined ? null : normalizeValue(v)));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (v === undefined) continue;
    out[k.normalize('NFC')] = normalizeValue(v);
  }
  return out;
}

export function canonicalAction(input: CanonInput): CanonicalAction {
  if (typeof input.class !== 'string' || input.class.length === 0) throw new TypeError('class is required');
  if (typeof input.tool !== 'string' || input.tool.length === 0) throw new TypeError('tool is required');
  return {
    v: CANON_VERSION,
    class: input.class,
    tool: input.tool,
    arguments: normalizeValue(input.arguments ?? {}),
    target: input.target ? { kind: input.target.kind, id: input.target.id } : null,
    environment: input.environment ?? null,
  };
}

/** RFC 8785 string of the canonical action. Exposed so receivers in other languages can cross-check. */
export function canonicalString(input: CanonInput): string {
  const s = canonicalize(canonicalAction(input));
  if (s === undefined) throw new TypeError('action is not serializable');
  return s;
}

export function actionHash(input: CanonInput): string {
  return `sha256:${createHash('sha256').update(canonicalString(input), 'utf8').digest('hex')}`;
}

export function isActionHash(s: string): boolean {
  return /^sha256:[0-9a-f]{64}$/.test(s);
}

// ---------- shell analysis (threat T02: indirect input) ----------

export interface ShellAnalysis {
  indirect: boolean;
  /** Which constructs were found, for the reviewer's `ACTION.INDIRECT_INPUT` detail. */
  constructs: string[];
}

const INDIRECT_PATTERNS: ReadonlyArray<[string, RegExp]> = [
  ['variable expansion', /\$[A-Za-z_{]/],
  ['positional or special parameter', /\$[0-9@*#?!$-]/],
  ['command substitution $(…)', /\$\(/],
  ['backtick substitution', /`/],
  ['process substitution', /[<>]\(/],
  ['eval', /(^|[\s;&|])eval\s/],
  ['source / dot-include', /(^|[\s;&|])(source|\.)\s+\S/],
  ['piped remote content', /\b(curl|wget)\b[^|]*\|\s*(sh|bash|zsh|python\d?|node|perl)\b/],
];

/**
 * Detects shell constructs whose effect is resolved at execution time, so the literal string a reviewer
 * sees is not exactly what will run. Conservative by design: false positives cost a question, false
 * negatives cost a bypass.
 */
export function analyzeShell(command: string): ShellAnalysis {
  const constructs = INDIRECT_PATTERNS.filter(([, re]) => re.test(command)).map(([name]) => name);
  return { indirect: constructs.length > 0, constructs };
}
