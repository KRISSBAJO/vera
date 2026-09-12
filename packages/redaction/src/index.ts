/**
 * Redaction (SR-15, threat T18).
 *
 * Tool arguments are full of credentials: `psql postgres://user:pw@host/db`, `PGPASSWORD=… psql`,
 * `curl -H "Authorization: Bearer …"`, a `.env` being written. VERA stores those arguments, renders
 * them to reviewers, and may send them to a model. Every one of those is a way for VERA to become the
 * breach it was built to prevent.
 *
 * So: the rendered form is redacted before it is stored, and the raw form is sealed (encrypted at
 * rest) and only revealed by an audited, step-up action.
 *
 * Two principles shape the patterns below:
 *   1. **Say what was removed.** `[redacted:aws-access-key-id]` tells a reviewer a credential was
 *      there and what kind — `***` tells them nothing and invites them to reveal the raw value.
 *   2. **Prefer a false positive.** Masking a harmless string costs a reviewer a moment; leaking a
 *      live key costs an incident. Where a rule is ambiguous, it redacts.
 */

export interface RedactionRule {
  /** Stable name; appears in the placeholder and in the findings list. */
  name: string;
  pattern: RegExp;
  /**
   * Which capture group holds the secret. 0 (default) masks the whole match; 1 masks only the
   * captured part, so `PGPASSWORD=` stays readable and only the value disappears.
   */
  group?: number;
}

/** Ordered: earlier rules win, so specific vendor tokens mask before the generic assignment rule. */
export const DEFAULT_RULES: readonly RedactionRule[] = [
  {
    name: 'private-key',
    pattern: /-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----[\s\S]*?-----END(?: [A-Z]+)* PRIVATE KEY-----/g,
  },
  { name: 'aws-access-key-id', pattern: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b/g },
  { name: 'github-token', pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  { name: 'github-fine-grained-token', pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g },
  { name: 'slack-token', pattern: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g },
  { name: 'stripe-key', pattern: /\b[sprw]k_(?:live|test)_[A-Za-z0-9]{10,}\b/g },
  { name: 'stripe-webhook-secret', pattern: /\bwhsec_[A-Za-z0-9]{20,}\b/g },
  { name: 'anthropic-key', pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { name: 'openai-key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { name: 'google-api-key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'sendgrid-key', pattern: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g },
  { name: 'vera-credential', pattern: /\bvera_(?:sk|rs)_[A-Za-z0-9_-]{10,}\b/g },
  { name: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  /** Password inside a connection string: keep the scheme, user and host; drop the secret. */
  { name: 'connection-string-password', pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:([^\s@]+)@/gi, group: 1 },
  {
    name: 'authorization-header',
    pattern:
      /\b(?:Authorization|X-Api-Key|X-Auth-Token)\s*[:=]\s*["']?(?:Bearer\s+|Basic\s+|Token\s+)?([^\s"',;]+)/gi,
    group: 1,
  },
  /** `PASSWORD=…`, `--api-key …`, `"secret": "…"` — the value only. The optional quote before the
   *  separator matters: inside an embedded JSON payload the key arrives as `\"secret\":`. */
  {
    name: 'secret-assignment',
    pattern:
      /\b(?:[A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL)[A-Za-z0-9_]*)\\?["']?\s*[:=]\s*\\?["']?([^\s"',;{}\\]+)/gi,
    group: 1,
  },
  {
    name: 'cli-secret-flag',
    pattern: /--(?:password|token|api-key|secret|access-key)(?:[=\s]+)["']?([^\s"']+)/gi,
    group: 1,
  },
  { name: 'card-number', pattern: /\b(?:\d[ -]?){13,19}\b/g },
];

export interface RedactionFinding {
  rule: string;
  /** Where it was found: a dot path into the arguments object. */
  path: string;
  /** Characters removed — enough to notice a big blob went missing, never the value. */
  length: number;
}

export interface RedactionResult<T> {
  value: T;
  findings: RedactionFinding[];
  get redacted(): boolean;
}

const placeholder = (rule: string) => `[redacted:${rule}]`;

/** Luhn check, so an order number or a long digit string is not mistaken for a card. */
function isLuhnValid(digits: string): boolean {
  const d = digits.replace(/[^\d]/g, '');
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = d.length - 1; i >= 0; i -= 1) {
    let n = Number(d[i]);
    if (double) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    double = !double;
  }
  return sum % 10 === 0;
}

/** Mask one string. Returns the original when nothing matched, so callers can cheaply detect changes. */
export function redactString(
  input: string,
  rules: readonly RedactionRule[] = DEFAULT_RULES,
  path = '',
): { value: string; findings: RedactionFinding[] } {
  let value = input;
  const findings: RedactionFinding[] = [];
  for (const rule of rules) {
    const group = rule.group ?? 0;
    value = value.replace(new RegExp(rule.pattern.source, rule.pattern.flags), (...args) => {
      const match = args[0] as string;
      const captured = group === 0 ? match : ((args[group] as string | undefined) ?? '');
      if (!captured) return match;
      if (rule.name === 'card-number' && !isLuhnValid(captured)) return match;
      // Don't mask a value that is itself already a placeholder.
      if (captured.startsWith('[redacted:')) return match;
      findings.push({ rule: rule.name, path, length: captured.length });
      return group === 0 ? placeholder(rule.name) : match.replace(captured, placeholder(rule.name));
    });
  }
  return { value, findings };
}

/**
 * A key whose value is a secret by virtue of its name. Tool arguments are structured, so the common
 * case is not `PGPASSWORD=hunter2` in a command string but `{ env: { PGPASSWORD: "hunter2" } }` —
 * where no textual rule can see the pairing. The key tells us; the value goes.
 */
const SECRET_KEY =
  /(?:password|passwd|secret|token|api_?key|access_?key|private_?key|credential|authorization|auth_?token|client_?secret)/i;

/**
 * Walk any JSON-shaped value, masking strings. Key *names* are preserved — a field called `password`
 * is information a reviewer needs — but a value sitting under such a name is masked whole, whatever
 * it looks like.
 */
export function redact<T>(input: T, rules: readonly RedactionRule[] = DEFAULT_RULES): RedactionResult<T> {
  const findings: RedactionFinding[] = [];

  const walk = (v: unknown, path: string, key?: string): unknown => {
    if (typeof v === 'string') {
      if (key && SECRET_KEY.test(key) && v.length > 0 && !v.startsWith('[redacted:')) {
        findings.push({ rule: 'secret-key', path, length: v.length });
        return placeholder('secret-key');
      }
      const r = redactString(v, rules, path);
      findings.push(...r.findings);
      return r.value;
    }
    if (Array.isArray(v)) return v.map((item, i) => walk(item, `${path}[${i}]`, key));
    if (v && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v as Record<string, unknown>))
        out[k] = walk(val, path ? `${path}.${k}` : k, k);
      return out;
    }
    return v;
  };

  const value = walk(input, '') as T;
  return {
    value,
    findings,
    get redacted() {
      return findings.length > 0;
    },
  };
}

/** Compile tenant-configured patterns, skipping any that do not compile rather than failing the request. */
export function tenantRules(
  patterns: readonly { name: string; pattern: string; flags?: string }[] = [],
): RedactionRule[] {
  const rules: RedactionRule[] = [];
  for (const p of patterns) {
    try {
      rules.push({
        name: p.name,
        pattern: new RegExp(p.pattern, p.flags?.includes('g') ? p.flags : `${p.flags ?? ''}g`),
      });
    } catch {
      // A bad tenant pattern must not break decisions; it is reported by the settings UI instead.
    }
  }
  return rules;
}

/** Tenant patterns run first so an organisation's own secret shapes win over the generic rules. */
export const rulesFor = (tenant: readonly RedactionRule[] = []): RedactionRule[] => [
  ...tenant,
  ...DEFAULT_RULES,
];
