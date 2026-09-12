import { EVIDENCE_ATTRIBUTES } from '@vera/policy-engine';
import type { Evidence } from '@vera/schemas';

type Flags = Partial<Record<keyof typeof EVIDENCE_ATTRIBUTES, boolean>>;

/**
 * Project evidence records onto the policy-visible evidence flags (ADR-0004). Known evidence types map
 * explicitly; any evidence may also carry a flag by its exact name in `data`. Called separately for
 * verified and asserted evidence so the two never mix (SR-01).
 */
export function projectEvidence(list: readonly Evidence[]): Flags {
  const flags: Flags = {};
  const set = (k: keyof Flags, v: unknown) => {
    if (typeof v === 'boolean') flags[k] = flags[k] === undefined ? v : flags[k] && v;
  };
  for (const ev of list) {
    const d = ev.data;
    switch (ev.type) {
      case 'github.pr':
        set('pr_approved', d.approved);
        if (typeof d.checks === 'string') set('tests_passed', d.checks === 'success');
        set('contains_migration', d.contains_migration);
        break;
      case 'ci.status':
        if (typeof d.status === 'string') set('tests_passed', d.status === 'success');
        break;
      case 'ops.backup':
        set('backup_verified', d.verified);
        break;
      case 'ops.rollback':
        set('rollback_plan', d.present ?? true);
        break;
      case 'deploy.staging':
        set('staging_deployed', d.deployed ?? true);
        break;
      default:
        break;
    }
    for (const key of Object.keys(EVIDENCE_ATTRIBUTES) as (keyof Flags)[]) {
      if (key in d) set(key, d[key]);
    }
  }
  return flags;
}
