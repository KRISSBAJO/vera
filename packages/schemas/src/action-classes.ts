import { z } from 'zod';

/**
 * Action-class taxonomy (brief §6.1). Adapters map tool names to classes using a tenant-signed table;
 * anything unmapped becomes `unknown.consequential`, which the tenant default treats as BLOCK or REVIEW,
 * never ALLOW (SR-03).
 */
export const ACTION_CLASSES = [
  // read-only — eligible for fail-open in degraded mode
  'file.read',
  'vcs.read',
  'http.read',
  'db.read',
  'search',
  // consequential — never fail-open
  'file.write',
  'shell.exec',
  'vcs.push',
  'vcs.merge',
  'deploy.staging',
  'deploy.production',
  'db.write',
  'db.ddl',
  'secret.read',
  'secret.write',
  'infra.change',
  'http.mutation',
  'message.send',
  'payment.create',
  'unknown.consequential',
] as const;

export const ActionClassSchema = z.enum(ACTION_CLASSES);
export type ActionClass = z.infer<typeof ActionClassSchema>;

export const READ_ONLY_CLASSES: ReadonlySet<ActionClass> = new Set<ActionClass>([
  'file.read',
  'vcs.read',
  'http.read',
  'db.read',
  'search',
]);

export function isConsequential(cls: ActionClass): boolean {
  return !READ_ONLY_CLASSES.has(cls);
}
