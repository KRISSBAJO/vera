import { z } from 'zod';

/**
 * Claude Code hook contract, pinned (ADR-0002, A17). Checked against code.claude.com/docs/en/hooks on
 * 11 September 2026. If Claude Code changes these shapes, the contract test in index.test.ts fails
 * before a customer does.
 */

export const PreToolUseInputSchema = z.looseObject({
  hook_event_name: z.literal('PreToolUse'),
  tool_name: z.string(),
  tool_input: z.record(z.string(), z.unknown()),
  tool_use_id: z.string(),
  session_id: z.string(),
  cwd: z.string(),
  permission_mode: z.string().optional(),
  prompt_id: z.string().optional(),
});
export type PreToolUseInput = z.infer<typeof PreToolUseInputSchema>;

export const PostToolUseInputSchema = z.looseObject({
  hook_event_name: z.literal('PostToolUse'),
  tool_name: z.string(),
  /** As originally sent by Claude — NOT a PreToolUse `updatedInput` (ADR-0002). */
  tool_input: z.record(z.string(), z.unknown()),
  tool_use_id: z.string(),
  session_id: z.string(),
  cwd: z.string(),
  tool_response: z.unknown().optional(),
  tool_output: z.unknown().optional(),
});
export type PostToolUseInput = z.infer<typeof PostToolUseInputSchema>;

export const PermissionDecisionSchema = z.enum(['allow', 'deny', 'ask', 'defer']);
export type PermissionDecision = z.infer<typeof PermissionDecisionSchema>;

export interface PreToolUseOutput {
  hookSpecificOutput: {
    hookEventName: 'PreToolUse';
    permissionDecision: PermissionDecision;
    permissionDecisionReason: string;
  };
  /** Shown to the user in the terminal. */
  systemMessage?: string;
}

export function preOutput(
  decision: PermissionDecision,
  reason: string,
  systemMessage?: string,
): PreToolUseOutput {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: decision,
      permissionDecisionReason: reason,
    },
    ...(systemMessage ? { systemMessage } : {}),
  };
}

/** PostToolUse: we never modify tool output; an empty object means "no change". */
export type PostToolUseOutput = Record<string, never>;
