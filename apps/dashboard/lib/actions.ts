'use server';

import { revalidatePath } from 'next/cache';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { API_BASE, ApiError, api, SESSION_COOKIE } from './api';

export interface ActionResult {
  ok: boolean;
  message: string;
}

/**
 * Approve or reject. The verdict is submitted from the server with the httpOnly session, so nothing
 * a rendered tool argument could inject is able to forge one, and a rationale is always recorded.
 */
export async function decide(
  decisionId: string,
  verdict: 'approve' | 'reject',
  formData: FormData,
): Promise<ActionResult> {
  const rationale = String(formData.get('rationale') ?? '').trim();
  if (verdict === 'reject' && rationale.length < 3) {
    return {
      ok: false,
      message: 'Say why you are rejecting — the agent and the audit trail both need the reason.',
    };
  }
  try {
    const r = await api<{ review_status: string; approvals: number; quorum: number; token_issued: boolean }>(
      `/v1/decisions/${encodeURIComponent(decisionId)}/${verdict}`,
      { method: 'POST', body: JSON.stringify(rationale ? { rationale } : {}) },
    );
    revalidatePath('/');
    revalidatePath(`/r/${decisionId}`);
    if (r.review_status === 'pending')
      return {
        ok: true,
        message: `Recorded. ${r.approvals} of ${r.quorum} approvals — still waiting for another reviewer.`,
      };
    if (r.review_status === 'approved')
      return { ok: true, message: 'Approved. A signed token was issued to the agent.' };
    return { ok: true, message: 'Rejected. No token was issued; the action will not run.' };
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.code === 'POLICY.SOD_VIOLATION')
        return {
          ok: false,
          message:
            'You cannot decide this one: you are the actor, the person it was requested for, or the owner of the key that made the request.',
        };
      if (e.code === 'REVIEW_EXPIRED')
        return {
          ok: false,
          message: 'This review expired before it was answered. The agent has already moved on.',
        };
      if (e.code === 'ALREADY_REVIEWED')
        return { ok: false, message: 'You have already recorded a verdict on this one.' };
      if (e.code === 'REVIEW_NOT_PENDING')
        return { ok: false, message: 'Someone else already decided this one.' };
      return { ok: false, message: e.message };
    }
    throw e;
  }
}

/** Reveal the raw, unredacted action. Requires a stated reason; the API records who looked and why. */
export async function reveal(
  decisionId: string,
  formData: FormData,
): Promise<{ ok: boolean; message: string; action?: unknown }> {
  const reason = String(formData.get('reason') ?? '').trim();
  if (reason.length < 3)
    return {
      ok: false,
      message: 'A reason is required. Looking at a credential is a deliberate act and it is recorded.',
    };
  try {
    const r = await api<{ action: unknown }>(`/v1/decisions/${encodeURIComponent(decisionId)}/reveal`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
    return {
      ok: true,
      message: 'Revealed. This was written to the audit chain with your name and reason.',
      action: r.action,
    };
  } catch (e) {
    if (e instanceof ApiError) return { ok: false, message: e.message };
    throw e;
  }
}

export async function signIn(formData: FormData): Promise<{ ok: false; message: string } | never> {
  const token = String(formData.get('token') ?? '').trim();
  if (!token.startsWith('vera_rs_'))
    return { ok: false, message: 'That is not a reviewer session token — they start with vera_rs_.' };

  // Verify before storing, so a bad token fails here rather than on every page.
  const res = await fetch(`${API_BASE}/v1/reviews?status=pending&limit=1`, {
    headers: { authorization: `Bearer ${token}` },
    cache: 'no-store',
  });
  if (res.status === 401)
    return { ok: false, message: 'That token is not valid, or its session has expired.' };
  if (!res.ok) return { ok: false, message: `The API answered ${res.status}. Is it running at ${API_BASE}?` };

  (await cookies()).set(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 60 * 60 * 12,
  });
  redirect('/');
}

export async function signOut(): Promise<never> {
  (await cookies()).delete(SESSION_COOKIE);
  redirect('/login');
}
