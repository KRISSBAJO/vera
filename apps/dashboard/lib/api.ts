import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';

export const API_BASE = (process.env.VERA_API_URL ?? 'http://localhost:4000').replace(/\/$/, '');
export const SESSION_COOKIE = 'vera_reviewer';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

/**
 * Call the VERA API as the signed-in reviewer. The session token lives in an httpOnly cookie and is
 * never exposed to the browser: every call goes through the server, so a script injected into a
 * rendered tool argument cannot read or replay it (threat T21, T23).
 */
export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  if (!token) redirect('/login');

  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}`, ...init?.headers },
    cache: 'no-store',
  });

  if (res.status === 401) redirect('/login?expired=1');
  const text = await res.text();
  const body = text ? JSON.parse(text) : {};
  if (!res.ok) {
    const err = (body as { error?: { code?: string; message?: string } }).error;
    throw new ApiError(res.status, err?.code ?? `HTTP_${res.status}`, err?.message ?? 'request failed');
  }
  return body as T;
}

// ---------- what the API returns ----------

export interface QueueItem {
  decision_id: string;
  created_at: string;
  expires_at: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  actor: string;
  acting_for: string | null;
  action_class: string;
  tool: string;
  target: string;
  environment: string | null;
  risk: number;
  top_reason: string | null;
  quorum: number;
  approvals: number;
  sod_blocked: boolean;
}

export interface ReasonCode {
  code: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  policy_id?: string;
  detail?: string;
  description: string | null;
  guidance: string | null;
}

export interface EvidenceItem {
  id: string;
  type: string;
  source: string;
  trust: 'verified' | 'asserted';
  observed_at: string;
  data: Record<string, unknown>;
}

export interface RedactionFinding {
  rule: string;
  path: string;
  length: number;
}

export interface DecisionDetail {
  decision_id: string;
  decision: 'ALLOW' | 'REVIEW' | 'BLOCK';
  created_at: string;
  expires_at: string;
  risk: { score: number; calibrated: boolean };
  confidence: number;
  policy_set_version: string;
  baseline_snapshot_id: string | null;
  actor: { id: string; type?: string; runtime?: string };
  acting_for: { id: string; trust?: string } | null;
  action: {
    tool: string;
    class: string;
    arguments: Record<string, unknown>;
    environment?: string;
    hints?: Record<string, boolean>;
  };
  redaction: RedactionFinding[];
  has_raw: boolean;
  target: { kind: string; id: string; sensitivity?: string } | null;
  context: Record<string, unknown> | null;
  evidence: EvidenceItem[];
  reason_codes: ReasonCode[];
  review: {
    status: 'pending' | 'approved' | 'rejected' | 'expired';
    quorum: number;
    routed_to: string[];
    excluded: string[];
    sod_blocked: boolean;
    approvals: { by: string; verdict: 'approve' | 'reject'; rationale: string | null; at: string }[];
  } | null;
}

export const getQueue = (status: string) =>
  api<{ reviews: QueueItem[] }>(`/v1/reviews?status=${encodeURIComponent(status)}`);
export const getDecision = (id: string) => api<DecisionDetail>(`/v1/reviews/${encodeURIComponent(id)}`);
