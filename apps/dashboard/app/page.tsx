import Link from 'next/link';
import { getQueue, type QueueItem } from '../lib/api';

export const dynamic = 'force-dynamic';

const SEVERITY_OF = (code: string | null): 'high' | 'medium' | 'low' => {
  if (!code) return 'low';
  if (code.startsWith('POLICY.') || code.startsWith('PREREQ.') || code.startsWith('TOKEN.')) return 'high';
  if (code.startsWith('ACTION.') || code.startsWith('BASELINE.') || code.startsWith('EVIDENCE.'))
    return 'medium';
  return 'low';
};

function age(iso: string): string {
  const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function expiry(iso: string): { text: string; urgent: boolean } {
  const s = Math.round((Date.parse(iso) - Date.now()) / 1000);
  if (s <= 0) return { text: 'expired', urgent: true };
  if (s < 60) return { text: `${s}s left`, urgent: true };
  if (s < 600) return { text: `${Math.round(s / 60)}m left`, urgent: true };
  return { text: `${Math.round(s / 60)}m left`, urgent: false };
}

const TABS = [
  { key: 'pending', label: 'Waiting on a human' },
  { key: 'approved', label: 'Approved' },
  { key: 'rejected', label: 'Rejected' },
  { key: 'expired', label: 'Expired' },
  { key: 'all', label: 'All' },
];

export default async function QueuePage({ searchParams }: { searchParams: Promise<{ status?: string }> }) {
  const { status = 'pending' } = await searchParams;
  const { reviews } = await getQueue(status);

  return (
    <main className="wrap">
      <h1>{status === 'pending' ? 'Waiting on a human' : `Reviews — ${status}`}</h1>
      <p className="lede">
        {status === 'pending'
          ? 'An agent is paused on each of these. Until someone decides, nothing runs.'
          : 'Decisions that already have an answer.'}
      </p>

      <nav className="tabs">
        {TABS.map((t) => (
          <Link key={t.key} href={`/?status=${t.key}`} className={t.key === status ? 'on' : ''}>
            {t.label}
          </Link>
        ))}
      </nav>

      {reviews.length === 0 ? (
        <div className="empty">
          {status === 'pending' ? (
            <>
              <p style={{ margin: 0, fontWeight: 600, color: 'var(--ink-2)' }}>Nothing is waiting.</p>
              <p style={{ margin: '6px 0 0' }}>
                Every agent action so far was either allowed outright or refused by policy.
              </p>
            </>
          ) : (
            <p style={{ margin: 0 }}>Nothing here yet.</p>
          )}
        </div>
      ) : (
        <table className="queue">
          <thead>
            <tr>
              <th>Action</th>
              <th>Who</th>
              <th>Why it stopped</th>
              <th>Risk</th>
              <th>Age</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {reviews.map((r: QueueItem) => {
              const sev = SEVERITY_OF(r.top_reason);
              const exp = expiry(r.expires_at);
              return (
                <tr key={r.decision_id} className={`sev-${sev}`}>
                  <td>
                    <div className="mono" style={{ fontWeight: 600 }}>
                      {r.action_class}
                    </div>
                    <div className="dim mono" style={{ fontSize: 12 }}>
                      {r.tool} → {r.target}
                    </div>
                    {r.environment ? (
                      <span className="chip env" style={{ marginTop: 4 }}>
                        {r.environment}
                      </span>
                    ) : null}
                  </td>
                  <td>
                    <div className="mono" style={{ fontSize: 12.5 }}>
                      {r.actor}
                    </div>
                    {r.acting_for ? (
                      <div className="dim" style={{ fontSize: 12 }}>
                        for {r.acting_for}
                      </div>
                    ) : null}
                  </td>
                  <td>
                    {r.top_reason ? (
                      <span className={`chip ${sev}`}>{r.top_reason}</span>
                    ) : (
                      <span className="dim">—</span>
                    )}
                    {r.quorum > 1 ? (
                      <div className="dim" style={{ fontSize: 12, marginTop: 4 }}>
                        {r.approvals} of {r.quorum} approvals
                      </div>
                    ) : null}
                  </td>
                  <td className="risk">{r.risk}</td>
                  <td>
                    <div style={{ fontSize: 12.5 }}>{age(r.created_at)}</div>
                    {r.status === 'pending' ? (
                      <div style={{ fontSize: 12, color: exp.urgent ? 'var(--high)' : 'var(--ink-3)' }}>
                        {exp.text}
                      </div>
                    ) : (
                      <div className="dim" style={{ fontSize: 12 }}>
                        {r.status}
                      </div>
                    )}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    {r.sod_blocked ? (
                      <>
                        <Link href={`/r/${r.decision_id}`}>Look</Link>
                        <div className="dim" style={{ fontSize: 11, marginTop: 2 }}>
                          not yours to decide
                        </div>
                      </>
                    ) : (
                      <Link href={`/r/${r.decision_id}`}>{r.status === 'pending' ? 'Review →' : 'Open'}</Link>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </main>
  );
}
