import Link from 'next/link';
import { AgentJson, AgentText } from '../../../components/AgentText';
import { DecideForm } from '../../../components/DecideForm';
import { RevealForm } from '../../../components/RevealForm';
import { type DecisionDetail, getDecision } from '../../../lib/api';

export const dynamic = 'force-dynamic';

const when = (iso: string) => new Date(iso).toLocaleString();

export default async function DecisionPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const d: DecisionDetail = await getDecision(id);
  const command =
    typeof d.action.arguments?.command === 'string' ? (d.action.arguments.command as string) : null;
  const pending = d.review?.status === 'pending';
  const expired = Date.parse(d.expires_at) < Date.now();

  // Info-level codes are context, not cause. They go last so the reason it stopped is what you read first.
  const ordered = [...d.reason_codes].sort((a, b) => {
    const rank = { high: 0, medium: 1, low: 2, info: 3 } as const;
    return rank[a.severity] - rank[b.severity];
  });

  return (
    <main className="wrap">
      <p style={{ margin: '18px 0 0' }}>
        <Link href="/">← Back to the queue</Link>
      </p>

      <h1 style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <span className={`verdict ${d.decision}`}>{d.decision}</span>
        <span className="mono">{d.action.class}</span>
      </h1>
      <p className="lede">
        <span className="mono">{d.actor.id}</span>
        {d.acting_for ? (
          <>
            {' '}
            acting for <span className="mono">{d.acting_for.id}</span>{' '}
            {d.acting_for.trust === 'asserted' ? (
              <span className="chip asserted">asserted identity</span>
            ) : null}
          </>
        ) : null}{' '}
        wants to run <span className="mono">{d.action.tool}</span> against{' '}
        <span className="mono">{d.target?.id ?? 'an unnamed target'}</span>.
      </p>

      <div className="grid-2">
        <div>
          <h2>What it wants to do</h2>
          {command ? (
            <AgentText label="Command">{command}</AgentText>
          ) : (
            <AgentJson label="Arguments" value={d.action.arguments} />
          )}
          {d.redaction.length > 0 ? (
            <p className="agent-note">
              {d.redaction.length} credential{d.redaction.length === 1 ? '' : 's'} removed before storing:{' '}
              {d.redaction.map((f) => `${f.rule} at ${f.path}`).join(', ')}.
            </p>
          ) : null}
          {d.has_raw ? <RevealForm decisionId={d.decision_id} /> : null}

          <h2>Why VERA stopped</h2>
          <ul className="reasons">
            {ordered.map((c) => (
              <li key={`${c.code}-${c.policy_id ?? ''}`} className={`sev-${c.severity}`}>
                <div className="reason-head">
                  <span className="reason-code">{c.code}</span>
                  <span className={`chip ${c.severity}`}>{c.severity}</span>
                  {c.policy_id ? (
                    <span className="dim mono" style={{ fontSize: 12 }}>
                      {c.policy_id}
                    </span>
                  ) : null}
                </div>
                {c.detail ? <div className="reason-detail">{c.detail}</div> : null}
                {c.guidance ? <div className="reason-guidance">{c.guidance}</div> : null}
              </li>
            ))}
          </ul>

          <h2>Evidence</h2>
          {d.evidence.length === 0 ? (
            <div className="empty" style={{ padding: 20 }}>
              Nothing was gathered for this action. Absence of evidence is not safety — decide as if the facts
              are unknown.
            </div>
          ) : (
            d.evidence.map((e) => (
              <div key={e.id} className="card" style={{ padding: 12, marginBottom: 8 }}>
                <div className="reason-head">
                  <span className="mono" style={{ fontWeight: 600, fontSize: 12.5 }}>
                    {e.type}
                  </span>
                  <span className={`chip ${e.trust}`}>{e.trust}</span>
                  <span className="dim" style={{ fontSize: 12 }}>
                    from {e.source}, seen {when(e.observed_at)}
                  </span>
                </div>
                {e.trust === 'asserted' ? (
                  <p className="dim" style={{ fontSize: 12.5, margin: '6px 0 0' }}>
                    The agent claimed this. It is recorded, but it cannot satisfy a prerequisite.
                  </p>
                ) : null}
                <pre
                  className="agent-body"
                  style={{ border: '1px solid var(--line)', borderRadius: 4, marginTop: 8 }}
                >
                  {JSON.stringify(e.data, null, 2)}
                </pre>
              </div>
            ))
          )}
        </div>

        <div>
          <h2 style={{ marginTop: 0 }}>Decide</h2>
          {!d.review ? (
            <div className="panel">
              <p style={{ margin: 0 }}>
                This decision was {d.decision === 'ALLOW' ? 'allowed outright' : 'refused by policy'} — there
                is nothing for a human to answer.
              </p>
            </div>
          ) : d.review.sod_blocked ? (
            <div className="panel">
              <div className="notice warn" style={{ marginTop: 0 }}>
                You cannot decide this one. You are the actor, the person it was requested for, or the owner
                of the key that made the request.
              </div>
              <p className="dim" style={{ fontSize: 13, marginBottom: 0 }}>
                Separation of duties, working as intended. Someone else on{' '}
                <span className="mono">{d.review.routed_to.join(', ')}</span> has to answer.
              </p>
            </div>
          ) : !pending ? (
            <div className="panel">
              <p style={{ margin: 0 }}>
                Already {d.review.status}
                {d.review.approvals.length > 0 ? ` by ${d.review.approvals.map((a) => a.by).join(', ')}` : ''}
                .
              </p>
            </div>
          ) : expired ? (
            <div className="panel">
              <div className="notice bad" style={{ marginTop: 0 }}>
                This review expired before anyone answered. No token was issued, and the agent has moved on.
              </div>
            </div>
          ) : (
            <DecideForm
              decisionId={d.decision_id}
              quorum={d.review.quorum}
              approvals={d.review.approvals.length}
            />
          )}

          {d.review && d.review.approvals.length > 0 ? (
            <>
              <h2>Already recorded</h2>
              {d.review.approvals.map((a) => (
                <div key={`${a.by}-${a.at}`} className="card" style={{ padding: 10, marginBottom: 6 }}>
                  <div className="reason-head">
                    <span className={`chip ${a.verdict === 'approve' ? 'verified' : 'high'}`}>
                      {a.verdict}
                    </span>
                    <span className="mono" style={{ fontSize: 12.5 }}>
                      {a.by}
                    </span>
                  </div>
                  {a.rationale ? <div className="reason-guidance">{a.rationale}</div> : null}
                  <div className="dim" style={{ fontSize: 11, marginTop: 4 }}>
                    {when(a.at)}
                  </div>
                </div>
              ))}
            </>
          ) : null}

          <h2>Facts</h2>
          <div className="panel">
            <dl className="kv">
              <dt>Decision</dt>
              <dd>{d.decision_id}</dd>
              <dt>Risk</dt>
              <dd>
                {d.risk.score}
                {!d.risk.calibrated ? <span className="dim"> (uncalibrated)</span> : null}
              </dd>
              <dt>Confidence</dt>
              <dd>{Math.round(d.confidence * 100)}%</dd>
              <dt>Policy set</dt>
              <dd>{d.policy_set_version}</dd>
              <dt>Baseline</dt>
              <dd>{d.baseline_snapshot_id ?? 'no history yet'}</dd>
              <dt>Environment</dt>
              <dd>{d.action.environment ?? '—'}</dd>
              <dt>Target</dt>
              <dd>
                {d.target?.kind}:{d.target?.id}
                {d.target?.sensitivity ? ` (${d.target.sensitivity})` : ''}
              </dd>
              <dt>Requested</dt>
              <dd>{when(d.created_at)}</dd>
              <dt>Expires</dt>
              <dd>{when(d.expires_at)}</dd>
            </dl>
          </div>
        </div>
      </div>
    </main>
  );
}
