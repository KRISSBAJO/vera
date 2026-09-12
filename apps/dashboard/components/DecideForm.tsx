'use client';

import { useActionState, useState } from 'react';
import { type ActionResult, decide } from '../lib/actions';

export function DecideForm({
  decisionId,
  quorum,
  approvals,
}: {
  decisionId: string;
  quorum: number;
  approvals: number;
}) {
  const [verdict, setVerdict] = useState<'approve' | 'reject' | null>(null);
  const [state, action, pending] = useActionState<ActionResult | null, FormData>(async (_prev, formData) => {
    const chosen = (formData.get('verdict') as 'approve' | 'reject') ?? 'approve';
    return decide(decisionId, chosen, formData);
  }, null);

  return (
    <form action={action} className="panel">
      {quorum > 1 ? (
        <p className="dim" style={{ marginTop: 0, fontSize: 13 }}>
          This needs {quorum} approvals; {approvals} recorded so far.
        </p>
      ) : null}

      <label className="field" htmlFor="rationale">
        Why? (required to reject, and worth writing either way — the next reviewer reads it)
      </label>
      <textarea
        id="rationale"
        name="rationale"
        rows={3}
        placeholder="Checked the backup ran at 02:00 and the PR is approved."
      />

      <input type="hidden" name="verdict" value={verdict ?? 'approve'} />
      <div className="actions">
        <button type="submit" className="approve" disabled={pending} onClick={() => setVerdict('approve')}>
          {pending && verdict === 'approve' ? 'Approving…' : 'Approve'}
        </button>
        <button type="submit" className="reject" disabled={pending} onClick={() => setVerdict('reject')}>
          {pending && verdict === 'reject' ? 'Rejecting…' : 'Reject'}
        </button>
      </div>

      {state ? <div className={`notice ${state.ok ? 'ok' : 'bad'}`}>{state.message}</div> : null}

      <p className="dim" style={{ fontSize: 12, margin: '14px 0 0' }}>
        Approving issues a signed token bound to this exact action. If the agent changes so much as a
        character before running it, the token stops verifying.
      </p>
    </form>
  );
}
