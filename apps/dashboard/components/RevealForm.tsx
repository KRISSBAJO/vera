'use client';

import { useActionState, useState } from 'react';
import { reveal } from '../lib/actions';

type State = { ok: boolean; message: string; action?: unknown } | null;

/**
 * Revealing the raw action is deliberate and recorded. The form makes that plain rather than hiding
 * it behind an innocuous "show more" — the reviewer should know a credential is about to be on screen
 * and that their name is going into the audit chain (SR-15).
 */
export function RevealForm({ decisionId }: { decisionId: string }) {
  const [open, setOpen] = useState(false);
  const [state, action, pending] = useActionState<State, FormData>(
    async (_prev, formData) => reveal(decisionId, formData),
    null,
  );

  if (!open) {
    return (
      <p style={{ margin: '0 0 18px' }}>
        <button
          type="button"
          className="quiet"
          onClick={() => setOpen(true)}
          style={{ padding: '5px 10px', fontSize: 13 }}
        >
          Show the unredacted command…
        </button>
      </p>
    );
  }

  return (
    <form action={action} className="panel" style={{ marginBottom: 18 }}>
      <p style={{ marginTop: 0, fontSize: 13 }}>
        This puts a live credential on your screen and writes your name, the time, and your reason to the
        audit chain.
      </p>
      <label className="field" htmlFor="reason">
        Why do you need to see it?
      </label>
      <input
        id="reason"
        name="reason"
        type="text"
        placeholder="Confirming which host this points at"
        required
      />
      <div className="actions">
        <button type="submit" disabled={pending}>
          {pending ? 'Revealing…' : 'Reveal and record'}
        </button>
        <button type="button" className="quiet" onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
      {state ? <div className={`notice ${state.ok ? 'warn' : 'bad'}`}>{state.message}</div> : null}
      {state?.action ? (
        <pre
          className="agent-body"
          style={{ marginTop: 10, border: '1px solid var(--line-strong)', borderRadius: 4 }}
        >
          {JSON.stringify(state.action, null, 2)}
        </pre>
      ) : null}
    </form>
  );
}
