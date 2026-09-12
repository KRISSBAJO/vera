'use client';

import { useActionState } from 'react';
import { signIn } from '../lib/actions';

type State = { ok: false; message: string } | null;

export function SignInForm() {
  const [state, action, pending] = useActionState<State, FormData>(async (_prev, formData) => {
    return (await signIn(formData)) as State;
  }, null);

  return (
    <form action={action}>
      <label className="field" htmlFor="token">
        Reviewer session token
      </label>
      <input id="token" name="token" type="password" placeholder="vera_rs_…" autoComplete="off" required />
      <div className="actions">
        <button type="submit" disabled={pending}>
          {pending ? 'Checking…' : 'Sign in'}
        </button>
      </div>
      {state && !state.ok ? <div className="notice bad">{state.message}</div> : null}
    </form>
  );
}
