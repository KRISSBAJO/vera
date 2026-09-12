import { SignInForm } from '../../components/SignInForm';

export default async function LoginPage({ searchParams }: { searchParams: Promise<{ expired?: string }> }) {
  const { expired } = await searchParams;
  return (
    <main className="wrap-narrow">
      <h1>Sign in to review</h1>
      <p className="lede">
        Paste your reviewer session token. It is stored in an httpOnly cookie and never reaches the
        browser&apos;s JavaScript, so nothing rendered from an agent&apos;s output can read it.
      </p>
      {expired ? (
        <div className="notice warn">Your session expired or was revoked. Sign in again.</div>
      ) : null}
      <div className="panel" style={{ marginTop: 16 }}>
        <SignInForm />
      </div>
      <p className="dim" style={{ marginTop: 16, fontSize: 13 }}>
        A token is printed once by <span className="mono">vera-api bootstrap</span> or{' '}
        <span className="mono">vera-api add-user</span>. Approving your own agent&apos;s actions is refused —
        that is separation of duties working, not a bug.
      </p>
    </main>
  );
}
