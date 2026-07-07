import { loginMfaAction } from "./actions";

export default async function LoginMfaPage({
  searchParams
}: {
  searchParams: Promise<{ challenge_token?: string; next?: string; error?: string }>;
}) {
  const params = await searchParams;
  const next = params.next ?? "/";
  const challengeToken = params.challenge_token ?? "";

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <h1>Two-factor authentication</h1>
        <p className="muted">Enter the 6-digit code from your authenticator app.</p>
        {params.error ? <div className="error">{params.error}</div> : null}
        <form className="settings-form" action={loginMfaAction}>
          <input type="hidden" name="challenge_token" value={challengeToken} />
          <input type="hidden" name="next" value={next} />
          <label>
            <span>Authentication code</span>
            <input name="code" inputMode="numeric" pattern="[0-9]*" maxLength={8} required autoComplete="one-time-code" autoFocus />
          </label>
          <div className="form-actions">
            <button type="submit" className="primary">
              Verify
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
