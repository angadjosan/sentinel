import { resetPasswordAction } from "./actions";

export default async function ResetPasswordPage({
  params,
  searchParams
}: {
  params: Promise<{ token: string }>;
  searchParams: Promise<{ error?: string }>;
}) {
  const { token } = await params;
  const { error } = await searchParams;

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <h1>Set a new password</h1>
        <p className="muted">Choose a new password for your account.</p>
        {error ? <div className="error">{error}</div> : null}
        <form className="settings-form" action={resetPasswordAction}>
          <input type="hidden" name="token" value={token} />
          <label>
            <span>New password</span>
            <input name="password" type="password" required minLength={8} autoComplete="new-password" />
          </label>
          <label>
            <span>Confirm password</span>
            <input name="confirm_password" type="password" required minLength={8} autoComplete="new-password" />
          </label>
          <div className="form-actions">
            <button type="submit" className="primary">
              Reset password
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
