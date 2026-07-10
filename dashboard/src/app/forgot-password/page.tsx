import Link from "next/link";
import { forgotPasswordAction } from "./actions";

export default async function ForgotPasswordPage({
  searchParams
}: {
  searchParams: Promise<{ sent?: string; error?: string }>;
}) {
  const params = await searchParams;

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <h1>Reset your password</h1>
        <p className="muted">Enter your email and we&apos;ll send you a link to reset your password.</p>
        {params.error ? <div className="error">{params.error}</div> : null}
        {params.sent ? (
          <div className="muted">If an account exists for that email, we&apos;ve sent a reset link.</div>
        ) : (
          <form className="settings-form" action={forgotPasswordAction}>
            <label>
              <span>Email</span>
              <input name="email" type="email" required autoComplete="email" />
            </label>
            <div className="form-actions">
              <button type="submit" className="primary">
                Send reset link
              </button>
            </div>
          </form>
        )}
        <div className="switch-link">
          <Link href="/login">Back to login</Link>
        </div>
      </div>
    </div>
  );
}
