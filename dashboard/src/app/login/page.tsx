import Link from "next/link";
import { loginAction } from "./actions";

export default async function LoginPage({
  searchParams
}: {
  searchParams: Promise<{ next?: string; error?: string; reset?: string }>;
}) {
  const params = await searchParams;
  const next = params.next ?? "/";

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <h1>Log in</h1>
        <p className="muted">Sign in to your Sentinel account.</p>
        {params.error ? <div className="error">{params.error}</div> : null}
        {params.reset ? <div className="muted">Your password has been reset. Log in with your new password.</div> : null}
        <form className="settings-form" action={loginAction}>
          <input type="hidden" name="next" value={next} />
          <label>
            <span>Email</span>
            <input name="email" type="email" required autoComplete="email" />
          </label>
          <label>
            <span>Password</span>
            <input name="password" type="password" required autoComplete="current-password" />
          </label>
          <div className="form-actions">
            <button type="submit" className="primary">
              Log in
            </button>
          </div>
        </form>
        <div className="switch-link">
          <Link href={`/forgot-password`}>Forgot password?</Link>
        </div>
        <a className="oauth-button" href={`/auth/github/start?next=${encodeURIComponent(next)}`}>
          Sign in with GitHub
        </a>
        <div className="switch-link">
          Don&apos;t have an account? <Link href={`/signup?next=${encodeURIComponent(next)}`}>Sign up</Link>
        </div>
      </div>
    </div>
  );
}
