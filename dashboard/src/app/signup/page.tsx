import Link from "next/link";
import { signupAction } from "./actions";

export default async function SignupPage({
  searchParams
}: {
  searchParams: Promise<{ next?: string; error?: string }>;
}) {
  const params = await searchParams;
  const next = params.next ?? "/";

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <h1>Create your account</h1>
        <p className="muted">This creates a new Sentinel account and workspace.</p>
        {params.error ? <div className="error">{params.error}</div> : null}
        <form className="settings-form" action={signupAction}>
          <input type="hidden" name="next" value={next} />
          <label>
            <span>Name</span>
            <input name="name" required autoComplete="name" />
          </label>
          <label>
            <span>Email</span>
            <input name="email" type="email" required autoComplete="email" />
          </label>
          <label>
            <span>Password</span>
            <input name="password" type="password" required minLength={8} autoComplete="new-password" />
          </label>
          <label>
            <span>Team name (optional)</span>
            <input name="account_name" placeholder="defaults to “<name>’s team”" />
          </label>
          <div className="form-actions">
            <button type="submit" className="primary">
              Sign up
            </button>
          </div>
        </form>
        <a className="oauth-button" href={`/auth/github/start?next=${encodeURIComponent(next)}`}>
          Sign up with GitHub
        </a>
        <div className="switch-link">
          Already have an account? <Link href={`/login?next=${encodeURIComponent(next)}`}>Log in</Link>
        </div>
      </div>
    </div>
  );
}
