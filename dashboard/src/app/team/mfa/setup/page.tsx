import Link from "next/link";
import { mfaEnroll } from "../../../../lib/api";
import { confirmMfaSetupAction } from "./actions";

export default async function MfaSetupPage({
  searchParams
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error } = await searchParams;
  const enrollment = await mfaEnroll();

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <h1>Enable two-factor authentication</h1>
        <p className="muted">
          Add this account to your authenticator app (1Password, Authy, Google Authenticator, etc.), either by
          scanning the setup URL below or entering the secret manually, then confirm with a code to finish.
        </p>
        <p className="kv">
          <code style={{ fontSize: 12, wordBreak: "break-all" }}>{enrollment.secret}</code>
        </p>
        <p className="muted" style={{ fontSize: 12, wordBreak: "break-all" }}>{enrollment.otpauth_url}</p>
        {error ? <div className="error">{error}</div> : null}
        <form className="settings-form" action={confirmMfaSetupAction}>
          <label>
            <span>Confirmation code</span>
            <input name="code" inputMode="numeric" pattern="[0-9]*" maxLength={8} required autoFocus />
          </label>
          <div className="form-actions">
            <button type="submit" className="primary">
              Enable
            </button>
          </div>
        </form>
        <div className="switch-link">
          <Link href="/team">Cancel</Link>
        </div>
      </div>
    </div>
  );
}
