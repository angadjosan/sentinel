import Link from "next/link";
import { verifyEmailRequest } from "../../lib/api";

export default async function VerifyEmailPage({
  searchParams
}: {
  searchParams: Promise<{ token?: string }>;
}) {
  const { token } = await searchParams;

  let verified = false;
  let error: string | null = null;
  if (!token) {
    error = "Missing verification token";
  } else {
    try {
      await verifyEmailRequest(token);
      verified = true;
    } catch (err) {
      error = err instanceof Error ? err.message : "Could not verify this email link";
    }
  }

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <h1>Verify email</h1>
        {verified ? (
          <p className="muted">Your email address has been verified.</p>
        ) : (
          <div className="error">{error}</div>
        )}
        <div className="switch-link">
          <Link href="/">Go to dashboard</Link>
        </div>
      </div>
    </div>
  );
}
