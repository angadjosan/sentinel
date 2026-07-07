import { currentUser } from "../../lib/api";
import { approveDeviceAction } from "./actions";

export default async function DevicePage({
  searchParams
}: {
  searchParams: Promise<{ user_code?: string; approved?: string }>;
}) {
  const params = await searchParams;
  const userCode = (params.user_code ?? "").toUpperCase();
  const approved = params.approved === "1";
  const user = await currentUser().catch(() => null);

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <h1>Authorize CLI login</h1>
        {approved ? (
          <>
            <p className="muted">
              Device approved{user ? ` for ${user.email}` : ""}. Return to your terminal — the CLI has already
              received its token.
            </p>
          </>
        ) : (
          <>
            <p className="muted">
              {user ? `Signed in as ${user.email}. ` : ""}
              Confirm the code below matches what your terminal is showing, then approve to finish{" "}
              <code>sentinel auth login</code>.
            </p>
            <form className="settings-form" action={approveDeviceAction}>
              <label>
                <span>Device code</span>
                <input name="user_code" defaultValue={userCode} autoComplete="one-time-code" placeholder="ABCD-EFGH" required />
              </label>
              <div className="form-actions">
                <button type="submit" className="primary">
                  Approve device
                </button>
              </div>
            </form>
          </>
        )}
      </div>
    </div>
  );
}
