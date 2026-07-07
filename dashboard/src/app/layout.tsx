import "./globals.css";

import Link from "next/link";
import type { Metadata } from "next";

import { logoutAction } from "./logout-action";
import { getSession, isDevMode } from "../lib/session";
import { currentUser } from "../lib/api";

export const metadata: Metadata = {
  title: "Sentinel Dashboard",
  description: "Sentinel application security dashboard"
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const session = await getSession();
  const user = session && !isDevMode() ? await currentUser().catch(() => null) : null;

  return (
    <html lang="en">
      <body>
        <div className="shell">
          <header className="topbar">
            <div className="brand">Sentinel</div>
            {session ? (
              <nav className="nav">
                <Link href="/">Overview</Link>
                <Link href="/findings">Findings</Link>
                <Link href="/runs">Runs</Link>
                <Link href="/graph">Graph</Link>
                <Link href="/team">Team</Link>
              </nav>
            ) : null}
            <div className="topbar-spacer" />
            {user ? (
              <div className="topbar-user">
                <span>{user.email}</span>
                <form action={logoutAction}>
                  <button type="submit">Log out</button>
                </form>
              </div>
            ) : null}
          </header>
          <main className="main">{children}</main>
        </div>
      </body>
    </html>
  );
}
