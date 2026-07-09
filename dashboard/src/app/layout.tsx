import "./globals.css";
import "@xyflow/react/dist/style.css";

import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import { ShieldHalf } from "lucide-react";

import { getSession, isDevMode } from "../lib/session";
import { getSelectedRepo } from "../lib/repo";
import { currentUser, listRepos, listFindings, type Repo, type Finding } from "../lib/api";
import { NavBar } from "../components/nav/NavBar";
import { RepoSwitcher } from "../components/nav/RepoSwitcher";
import { CommandPalette, CommandTrigger } from "../components/nav/CommandPalette";
import { MobileNav } from "../components/nav/MobileNav";
import { UserMenu } from "../components/nav/UserMenu";
import { Toaster } from "../components/Toast";

export const metadata: Metadata = {
  title: "Sentinel",
  description: "LLM-powered application security — findings, attack surface, and exploit confirmation."
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const session = await getSession();
  const authed = Boolean(session);

  const [user, repos, selectedRepo, findings] = authed
    ? await Promise.all([
        isDevMode() ? Promise.resolve(null) : currentUser().catch(() => null),
        listRepos().catch((): Repo[] => []),
        getSelectedRepo(),
        listFindings().catch((): Finding[] => [])
      ])
    : [null, [] as Repo[], null, [] as Finding[]];

  const paletteFindings = findings.slice(0, 60).map((finding) => ({ id: finding.id, title: finding.title, severity: finding.severity }));

  return (
    <html lang="en" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body>
        <div className="shell">
          <header className="topbar">
            {authed ? <MobileNav /> : null}
            <div className="brand">
              <span className="brand-mark">
                <ShieldHalf size={18} strokeWidth={2.2} />
              </span>
              Sentinel
            </div>
            {authed ? (
              <>
                <span className="topbar-divider">/</span>
                <RepoSwitcher repos={repos} selected={selectedRepo} />
                <NavBar />
                <div className="topbar-spacer" />
                <CommandTrigger />
                <UserMenu email={user?.email ?? null} />
                <CommandPalette findings={paletteFindings} />
              </>
            ) : (
              <div className="topbar-spacer" />
            )}
          </header>
          <main className="main">{children}</main>
        </div>
        <Toaster />
      </body>
    </html>
  );
}
