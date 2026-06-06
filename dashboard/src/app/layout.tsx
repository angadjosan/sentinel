import "./globals.css";

import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Sentinel Dashboard",
  description: "Sentinel application security dashboard"
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <header className="topbar">
            <div className="brand">Sentinel</div>
            <nav className="nav">
              <Link href="/">Overview</Link>
              <Link href="/findings">Findings</Link>
              <Link href="/runs">Runs</Link>
              <Link href="/graph">Graph</Link>
            </nav>
          </header>
          <main className="main">{children}</main>
        </div>
      </body>
    </html>
  );
}
