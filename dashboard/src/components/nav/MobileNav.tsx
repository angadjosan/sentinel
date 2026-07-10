"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Menu, X, ShieldHalf } from "lucide-react";

const LINKS = [
  { href: "/", label: "Overview" },
  { href: "/findings", label: "Findings" },
  { href: "/graph", label: "Graph" },
  { href: "/scans", label: "Scans" },
  { href: "/plan", label: "Plan review" },
  { href: "/settings", label: "Settings" }
];

export function MobileNav() {
  const [open, setOpen] = useState(false);
  const pathname = usePathname();

  return (
    <>
      <button className="mobile-trigger ghost icon" onClick={() => setOpen(true)} aria-label="Open menu"><Menu size={18} /></button>
      {open ? (
        <div className="mobile-overlay" onClick={() => setOpen(false)}>
          <div className="mobile-drawer" onClick={(e) => e.stopPropagation()}>
            <div className="spread" style={{ marginBottom: 14 }}>
              <span className="brand"><span className="brand-mark"><ShieldHalf size={17} /></span> Sentinel</span>
              <button className="ghost icon" onClick={() => setOpen(false)}><X size={17} /></button>
            </div>
            <nav style={{ display: "grid", gap: 2 }}>
              {LINKS.map((link) => {
                const active = link.href === "/" ? pathname === "/" : pathname.startsWith(link.href);
                return (
                  <Link key={link.href} href={link.href} onClick={() => setOpen(false)} className={`mobile-link ${active ? "active" : ""}`}>{link.label}</Link>
                );
              })}
            </nav>
          </div>
        </div>
      ) : null}
    </>
  );
}
