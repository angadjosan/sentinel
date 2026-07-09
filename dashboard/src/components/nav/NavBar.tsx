"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const LINKS = [
  { href: "/", label: "Overview" },
  { href: "/findings", label: "Findings" },
  { href: "/graph", label: "Graph" },
  { href: "/scans", label: "Scans" },
  { href: "/settings", label: "Settings" }
];

export function NavBar() {
  const pathname = usePathname();
  return (
    <nav className="nav">
      {LINKS.map((link) => {
        const active = link.href === "/" ? pathname === "/" : pathname.startsWith(link.href);
        return (
          <Link key={link.href} href={link.href} className={active ? "active" : ""}>
            {link.label}
          </Link>
        );
      })}
    </nav>
  );
}
