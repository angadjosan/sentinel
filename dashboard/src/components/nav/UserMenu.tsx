"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { Settings, LogOut } from "lucide-react";
import { logoutAction } from "../../app/logout-action";

export function UserMenu({ email }: { email: string | null }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  const initial = (email ?? "D").slice(0, 1).toUpperCase();

  return (
    <div className="user-menu" ref={ref}>
      <button className="ghost icon" onClick={() => setOpen((v) => !v)} title={email ?? "dev mode"} style={{ width: 32, padding: 0 }}>
        <span className="avatar">{initial}</span>
      </button>
      {open ? (
        <div className="repo-menu" style={{ left: "auto", right: 0, minWidth: 220 }}>
          <div className="repo-menu-label" style={{ textTransform: "none", letterSpacing: 0, fontSize: 12 }}>{email ?? "dev mode"}</div>
          <Link href="/settings" className="repo-menu-item" onClick={() => setOpen(false)}><Settings size={14} /> Settings</Link>
          <form action={logoutAction}>
            <button type="submit" className="repo-menu-item" style={{ color: "var(--critical)" }}><LogOut size={14} /> Log out</button>
          </form>
        </div>
      ) : null}
    </div>
  );
}
