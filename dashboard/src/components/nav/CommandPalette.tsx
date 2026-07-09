"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, LayoutGrid, GitBranch, Radar, Bug, Settings, Search, FileSearch } from "lucide-react";

type Item = { id: string; label: string; hint?: string; href: string; icon: React.ReactNode; group: string };

const NAV: Item[] = [
  { id: "n-overview", label: "Overview", href: "/", icon: <LayoutGrid size={15} />, group: "Navigate" },
  { id: "n-findings", label: "Findings", href: "/findings", icon: <Bug size={15} />, group: "Navigate" },
  { id: "n-graph", label: "Graph — Attack Surface", href: "/graph", icon: <Radar size={15} />, group: "Navigate" },
  { id: "n-scans", label: "Scans", href: "/scans", icon: <GitBranch size={15} />, group: "Navigate" },
  { id: "n-plan", label: "Plan Review", href: "/plan", icon: <FileSearch size={15} />, group: "Navigate" },
  { id: "n-settings", label: "Settings", href: "/settings", icon: <Settings size={15} />, group: "Navigate" }
];

export function CommandPalette({ findings }: { findings: { id: string; title: string; severity: string }[] }) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen((value) => !value);
      }
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
      setTimeout(() => inputRef.current?.focus(), 20);
    }
  }, [open]);

  const items = useMemo(() => {
    const findingItems: Item[] = findings.map((finding) => ({
      id: finding.id,
      label: finding.title,
      hint: finding.severity,
      href: `/findings/${finding.id}`,
      icon: <AlertTriangle size={15} />,
      group: "Findings"
    }));
    const all = [...NAV, ...findingItems];
    if (!query.trim()) return all.slice(0, 10);
    const q = query.toLowerCase();
    return all.filter((item) => item.label.toLowerCase().includes(q) || item.group.toLowerCase().includes(q)).slice(0, 12);
  }, [query, findings]);

  function go(item: Item) {
    setOpen(false);
    router.push(item.href);
  }

  if (!open) return null;

  return (
    <div
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) setOpen(false);
      }}
      style={{ position: "fixed", inset: 0, zIndex: 100, background: "rgba(2,4,3,0.62)", backdropFilter: "blur(3px)", display: "flex", alignItems: "flex-start", justifyContent: "center", paddingTop: "14vh" }}
    >
      <div style={{ width: "100%", maxWidth: 560, background: "var(--surface)", border: "1px solid var(--border-strong)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow)", overflow: "hidden" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "13px 16px", borderBottom: "1px solid var(--border)" }}>
          <Search size={17} className="dim" />
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setActive(0);
            }}
            onKeyDown={(event) => {
              if (event.key === "ArrowDown") {
                event.preventDefault();
                setActive((value) => Math.min(value + 1, items.length - 1));
              }
              if (event.key === "ArrowUp") {
                event.preventDefault();
                setActive((value) => Math.max(value - 1, 0));
              }
              if (event.key === "Enter" && items[active]) go(items[active]);
            }}
            placeholder="Jump to a page or search findings…"
            style={{ background: "transparent", border: "none", boxShadow: "none", padding: 0, fontSize: 15 }}
          />
        </div>
        <div style={{ maxHeight: 360, overflow: "auto", padding: 6 }}>
          {items.length === 0 ? <div className="muted" style={{ padding: "18px 12px", textAlign: "center" }}>No matches.</div> : null}
          {items.map((item, index) => (
            <button
              key={item.id}
              onMouseEnter={() => setActive(index)}
              onClick={() => go(item)}
              className="repo-menu-item"
              style={{ background: index === active ? "var(--surface-2)" : "transparent", justifyContent: "flex-start", padding: "9px 11px" }}
            >
              <span className="dim" style={{ display: "inline-flex" }}>{item.icon}</span>
              <span style={{ flex: 1, textAlign: "left", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.label}</span>
              {item.hint ? <span className={`badge ${item.hint} no-dot`} style={{ fontSize: 10 }}>{item.hint}</span> : <span className="muted" style={{ fontSize: 11 }}>{item.group}</span>}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

export function CommandTrigger() {
  return (
    <span className="kbd" title="Open command palette" style={{ cursor: "default" }}>
      ⌘K
    </span>
  );
}
