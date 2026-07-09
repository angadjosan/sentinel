"use client";

import { useEffect, useRef, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Search, X } from "lucide-react";

export function FindingsSearch() {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const [value, setValue] = useState(params.get("q") ?? "");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    setValue(params.get("q") ?? "");
  }, [params]);

  function commit(next: string) {
    const p = new URLSearchParams(Array.from(params.entries()));
    if (next) p.set("q", next);
    else p.delete("q");
    const qs = p.toString();
    router.replace(`${pathname}${qs ? `?${qs}` : ""}`, { scroll: false });
  }

  function onChange(next: string) {
    setValue(next);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => commit(next), 180);
  }

  return (
    <div className="search" style={{ position: "relative" }}>
      <Search size={14} className="dim" style={{ position: "absolute", left: 11, top: "50%", transform: "translateY(-50%)" }} />
      <input value={value} onChange={(e) => onChange(e.target.value)} placeholder="Search findings…" style={{ paddingLeft: 32, paddingRight: value ? 30 : 11, minWidth: 240 }} />
      {value ? <button className="ghost icon sm" onClick={() => onChange("")} style={{ position: "absolute", right: 4, top: "50%", transform: "translateY(-50%)" }} title="Clear"><X size={14} /></button> : null}
    </div>
  );
}
