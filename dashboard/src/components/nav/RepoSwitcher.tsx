"use client";

import { useEffect, useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Check, ChevronsUpDown, GitBranch, Layers } from "lucide-react";
import type { Repo } from "../../lib/api";
import { selectRepoAction } from "../../app/repo-action";
import { toast } from "../Toast";

export function RepoSwitcher({ repos, selected }: { repos: Repo[]; selected: string | null }) {
  const [open, setOpen] = useState(false);
  const [pending, startTransition] = useTransition();
  const ref = useRef<HTMLDivElement>(null);
  const router = useRouter();

  useEffect(() => {
    function onClick(event: MouseEvent) {
      if (ref.current && !ref.current.contains(event.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  function choose(name: string) {
    setOpen(false);
    startTransition(async () => {
      await selectRepoAction(name);
      toast(name ? `Scoped to ${name}` : "Showing all repositories", "info");
      router.refresh();
    });
  }

  const current = selected ?? (repos.length ? "All repositories" : "No repositories");

  return (
    <div className="repo-switcher" ref={ref}>
      <button className="repo-switcher-btn" onClick={() => setOpen((value) => !value)} disabled={pending}>
        {selected ? <GitBranch size={14} className="accent-text" /> : <Layers size={14} className="dim" />}
        <span className="repo-name">{current}</span>
        <ChevronsUpDown size={13} className="chev" />
      </button>
      {open ? (
        <div className="repo-menu">
          <div className="repo-menu-label">Repositories</div>
          <button className={`repo-menu-item ${!selected ? "selected" : ""}`} onClick={() => choose("")}>
            <Layers size={14} />
            <span style={{ flex: 1, textAlign: "left" }}>All repositories</span>
            {!selected ? <Check size={14} /> : null}
          </button>
          {repos.map((repo) => (
            <button key={repo.id} className={`repo-menu-item ${selected === repo.name ? "selected" : ""}`} onClick={() => choose(repo.name)}>
              <GitBranch size={14} />
              <span style={{ flex: 1, textAlign: "left", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{repo.name}</span>
              {selected === repo.name ? <Check size={14} /> : null}
            </button>
          ))}
          {repos.length === 0 ? <div className="repo-menu-label" style={{ textTransform: "none", letterSpacing: 0 }}>Run <code>sentinel init</code> to register one.</div> : null}
        </div>
      ) : null}
    </div>
  );
}
