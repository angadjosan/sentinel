"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState, useTransition } from "react";
import { Ban, Check, ShieldCheck, X, Radar } from "lucide-react";
import type { Finding } from "../lib/api";
import { SevDot, StatusPill, scanFamily, relativeTime } from "./ui";
import { toast } from "./Toast";
import { approveSuppressionAction, rejectSuppressionAction, suppressFindingAction } from "../app/findings/actions";

export function FindingList({ findings, showActions = true, keyboard = false }: { findings: Finding[]; showActions?: boolean; keyboard?: boolean }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [active, setActive] = useState(-1);
  const rowRefs = useRef<(HTMLDivElement | null)[]>([]);

  function run(action: () => Promise<void>, message: string) {
    startTransition(async () => {
      try {
        await action();
        toast(message);
      } catch (error) {
        toast(error instanceof Error ? error.message : "Action failed", "error");
      }
      router.refresh();
    });
  }

  useEffect(() => {
    if (!keyboard) return;
    function onKey(e: KeyboardEvent) {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || (e.target as HTMLElement)?.isContentEditable) return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "j" || e.key === "ArrowDown") { e.preventDefault(); setActive((v) => Math.min(v + 1, findings.length - 1)); }
      else if (e.key === "k" || e.key === "ArrowUp") { e.preventDefault(); setActive((v) => Math.max(v - 1, 0)); }
      else if ((e.key === "o" || e.key === "Enter") && active >= 0) { e.preventDefault(); router.push(`/findings/${findings[active].id}`); }
      else if (e.key === "e" && active >= 0) { const f = findings[active]; if (f.status !== "suppressed" && f.status !== "suppression_pending") run(() => suppressFindingAction(f.id, "Suppressed from the triage inbox"), "Finding suppressed"); }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [keyboard, active, findings]);

  useEffect(() => {
    if (active >= 0) rowRefs.current[active]?.scrollIntoView({ block: "nearest" });
  }, [active]);

  if (findings.length === 0) {
    return <div className="empty" style={{ padding: "40px 24px" }}><p>No findings match.</p></div>;
  }

  return (
    <div>
      {findings.map((finding, index) => (
        <div className={`finding-row${keyboard && index === active ? " kbd-active" : ""}`} key={finding.id} ref={(el) => { rowRefs.current[index] = el; }}>
          <SevDot severity={finding.severity} />
          <div className="fr-main">
            <Link href={`/findings/${finding.id}`} className="fr-title">
              {finding.title}
              {finding.confirmed ? <span className="chip warn"><ShieldCheck size={12} /> exploited</span> : null}
            </Link>
            <div className="fr-meta">
              <span className="chip">{scanFamily(finding.vuln_type)}</span>
              <span>{finding.vuln_type.replace(/_/g, " ")}</span>
              {finding.file ? <><span>·</span><span className="file-ref">{finding.file}{finding.line_start ? `:${finding.line_start}` : ""}</span></> : null}
            </div>
          </div>
          <div className="fr-side">
            <span className="cell-dim" style={{ fontSize: 12, minWidth: 66, textAlign: "right" }}>{relativeTime(finding.updated_at)}</span>
            <StatusPill status={finding.status} />
            {showActions ? (
              <div className="actions">
                {finding.status === "suppression_pending" ? (
                  <>
                    <button className="icon sm" title="Approve suppression" disabled={pending} onClick={() => run(() => approveSuppressionAction(finding.id, "Approved from the triage inbox"), "Suppression approved")}><Check size={15} /></button>
                    <button className="icon sm" title="Reject suppression" disabled={pending} onClick={() => run(() => rejectSuppressionAction(finding.id, "Rejected from the triage inbox"), "Suppression rejected")}><X size={15} /></button>
                  </>
                ) : (
                  <button className="icon sm" title="Suppress finding" disabled={pending || finding.status === "suppressed"} onClick={() => run(() => suppressFindingAction(finding.id, "Suppressed from the triage inbox"), "Finding suppressed")}><Ban size={15} /></button>
                )}
              </div>
            ) : (
              <Link href={`/findings/${finding.id}`} className="chip" title="Open finding"><Radar size={12} /></Link>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
