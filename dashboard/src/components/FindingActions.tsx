"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Ban, Crosshair, RotateCcw, Link2, Check } from "lucide-react";
import type { Finding } from "../lib/api";
import { toast } from "./Toast";
import { startPentestAction, suppressFindingAction, unsuppressFindingAction } from "../app/findings/actions";

export function FindingActions({ finding }: { finding: Finding }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [showSuppress, setShowSuppress] = useState(false);
  const [reason, setReason] = useState("");
  const [copied, setCopied] = useState(false);
  const [pentestMsg, setPentestMsg] = useState<string | null>(null);

  const suppressed = finding.status === "suppressed" || finding.status === "suppression_pending";

  function suppress() {
    startTransition(async () => {
      try {
        await suppressFindingAction(finding.id, reason);
        setShowSuppress(false);
        setReason("");
        toast("Finding suppressed");
      } catch (error) {
        toast(error instanceof Error ? error.message : "Could not suppress", "error");
      }
      router.refresh();
    });
  }
  function reopen() {
    startTransition(async () => {
      await unsuppressFindingAction(finding.id);
      toast("Finding reopened");
      router.refresh();
    });
  }
  function pentest() {
    setPentestMsg(null);
    startTransition(async () => {
      const result = await startPentestAction(finding.id);
      if (result.startsWith("error")) {
        setPentestMsg("Could not queue pentest (worker offline?)");
        toast("Could not queue pentest", "error");
      } else {
        setPentestMsg("Pentest queued — track it in Scans.");
        toast("Pentest queued — track it in Scans");
      }
      router.refresh();
    });
  }
  function copy() {
    navigator.clipboard?.writeText(window.location.href).then(() => {
      setCopied(true);
      toast("Link copied");
      setTimeout(() => setCopied(false), 1400);
    });
  }

  return (
    <div className="stack" style={{ gap: 10 }}>
      <div className="wrap">
        <button className="primary" onClick={pentest} disabled={pending || finding.confirmed}>
          <Crosshair size={15} /> {finding.confirmed ? "Exploit confirmed" : "Run pentest"}
        </button>
        {suppressed ? (
          <button onClick={reopen} disabled={pending}><RotateCcw size={15} /> Reopen</button>
        ) : (
          <button onClick={() => setShowSuppress((v) => !v)} disabled={pending}><Ban size={15} /> Suppress</button>
        )}
        <button onClick={copy}>{copied ? <><Check size={15} /> Copied</> : <><Link2 size={15} /> Copy link</>}</button>
      </div>

      {pentestMsg ? <div className="dim" style={{ fontSize: 12.5 }}>{pentestMsg}</div> : null}

      {showSuppress ? (
        <div className="panel" style={{ padding: 12, display: "grid", gap: 8 }}>
          <textarea placeholder="Reason for suppression (required, min 10 chars — recorded in the audit trail)" value={reason} onChange={(e) => setReason(e.target.value)} style={{ minHeight: 64 }} />
          <div className="spread">
            <span className="muted" style={{ fontSize: 12 }}>{reason.trim().length < 10 ? `${10 - Math.min(10, reason.trim().length)} more characters needed` : "Recorded in the audit trail"}</span>
            <div className="actions">
              <button onClick={() => setShowSuppress(false)}>Cancel</button>
              <button className="primary" onClick={suppress} disabled={pending || reason.trim().length < 10}>Suppress finding</button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
