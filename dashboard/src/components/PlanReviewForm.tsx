"use client";

import { useState, useTransition } from "react";
import Link from "next/link";
import { FileSearch, CheckCircle2, AlertCircle } from "lucide-react";
import type { Repo } from "../lib/api";
import { reviewPlanAction } from "../app/settings/actions";
import { toast } from "./Toast";

export function PlanReviewForm({ repos }: { repos: Repo[] }) {
  const [repoId, setRepoId] = useState(repos[0]?.id ?? "");
  const [content, setContent] = useState("");
  const [withRetry, setWithRetry] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; runId?: string; message: string } | null>(null);
  const [pending, startTransition] = useTransition();

  function submit() {
    setResult(null);
    startTransition(async () => {
      const res = await reviewPlanAction(repoId, content, withRetry);
      if (res.startsWith("error")) {
        setResult({ ok: false, message: res.replace(/^error:\s*/, "") || "Could not queue plan review." });
        toast("Could not queue plan review", "error");
      } else {
        setResult({ ok: true, runId: res, message: "Plan review queued." });
        toast("Plan review queued");
      }
    });
  }

  return (
    <div className="grid two">
      <div className="panel">
        <div className="panel-header"><h2>Plan</h2><span className="muted">reviewed before any code is written</span></div>
        <div className="panel-body settings-form">
          <label><span>Repository</span>
            <select value={repoId} onChange={(e) => setRepoId(e.target.value)}>
              {repos.length === 0 ? <option value="">No repositories</option> : null}
              {repos.map((repo) => (<option key={repo.id} value={repo.id}>{repo.name}</option>))}
            </select>
          </label>
          <label><span>Plan content</span>
            <textarea value={content} onChange={(e) => setContent(e.target.value)} placeholder={"Paste an implementation plan, design doc, or IDE plan-mode output…\n\ne.g. Add a POST /api/export route that streams the user's data as CSV. It reads req.body.userId and returns rows from the reports table."} style={{ minHeight: 220 }} />
          </label>
          <label className="checkbox-row"><input type="checkbox" checked={withRetry} onChange={(e) => setWithRetry(e.target.checked)} /><span>Re-submit until no new issues surface (<code>--with-retry</code>, max 3 passes)</span></label>
          <div className="form-actions">
            <button className="primary" onClick={submit} disabled={pending || !repoId || !content.trim()}><FileSearch size={15} /> {pending ? "Queuing…" : "Review plan"}</button>
          </div>
          {result ? (
            <div className={`wrap ${result.ok ? "" : ""}`} style={{ alignItems: "center", background: result.ok ? "var(--accent-dim-2)" : "var(--critical-bg)", border: `1px solid ${result.ok ? "var(--border-accent)" : "rgba(255,93,93,0.3)"}`, borderRadius: "var(--radius-sm)", padding: "10px 12px" }}>
              {result.ok ? <CheckCircle2 size={15} className="accent-text" /> : <AlertCircle size={15} style={{ color: "var(--critical)" }} />}
              <span style={{ fontSize: 13 }}>{result.message}</span>
              {result.ok && result.runId ? <Link href={`/scans/${result.runId}`} className="link" style={{ marginLeft: "auto" }}>Track in Scans →</Link> : null}
            </div>
          ) : null}
        </div>
      </div>

      <div className="panel">
        <div className="panel-header"><h2>What it checks</h2></div>
        <div className="panel-body">
          <ul className="steps" style={{ paddingLeft: 18 }}>
            <li>Does the change <strong>remove a guard</strong> on an existing path?</li>
            <li>Does it add an <strong>unauthenticated entry point</strong> to a guarded handler?</li>
            <li>Does it introduce a <strong>new taint path</strong> to an existing sink?</li>
          </ul>
          <p className="hint" style={{ marginTop: 12 }}>The agent loads the referenced functions&apos; subgraphs — existing <code>GUARDED_BY</code> edges and any prior <code>CONFIRMED_EXPLOIT</code> findings — and annotates the plan with severity-rated, path-cited comments. Great as a CI gate or pre-commit hook.</p>
        </div>
      </div>
    </div>
  );
}
