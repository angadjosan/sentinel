"use client"

import { useEffect, useState } from "react"
import { SeverityBadge } from "./ui"
import type { Finding } from "../lib/api"

interface LiveFindingCardsProps {
  runId: string
  apiUrl: string
}

export function LiveFindingCards({ runId, apiUrl }: LiveFindingCardsProps) {
  const [findings, setFindings] = useState<Finding[]>([])
  const [connected, setConnected] = useState(false)
  const [done, setDone] = useState(false)

  useEffect(() => {
    const url = `${apiUrl}/runs/${runId}/events`
    const sse = new EventSource(url)

    sse.addEventListener("open", () => {
      setConnected(true)
    })

    sse.addEventListener("message", (event) => {
      try {
        const data = JSON.parse(event.data as string) as { kind?: string; finding?: Finding }
        if (data.kind === "finding" && data.finding) {
          setFindings((prev) => {
            const exists = prev.some((f) => f.id === data.finding!.id)
            return exists ? prev : [...prev, data.finding!]
          })
        }
        if (data.kind === "run.completed" || data.kind === "run.failed") {
          setDone(true)
          sse.close()
        }
      } catch {
        // ignore malformed events
      }
    })

    sse.addEventListener("error", () => {
      setConnected(false)
      setDone(true)
      sse.close()
    })

    return () => {
      sse.close()
    }
  }, [runId, apiUrl])

  return (
    <section className="panel" style={{ marginTop: 16 }}>
      <div className="panel-header">
        <h2>Live Findings</h2>
        <span className="muted" style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {!done && (
            <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
              <span
                style={{
                  width: 10,
                  height: 10,
                  borderRadius: "50%",
                  background: connected ? "var(--accent)" : "var(--medium)",
                  display: "inline-block",
                  animation: "pulse 1.5s infinite",
                }}
              />
              {connected ? "Scanning…" : "Connecting…"}
            </span>
          )}
          {done && <span>Scan complete — {findings.length} finding{findings.length !== 1 ? "s" : ""} detected</span>}
        </span>
      </div>
      <div className="panel-body">
        {findings.length === 0 && !done && (
          <div className="muted">Waiting for findings…</div>
        )}
        {findings.length === 0 && done && (
          <div className="muted">No findings detected during this scan.</div>
        )}
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {findings.map((finding) => (
            <div
              key={finding.id}
              className="panel"
              style={{ padding: "12px 16px", display: "flex", alignItems: "center", gap: 12 }}
            >
              <SeverityBadge severity={finding.severity} />
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600 }}>{finding.title}</div>
                <div className="muted" style={{ fontSize: 12 }}>
                  {finding.vuln_type}
                  {finding.file ? ` · ${finding.file}${finding.line_start ? `:${finding.line_start}` : ""}` : ""}
                </div>
              </div>
              {finding.confirmed && (
                <span style={{ color: "var(--critical)", fontSize: 12, fontWeight: 600 }}>CONFIRMED</span>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
