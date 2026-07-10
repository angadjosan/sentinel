"use client";

import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { FindingTrendPoint, Run } from "../lib/api";

const SEV = [
  { key: "critical", color: "#ff5d5d" },
  { key: "high", color: "#ff9e4f" },
  { key: "medium", color: "#ffd15c" },
  { key: "low", color: "#5ea8ff" },
  { key: "info", color: "#93a1b3" }
] as const;

type Row = { label: string; critical: number; high: number; medium: number; low: number; info: number };

function ChartTooltip({ active, payload, label, unit }: { active?: boolean; payload?: Array<{ name: string; value: number; color: string }>; label?: string; unit?: string }) {
  if (!active || !payload?.length) return null;
  const rows = payload.filter((row) => row.value > 0);
  return (
    <div className="chart-tooltip">
      <div className="ct-label">{label}</div>
      {(rows.length ? rows : payload).map((row) => (
        <div className="ct-row" key={row.name}>
          <span className="ct-swatch" style={{ background: row.color }} />
          <span style={{ textTransform: "capitalize" }}>{row.name}</span>
          <span className="mono" style={{ marginLeft: "auto" }}>{row.value.toLocaleString()}{unit ?? ""}</span>
        </div>
      ))}
    </div>
  );
}

export function FindingTrend({ points }: { points: FindingTrendPoint[] }) {
  const byDate = new Map<string, Row>();
  for (const point of points) {
    const label = point.date.slice(5, 10);
    const row = byDate.get(label) ?? { label, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    if (point.severity in row) (row as unknown as Record<string, number>)[point.severity] += point.count;
    byDate.set(label, row);
  }
  const data = Array.from(byDate.values()).slice(-30);
  if (data.length === 0) return <ChartEmpty note="No findings recorded yet." />;
  if (data.length === 1) return <ChartEmpty note="Not enough history yet — the trend fills in once scans land across multiple days." />;

  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={data} margin={{ top: 6, right: 6, left: -18, bottom: 0 }}>
        <defs>
          {SEV.map((sev) => (
            <linearGradient id={`g-${sev.key}`} key={sev.key} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={sev.color} stopOpacity={0.35} />
              <stop offset="100%" stopColor={sev.color} stopOpacity={0.02} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid vertical={false} />
        <XAxis dataKey="label" tickLine={false} axisLine={false} minTickGap={20} />
        <YAxis allowDecimals={false} tickLine={false} axisLine={false} width={34} />
        <Tooltip content={<ChartTooltip />} cursor={{ stroke: "#2e3733" }} />
        {SEV.map((sev) => (
          <Area key={sev.key} type="monotone" dataKey={sev.key} stackId="1" stroke={sev.color} strokeWidth={1.5} fill={`url(#g-${sev.key})`} />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function TokenChart({ runs }: { runs: Run[] }) {
  const data = runs
    .filter((run) => run.token_spend > 0)
    .slice(0, 24)
    .reverse()
    .map((run, index) => ({ label: `${run.kind}·${index + 1}`, tokens: run.token_spend }));
  if (data.length === 0) return <ChartEmpty note="No token spend recorded yet." />;
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} margin={{ top: 6, right: 6, left: -18, bottom: 0 }}>
        <CartesianGrid vertical={false} />
        <XAxis dataKey="label" tickLine={false} axisLine={false} minTickGap={16} />
        <YAxis allowDecimals={false} tickLine={false} axisLine={false} width={44} />
        <Tooltip content={<ChartTooltip unit=" tok" />} cursor={{ fill: "rgba(45,212,130,0.06)" }} />
        <Bar dataKey="tokens" fill="#2dd482" radius={[3, 3, 0, 0]} maxBarSize={30} />
      </BarChart>
    </ResponsiveContainer>
  );
}

function ChartEmpty({ note }: { note: string }) {
  return (
    <div style={{ alignItems: "center", color: "var(--muted)", display: "flex", height: 220, justifyContent: "center", fontSize: 13 }}>
      {note}
    </div>
  );
}
