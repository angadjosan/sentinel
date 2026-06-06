"use client";

import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Finding, Run } from "../lib/api";

function day(value: string | undefined, fallback: number): string {
  if (!value) return `run ${fallback + 1}`;
  return value.slice(0, 10);
}

export function FindingTrend({ findings }: { findings: Finding[] }) {
  const counts = new Map<string, { label: string; critical: number; high: number; medium: number; low: number; info: number }>();
  findings.forEach((finding, index) => {
    const label = day(finding.id, index);
    const row = counts.get(label) ?? { label, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    row[finding.severity] += 1;
    counts.set(label, row);
  });
  const data = Array.from(counts.values()).slice(-30);
  return (
    <ResponsiveContainer width="100%" height={260}>
      <LineChart data={data}>
        <CartesianGrid stroke="#e5e7eb" />
        <XAxis dataKey="label" />
        <YAxis allowDecimals={false} />
        <Tooltip />
        <Line type="monotone" dataKey="critical" stroke="#b42318" />
        <Line type="monotone" dataKey="high" stroke="#c2410c" />
        <Line type="monotone" dataKey="medium" stroke="#a16207" />
        <Line type="monotone" dataKey="low" stroke="#2563eb" />
      </LineChart>
    </ResponsiveContainer>
  );
}

export function TokenChart({ runs }: { runs: Run[] }) {
  const data = runs.slice(0, 30).reverse().map((run, index) => ({
    label: `${run.kind} ${index + 1}`,
    tokens: run.token_spend
  }));
  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={data}>
        <CartesianGrid stroke="#e5e7eb" />
        <XAxis dataKey="label" />
        <YAxis allowDecimals={false} />
        <Tooltip />
        <Bar dataKey="tokens" fill="#0f766e" />
      </BarChart>
    </ResponsiveContainer>
  );
}
