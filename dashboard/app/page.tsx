'use client'

import { useEffect, useState } from 'react'

// --- Types ---

interface DepFinding {
  package: string
  version: string
  ecosystem: string
  cve_id: string
  cvss_score: number
  severity: string
  summary: string
  fix_version: string
}

interface CodeFinding {
  file: string
  line: number
  category: string
  severity: string
  cwe_id: string
  explanation: string
  fix_suggestion: string
}

interface AttackSurfaceFinding {
  asset: string
  asset_type: string
  issue: string
  severity: string
  details: Record<string, unknown>
}

interface Report {
  scan_id: string | null
  repo: string | null
  timestamp: string | null
  risk_score: number
  total_findings: number
  dep_findings: DepFinding[]
  code_security_findings: CodeFinding[]
  attack_surface_findings: AttackSurfaceFinding[]
}

// --- Helpers ---

type Tab = 'dependencies' | 'code' | 'surface'

function severityBadge(severity: string) {
  const s = severity?.toLowerCase() ?? ''
  const colorMap: Record<string, string> = {
    critical: 'bg-red-600 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-yellow-500 text-gray-900',
    low: 'bg-blue-400 text-gray-900',
    info: 'bg-gray-400 text-gray-900',
  }
  const cls = colorMap[s] ?? 'bg-gray-600 text-white'
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide ${cls}`}>
      {severity || 'unknown'}
    </span>
  )
}

function riskColor(score: number) {
  if (score > 70) return 'text-red-500 border-red-500'
  if (score > 40) return 'text-orange-400 border-orange-400'
  return 'text-green-400 border-green-400'
}

function formatTimestamp(ts: string | null) {
  if (!ts) return '—'
  try {
    return new Date(ts).toLocaleString()
  } catch {
    return ts
  }
}

// --- Sub-components ---

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg px-6 py-4 flex flex-col items-center gap-1">
      <span className="text-3xl font-bold text-white">{value}</span>
      <span className="text-sm text-gray-400">{label}</span>
    </div>
  )
}

function DepsTable({ findings }: { findings: DepFinding[] }) {
  if (findings.length === 0) {
    return <EmptyState message="No dependency findings." />
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-800 text-gray-400 text-left">
            <th className="py-3 pr-4 font-medium">Package</th>
            <th className="py-3 pr-4 font-medium">Version</th>
            <th className="py-3 pr-4 font-medium">CVE</th>
            <th className="py-3 pr-4 font-medium">CVSS</th>
            <th className="py-3 pr-4 font-medium">Severity</th>
            <th className="py-3 pr-4 font-medium">Fix Version</th>
            <th className="py-3 font-medium">Summary</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-900/60 transition-colors">
              <td className="py-3 pr-4 font-mono text-gray-200">{f.package}</td>
              <td className="py-3 pr-4 font-mono text-gray-400">{f.version}</td>
              <td className="py-3 pr-4">
                {f.cve_id ? (
                  <span className="font-mono text-blue-400">{f.cve_id}</span>
                ) : (
                  <span className="text-gray-600">—</span>
                )}
              </td>
              <td className="py-3 pr-4">
                {f.cvss_score != null ? (
                  <span className="font-semibold text-gray-200">{f.cvss_score.toFixed(1)}</span>
                ) : (
                  <span className="text-gray-600">—</span>
                )}
              </td>
              <td className="py-3 pr-4">{severityBadge(f.severity)}</td>
              <td className="py-3 pr-4 font-mono text-green-400">{f.fix_version || '—'}</td>
              <td className="py-3 text-gray-400 max-w-xs truncate" title={f.summary}>{f.summary || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function CodeTable({ findings }: { findings: CodeFinding[] }) {
  if (findings.length === 0) {
    return <EmptyState message="No code security findings." />
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-800 text-gray-400 text-left">
            <th className="py-3 pr-4 font-medium">File : Line</th>
            <th className="py-3 pr-4 font-medium">Category</th>
            <th className="py-3 pr-4 font-medium">Severity</th>
            <th className="py-3 pr-4 font-medium">CWE</th>
            <th className="py-3 pr-4 font-medium">Explanation</th>
            <th className="py-3 font-medium">Fix</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-900/60 transition-colors">
              <td className="py-3 pr-4 font-mono text-blue-300 whitespace-nowrap">
                {f.file}<span className="text-gray-600">:</span><span className="text-gray-400">{f.line}</span>
              </td>
              <td className="py-3 pr-4 capitalize text-gray-300">{f.category}</td>
              <td className="py-3 pr-4">{severityBadge(f.severity)}</td>
              <td className="py-3 pr-4 font-mono text-gray-400">{f.cwe_id || '—'}</td>
              <td className="py-3 pr-4 text-gray-400 max-w-xs truncate" title={f.explanation}>{f.explanation || '—'}</td>
              <td className="py-3 text-gray-400 max-w-xs truncate" title={f.fix_suggestion}>{f.fix_suggestion || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function SurfaceTable({ findings }: { findings: AttackSurfaceFinding[] }) {
  if (findings.length === 0) {
    return <EmptyState message="No attack surface findings." />
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-800 text-gray-400 text-left">
            <th className="py-3 pr-4 font-medium">Asset</th>
            <th className="py-3 pr-4 font-medium">Type</th>
            <th className="py-3 pr-4 font-medium">Issue</th>
            <th className="py-3 font-medium">Severity</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-900/60 transition-colors">
              <td className="py-3 pr-4 font-mono text-gray-200">{f.asset}</td>
              <td className="py-3 pr-4 text-gray-400 uppercase text-xs tracking-wide">{f.asset_type}</td>
              <td className="py-3 pr-4 text-gray-300">{f.issue}</td>
              <td className="py-3">{severityBadge(f.severity)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="py-16 text-center text-gray-600">
      <svg className="mx-auto mb-3 w-8 h-8 opacity-40" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
          d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
      <p className="text-sm">{message}</p>
    </div>
  )
}

// --- Main Page ---

export default function Page() {
  const [report, setReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState<Tab>('dependencies')

  useEffect(() => {
    fetch('/api/findings')
      .then((r) => r.json())
      .then((data: Report) => {
        setReport(data)
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-gray-500 text-sm animate-pulse">Loading findings...</div>
      </div>
    )
  }

  const data = report ?? {
    scan_id: null, repo: null, timestamp: null,
    risk_score: 0, total_findings: 0,
    dep_findings: [], code_security_findings: [], attack_surface_findings: [],
  }

  const tabs: { id: Tab; label: string; count: number }[] = [
    { id: 'dependencies', label: 'Dependencies', count: data.dep_findings.length },
    { id: 'code', label: 'Code Security', count: data.code_security_findings.length },
    { id: 'surface', label: 'Attack Surface', count: data.attack_surface_findings.length },
  ]

  const scoreColorCls = riskColor(data.risk_score)

  return (
    <div className="max-w-7xl mx-auto px-6 py-6">

      {/* Header */}
      <header className="flex items-center justify-between mb-8 pb-4 border-b border-gray-800">
        <div className="flex items-center gap-3">
          <svg className="w-7 h-7 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <span className="text-xl font-bold tracking-tight text-white">Sentinel</span>
        </div>
        <div className="text-right">
          {data.repo && (
            <p className="text-sm text-gray-300 font-mono">{data.repo}</p>
          )}
          {data.timestamp && (
            <p className="text-xs text-gray-500 mt-0.5">{formatTimestamp(data.timestamp)}</p>
          )}
          {!data.repo && !data.timestamp && (
            <p className="text-xs text-gray-600 italic">No scan loaded</p>
          )}
        </div>
      </header>

      {/* Risk score + stat cards */}
      <div className="flex flex-col sm:flex-row gap-6 mb-8">
        {/* Risk Score */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg px-8 py-6 flex flex-col items-center justify-center min-w-[160px]">
          <div className={`w-24 h-24 rounded-full border-4 flex items-center justify-center mb-3 ${scoreColorCls}`}>
            <span className="text-3xl font-bold">{data.risk_score}</span>
          </div>
          <span className="text-sm text-gray-400 font-medium">Risk Score</span>
        </div>

        {/* Stat cards */}
        <div className="flex flex-1 gap-4 items-stretch">
          <StatCard label="Dep Findings" value={data.dep_findings.length} />
          <StatCard label="Code Findings" value={data.code_security_findings.length} />
          <StatCard label="Surface Findings" value={data.attack_surface_findings.length} />
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-6">
        <div className="flex gap-1 border-b border-gray-800">
          {tabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
                tab === t.id
                  ? 'border-red-500 text-white'
                  : 'border-transparent text-gray-500 hover:text-gray-300'
              }`}
            >
              {t.label}
              <span className={`ml-2 text-xs px-1.5 py-0.5 rounded-full ${
                tab === t.id ? 'bg-red-500/20 text-red-400' : 'bg-gray-800 text-gray-500'
              }`}>
                {t.count}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-4">
        {tab === 'dependencies' && <DepsTable findings={data.dep_findings} />}
        {tab === 'code' && <CodeTable findings={data.code_security_findings} />}
        {tab === 'surface' && <SurfaceTable findings={data.attack_surface_findings} />}
      </div>
    </div>
  )
}
