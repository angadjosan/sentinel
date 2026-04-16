import { NextResponse } from 'next/server'
import fs from 'fs'
import path from 'path'

export async function GET() {
  // Read from SENTINEL_REPORT_PATH env var, or default to ./sentinel-report/findings.json
  const reportPath = process.env.SENTINEL_REPORT_PATH ||
    path.join(process.cwd(), '..', 'sentinel-report', 'findings.json')

  try {
    const data = fs.readFileSync(reportPath, 'utf-8')
    return NextResponse.json(JSON.parse(data))
  } catch {
    // Return empty report structure if no file yet
    return NextResponse.json({
      scan_id: null,
      repo: null,
      timestamp: null,
      dep_findings: [],
      code_security_findings: [],
      attack_surface_findings: [],
      risk_score: 0,
      total_findings: 0,
    })
  }
}
