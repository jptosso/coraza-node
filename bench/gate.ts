// Per-PR perf-regression gate. Consumes two k6 --summary-export JSON blobs
// (baseline = main, candidate = PR head) and decides whether to fail the
// CI step.
//
// Design notes:
//
//   - We read the k6 JSON directly, not the human-formatted table written
//     by k6-run.ts's renderTable(). The table is tuned for eyeballing and
//     its shape has shifted before; the JSON is the API the threshold
//     gate needs to be built on.
//
//   - The two metrics we gate on are:
//
//       1. RPS (http_reqs.rate) under WAF=on. A drop here means the same
//          traffic is now slower. We allow up to RPS_DROP_PCT before
//          failing. Default 10% — runner noise on GitHub-hosted ubuntu
//          is ~±15% on absolute RPS, but a same-runner A/B on a 30s
//          sustained window narrows that to single-digit %.
//
//       2. P99 latency (http_req_duration.p99) under WAF=on. A spike
//          here means tail behavior degraded even if average is fine.
//          We allow up to P99_RISE_PCT before failing. Default 15% —
//          tail latency is noisier than mean throughput, so the tail
//          gate is looser than the throughput gate.
//
//     RPS is the primary "is this slower" signal; P99 is the tail
//     guardrail. A regression is anything that breaches either gate.
//
//   - The gate also emits a PR-comment-shaped markdown summary on
//     stdout (between BEGIN/END markers) so the workflow can capture
//     it and post it inline.
//
//   - Exit codes:
//       0 — OK (within thresholds, or BASELINE_OPTIONAL=1 and no baseline)
//       1 — regressed past threshold OR a parsing error occurred
//
// Usage:
//   tsx bench/gate.ts \
//     --baseline=path/to/main.json \
//     --candidate=path/to/pr.json \
//     [--rps-drop-pct=10] [--p99-rise-pct=15] [--label=express]
//
// If baseline is missing AND BASELINE_OPTIONAL=1, the gate prints the
// candidate-side numbers and exits 0. Useful for the "first run on a
// branch where main hasn't been re-benched yet" case.

import * as fs from 'node:fs'

interface K6Summary {
  metrics: Record<
    string,
    {
      rate?: number
      count?: number
      avg?: number
      med?: number
      max?: number
      min?: number
      ['p(90)']?: number
      ['p(95)']?: number
      ['p(99)']?: number
    }
  >
}

interface BenchPoint {
  rps: number
  p95Ms: number
  p99Ms: number
  blocked: number
  missed: number
}

interface GateConfig {
  baselinePath: string
  candidatePath: string
  rpsDropPct: number
  p99RisePct: number
  label: string
  baselineOptional: boolean
}

interface GateOutcome {
  ok: boolean
  reasons: string[]
  baseline: BenchPoint | null
  candidate: BenchPoint
  rpsDeltaPct: number | null
  p99DeltaPct: number | null
}

function parseSummary(path: string): BenchPoint {
  const raw = fs.readFileSync(path, 'utf8')
  const json = JSON.parse(raw) as K6Summary
  const reqs = json.metrics.http_reqs ?? {}
  const dur = json.metrics.http_req_duration ?? {}
  const blocked = json.metrics.blocked_attacks ?? {}
  const missed = json.metrics.missed_attacks ?? {}
  return {
    rps: Number(reqs.rate ?? 0),
    p95Ms: Number(dur['p(95)'] ?? 0),
    p99Ms: Number(dur['p(99)'] ?? 0),
    blocked: Number(blocked.count ?? 0),
    missed: Number(missed.count ?? 0),
  }
}

function evaluate(config: GateConfig): GateOutcome {
  const candidate = parseSummary(config.candidatePath)
  const reasons: string[] = []

  if (!fs.existsSync(config.baselinePath)) {
    if (config.baselineOptional) {
      return {
        ok: true,
        reasons: ['no baseline available; BASELINE_OPTIONAL=1, skipping gate'],
        baseline: null,
        candidate,
        rpsDeltaPct: null,
        p99DeltaPct: null,
      }
    }
    return {
      ok: false,
      reasons: [`baseline JSON missing at ${config.baselinePath}`],
      baseline: null,
      candidate,
      rpsDeltaPct: null,
      p99DeltaPct: null,
    }
  }
  const baseline = parseSummary(config.baselinePath)

  // RPS regression: candidate must be at least baseline * (1 - dropPct/100).
  const rpsFloor = baseline.rps * (1 - config.rpsDropPct / 100)
  const rpsDeltaPct = baseline.rps > 0 ? ((candidate.rps - baseline.rps) / baseline.rps) * 100 : 0
  if (baseline.rps > 0 && candidate.rps < rpsFloor) {
    reasons.push(
      `RPS dropped ${(-rpsDeltaPct).toFixed(1)}% (${candidate.rps.toFixed(1)} vs baseline ${baseline.rps.toFixed(1)}; gate: drop must be <${config.rpsDropPct}%)`,
    )
  }

  // P99 regression: candidate must be at most baseline * (1 + risePct/100).
  const p99Ceiling = baseline.p99Ms * (1 + config.p99RisePct / 100)
  const p99DeltaPct = baseline.p99Ms > 0 ? ((candidate.p99Ms - baseline.p99Ms) / baseline.p99Ms) * 100 : 0
  if (baseline.p99Ms > 0 && candidate.p99Ms > p99Ceiling) {
    reasons.push(
      `P99 rose ${p99DeltaPct.toFixed(1)}% (${candidate.p99Ms.toFixed(1)}ms vs baseline ${baseline.p99Ms.toFixed(1)}ms; gate: rise must be <${config.p99RisePct}%)`,
    )
  }

  // Sanity: if the WAF stops blocking attacks, that's a worse regression
  // than any latency change. This makes the per-PR gate a security check
  // too — see AGENTS.md "Security > Performance".
  if (candidate.missed > 0) {
    reasons.push(`WAF missed ${candidate.missed} attack(s) under candidate run — security regression`)
  }

  return {
    ok: reasons.length === 0,
    reasons,
    baseline,
    candidate,
    rpsDeltaPct,
    p99DeltaPct,
  }
}

function fmtDelta(pct: number | null): string {
  if (pct === null) return 'n/a'
  const sign = pct >= 0 ? '+' : ''
  return `${sign}${pct.toFixed(1)}%`
}

function fmtNum(n: number | undefined, decimals = 1): string {
  if (n === undefined) return 'n/a'
  return n.toFixed(decimals)
}

function renderMarkdown(outcome: GateOutcome, label: string, config: GateConfig): string {
  const { baseline, candidate, rpsDeltaPct, p99DeltaPct } = outcome
  const verdict = outcome.ok ? 'PASS' : 'FAIL'
  const lines: string[] = []
  lines.push(`### Bench gate (${label}): ${verdict}`)
  lines.push('')
  lines.push(`| metric | baseline (main) | candidate (PR) | delta | gate |`)
  lines.push(`|---|---|---|---|---|`)
  lines.push(
    `| RPS | ${fmtNum(baseline?.rps)} | ${fmtNum(candidate.rps)} | ${fmtDelta(rpsDeltaPct)} | drop > ${config.rpsDropPct}% fails |`,
  )
  lines.push(
    `| P95 ms | ${fmtNum(baseline?.p95Ms)} | ${fmtNum(candidate.p95Ms)} | ${baseline ? fmtDelta(((candidate.p95Ms - baseline.p95Ms) / Math.max(baseline.p95Ms, 1e-9)) * 100) : 'n/a'} | advisory |`,
  )
  lines.push(
    `| P99 ms | ${fmtNum(baseline?.p99Ms)} | ${fmtNum(candidate.p99Ms)} | ${fmtDelta(p99DeltaPct)} | rise > ${config.p99RisePct}% fails |`,
  )
  lines.push(
    `| attacks blocked | ${baseline?.blocked ?? 'n/a'} | ${candidate.blocked} | — | informational |`,
  )
  lines.push(
    `| attacks missed | ${baseline?.missed ?? 'n/a'} | ${candidate.missed} | — | any miss fails |`,
  )
  if (!outcome.ok) {
    lines.push('')
    lines.push('**Reasons:**')
    for (const r of outcome.reasons) lines.push(`- ${r}`)
  }
  lines.push('')
  lines.push(
    `_Adapter: \`${label}\` · runner: GitHub-hosted ubuntu (~±5% same-runner noise on 30s windows). The weekly bench (${'`bench.yml`'}) tracks the full Express/Fastify/Nest matrix; this PR gate runs Express only for fast feedback._`,
  )
  return lines.join('\n')
}

function parseArgs(argv: string[]): GateConfig {
  const out: GateConfig = {
    baselinePath: '',
    candidatePath: '',
    rpsDropPct: Number(process.env.RPS_DROP_PCT ?? '10'),
    p99RisePct: Number(process.env.P99_RISE_PCT ?? '15'),
    label: 'express',
    baselineOptional: process.env.BASELINE_OPTIONAL === '1',
  }
  for (const raw of argv) {
    const [k, v] = raw.replace(/^--/, '').split('=', 2) as [string, string | undefined]
    if (k === 'baseline' && v) out.baselinePath = v
    else if (k === 'candidate' && v) out.candidatePath = v
    else if (k === 'rps-drop-pct' && v) out.rpsDropPct = Number(v)
    else if (k === 'p99-rise-pct' && v) out.p99RisePct = Number(v)
    else if (k === 'label' && v) out.label = v
    else if (k === 'baseline-optional') out.baselineOptional = true
  }
  if (!out.candidatePath) {
    throw new Error('--candidate=<path> is required')
  }
  return out
}

function main(): void {
  const config = parseArgs(process.argv.slice(2))
  const outcome = evaluate(config)
  const md = renderMarkdown(outcome, config.label, config)

  // Human log on stderr (so stdout can be piped into a comment file).
  process.stderr.write(`\n${md}\n`)

  // Markdown body on stdout, fenced with markers so the workflow can carve
  // it out reliably even if other tools spam stdout.
  process.stdout.write(`<!--BEGIN_BENCH_GATE_MD-->\n${md}\n<!--END_BENCH_GATE_MD-->\n`)

  if (!outcome.ok) {
    process.stderr.write(`\nbench-gate: FAIL — ${outcome.reasons.join('; ')}\n`)
    process.exit(1)
  }
  process.stderr.write(`\nbench-gate: PASS\n`)
}

// CLI entry. This file is only invoked via `tsx bench/gate.ts ...` from
// the per-PR workflow; it isn't imported elsewhere.
try {
  main()
} catch (err) {
  process.stderr.write(`bench-gate: error: ${(err as Error).message}\n`)
  process.exit(1)
}
