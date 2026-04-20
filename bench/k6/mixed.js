// Mixed-traffic k6 scenario against the shared example contract.
// Designed to approximate realistic app traffic, so the WAF overhead
// number we report is meaningful (not cherry-picked).
//
// Run:
//   BASE_URL=http://127.0.0.1:3001 k6 run bench/k6/mixed.js
//
// Env vars:
//   BASE_URL      target server (default http://127.0.0.1:3001)
//   VUS           virtual users (default 50)
//   DURATION      test duration (default 30s)
//   SCENARIO      single | mixed — default mixed
//
// Output: k6's summary + a JSON blob at stdout's tail for the runner to parse.

import http from 'k6/http'
import { check, group } from 'k6'
import { Trend, Counter } from 'k6/metrics'

const BASE = __ENV.BASE_URL || 'http://127.0.0.1:3001'
const VUS = parseInt(__ENV.VUS || '50', 10)
const DURATION = __ENV.DURATION || '30s'

export const options = {
  vus: VUS,
  duration: DURATION,
  thresholds: {
    // p(99) under 500 ms even with WAF+CRS — sanity ceiling, not a product SLO
    http_req_duration: ['p(99)<500'],
    // < 1% unexpected failures
    checks: ['rate>0.99'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
}

// Per-route latency trends so we can see which path is slow.
const trends = {
  root: new Trend('route_root', true),
  healthz: new Trend('route_healthz', true),
  search: new Trend('route_search', true),
  echo: new Trend('route_echo', true),
  upload: new Trend('route_upload', true),
  image: new Trend('route_image', true),
  user: new Trend('route_user', true),
  attackSqli: new Trend('route_attack_sqli', true),
  attackXss: new Trend('route_attack_xss', true),
}
const blocked = new Counter('blocked_attacks')
const missedAttacks = new Counter('missed_attacks')

const xssBody = JSON.stringify({ msg: '<script>alert(1)</script>' })
const benignBody = JSON.stringify({ msg: 'hello', userId: 42 })
const uploadBody = 'x'.repeat(1024)

// Shape of the traffic mix. Percentages should roughly reflect real apps —
// most traffic is benign reads; a minority are writes; attacks are rare.
// Adjust for your own workload by tweaking weights.
const scenarios = [
  { weight: 25, fn: rootReq },
  { weight: 30, fn: searchReq },
  { weight: 10, fn: healthzReq },
  { weight: 10, fn: userReq },
  { weight: 10, fn: echoReq },
  { weight: 5, fn: uploadReq },
  { weight: 5, fn: imageReq },
  { weight: 3, fn: sqliAttack },
  { weight: 2, fn: xssAttack },
]
const totalWeight = scenarios.reduce((s, x) => s + x.weight, 0)

export default function () {
  const forced = __ENV.SCENARIO
  if (forced === 'single') {
    rootReq()
    return
  }
  // Weighted pick
  let r = Math.random() * totalWeight
  for (const s of scenarios) {
    r -= s.weight
    if (r <= 0) {
      s.fn()
      return
    }
  }
}

function rootReq() {
  const r = http.get(`${BASE}/`)
  trends.root.add(r.timings.duration)
  check(r, { 'root 200': (x) => x.status === 200 })
}

function healthzReq() {
  const r = http.get(`${BASE}/healthz`)
  trends.healthz.add(r.timings.duration)
  check(r, { 'healthz 200': (x) => x.status === 200 })
}

function searchReq() {
  const r = http.get(`${BASE}/search?q=hello+world`)
  trends.search.add(r.timings.duration)
  check(r, { 'search 200': (x) => x.status === 200 })
}

function echoReq() {
  const r = http.post(`${BASE}/echo`, benignBody, {
    headers: { 'content-type': 'application/json' },
  })
  trends.echo.add(r.timings.duration)
  check(r, { 'echo 200': (x) => x.status === 200 })
}

function uploadReq() {
  const r = http.post(`${BASE}/upload`, uploadBody, {
    headers: { 'content-type': 'application/octet-stream' },
  })
  trends.upload.add(r.timings.duration)
  check(r, { 'upload 2xx': (x) => x.status >= 200 && x.status < 300 })
}

function imageReq() {
  const r = http.get(`${BASE}/img/logo.png`)
  trends.image.add(r.timings.duration)
  check(r, { 'image 200': (x) => x.status === 200 })
}

function userReq() {
  const r = http.get(`${BASE}/api/users/42`)
  trends.user.add(r.timings.duration)
  check(r, { 'user 200': (x) => x.status === 200 })
}

function sqliAttack() {
  const r = http.get(`${BASE}/search?q=${encodeURIComponent("' OR 1=1--")}`)
  trends.attackSqli.add(r.timings.duration)
  if (r.status >= 400) blocked.add(1)
  else missedAttacks.add(1)
}

function xssAttack() {
  const r = http.post(`${BASE}/echo`, xssBody, {
    headers: { 'content-type': 'application/json' },
  })
  trends.attackXss.add(r.timings.duration)
  if (r.status >= 400) blocked.add(1)
  else missedAttacks.add(1)
}
