// Single-route k6 scenario. Hammer one endpoint to measure its steady-state
// throughput under WAF=on vs WAF=off. Used by the runner to populate the
// per-route comparison table.
//
// Run:
//   BASE_URL=http://127.0.0.1:3001 ROUTE=search k6 run bench/k6/per-route.js
//
// Env:
//   BASE_URL       target server
//   ROUTE          root | healthz | search | echo | upload | image | user | sqli | xss
//   VUS            virtual users (default 50)
//   DURATION       test duration (default 20s)

import http from 'k6/http'
import { check } from 'k6'

const BASE = __ENV.BASE_URL || 'http://127.0.0.1:3001'
const ROUTE = __ENV.ROUTE || 'root'

export const options = {
  vus: parseInt(__ENV.VUS || '50', 10),
  duration: __ENV.DURATION || '20s',
  thresholds: {
    checks: ['rate>0.99'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
}

const routes = {
  root: () => http.get(`${BASE}/`),
  healthz: () => http.get(`${BASE}/healthz`),
  search: () => http.get(`${BASE}/search?q=hello`),
  echo: () =>
    http.post(`${BASE}/echo`, JSON.stringify({ msg: 'hi' }), {
      headers: { 'content-type': 'application/json' },
    }),
  upload: () =>
    http.post(`${BASE}/upload`, 'x'.repeat(1024), {
      headers: { 'content-type': 'application/octet-stream' },
    }),
  image: () => http.get(`${BASE}/img/logo.png`),
  user: () => http.get(`${BASE}/api/users/42`),
  sqli: () => http.get(`${BASE}/search?q=${encodeURIComponent("' OR 1=1--")}`),
  xss: () =>
    http.post(`${BASE}/echo`, JSON.stringify({ msg: '<script>alert(1)</script>' }), {
      headers: { 'content-type': 'application/json' },
    }),
}

export default function () {
  const fn = routes[ROUTE]
  if (!fn) throw new Error(`unknown ROUTE=${ROUTE}`)
  const r = fn()
  // For attack routes (sqli/xss) we expect 4xx when WAF=on; treat both as ok
  // so the run doesn't fail its threshold mid-test.
  if (ROUTE === 'sqli' || ROUTE === 'xss') {
    check(r, { 'responded': (x) => x.status >= 200 && x.status < 600 })
  } else {
    check(r, { '2xx': (x) => x.status >= 200 && x.status < 400 })
  }
}
