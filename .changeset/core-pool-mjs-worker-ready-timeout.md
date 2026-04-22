---
'@coraza/core': patch
---

`WAFPool`: ship the worker file as `pool-worker.mjs` so Node unambiguously
loads it as ESM regardless of what the surrounding bundler does with
`package.json` markers. Fixes a silent hang under Next.js 16 Turbopack
dev mode where the emitted worker was `.js` with ESM `import` statements
but no sibling `"type":"module"` — Node refused to load it, the worker
never signalled ready, and `createWAFPool` awaited forever
(github.com/coraza-incubator/coraza-node#8).

Also adds a `readyTimeoutMs` option to `createWAFPool` (default `10000`
ms): if every worker has not acknowledged the init handshake within the
window, the promise rejects with an actionable error that names the
likely bundler / module-format cause. No more hang-forever.

Public shape: `pool-worker.js` is no longer emitted — adapter callers
never reference it directly, but any external tooling that expected
`@coraza/core/dist/pool-worker.js` should switch to `pool-worker.mjs`.
