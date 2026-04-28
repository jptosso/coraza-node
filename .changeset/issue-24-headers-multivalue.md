---
'@coraza/next': patch
'@coraza/express': patch
'@coraza/fastify': patch
'@coraza/nestjs': patch
---

Preserve multi-value list-form headers when handing requests to Coraza.
WHATWG `Headers.entries()` joins multi-value headers (`X-Forwarded-For`,
`Forwarded`, `Via`, `Warning`, `Set-Cookie`) into a single comma-joined
string, smashing the per-hop boundary that CRS IP-allowlist and
scanner-detection rules depend on. Each adapter now:

- `@coraza/next` — splits known RFC 7230 list-form request headers on
  the comma separator and uses `Headers.getSetCookie()` for set-cookie.
  `Cookie` is NOT split (RFC 6265 uses `;`, not `,`).
- `@coraza/express`, `@coraza/fastify`, `@coraza/nestjs` — prefer
  `req.rawHeaders` / `req.raw.rawHeaders` (Node's IncomingMessage flat
  pair array) when present, falling back to the joined `req.headers`
  when not. Closes #24.
