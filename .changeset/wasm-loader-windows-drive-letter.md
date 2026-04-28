---
'@coraza/core': patch
---

Fix Windows file-URL handling in the WASM loader and pool worker spawn.
When a bundler (webpack / Turbopack) duplicates the `URL` class so that
`fileURLToPath` rejects with `ERR_INVALID_ARG_TYPE`, the previous
fallback decoded `URL.pathname` directly. On Windows this returns
`/C:/path/to/file` because that's how the WHATWG URL spec serialises a
drive-letter file URL — Node's `fs.readFile` and the
`worker_threads.Worker` constructor both reject that leading slash.

The fallback now strips the leading `/` from drive-letter paths and
reconstructs the UNC form for `file://server/share/...` URLs, so a
Windows-bundled middleware that ships its own URL class no longer fails
to load `coraza.wasm` or spawn the pool worker. The unit test exercises
the fix against synthetic Windows file URLs on every CI runner, so the
behaviour is locked in regardless of which platform CI is running on.

Resolves a latent Windows-only bug nobody noticed because CI was
Linux-only until now; CI now runs on Ubuntu, macOS, and Windows for
every per-package leg.
