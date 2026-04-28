# @coraza/example-express

Demo Express 5 app wrapped by `@coraza/express` so a single Coraza WAF
inspects every common HTTP payload shape: JSON, urlencoded, multipart,
streamed file downloads, and the WebSocket upgrade handshake.

## Run

```sh
pnpm install
pnpm -F '@coraza/*' build       # adapters need dist/ for workspace import
PORT=3001 pnpm -F @coraza/example-express dev
```

`MODE=block` (default) returns 403 on detection. `MODE=detect` only logs.
`WAF=off` disables the middleware entirely. `POOL=1` swaps the single
WAF for a `WAFPool` of `POOL_SIZE` workers.

## Endpoints

| Method | Path                | Payload                    | Notes                                                       |
| ------ | ------------------- | -------------------------- | ----------------------------------------------------------- |
| POST   | `/echo`             | `application/json` (≤10MB) | JSON body echo                                              |
| POST   | `/form`             | `application/x-www-form-urlencoded` (≤1MB) | Body echo                                          |
| POST   | `/upload`           | `multipart/form-data` (multer, in-memory, ≤5MB per file) | Echoes field names + each file's name+byte length |
| GET    | `/download/:name`   | -                          | Streams a fixture from `public/` with `Content-Disposition: attachment` |
| WS     | `/ws/echo`          | text frames                | Upgrade GET is WAF-inspected; messages echoed with `[srv]` prefix |

Plus the existing benchmark/FTW routes: `/`, `/healthz`, `/search`,
`/img/logo.png`, `/api/users/:id`. A few small fixtures live under
`public/`: `test.txt`, `sample.json`, `pixel.png`.

## Verify the WAF protects each surface

Start the server (`PORT=3001 pnpm -F @coraza/example-express dev`) and
fire each pair below. Benign should return 200 (or 200/echoed for WS),
malicious should return 403 (or block the WS upgrade).

```sh
# JSON
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST -H 'content-type: application/json' \
  --data '{"q":"hello"}' \
  http://localhost:3001/echo
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST -H 'content-type: application/json' \
  --data "{\"q\":\"' OR 1=1--\"}" \
  http://localhost:3001/echo

# urlencoded
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST --data 'q=hello' \
  http://localhost:3001/form
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST --data 'q=%27+OR+1%3D1--' \
  http://localhost:3001/form

# multipart
echo "hello" > /tmp/bn.txt
curl -s -o /dev/null -w '%{http_code}\n' \
  -F file=@/tmp/bn.txt http://localhost:3001/upload
# CRS at PL1 inspects multipart ARGS (field values) but does NOT
# pattern-match the FILES_NAMES (filenames) against the XSS/SQLi
# detection rules — those rules target ARGS|XSS_TARGETS, not file
# headers. To trigger a block via the multipart path, put the
# attack pattern in a field value:
curl -s -o /dev/null -w '%{http_code}\n' \
  -F "q=' OR 1=1--" -F "file=@/tmp/bn.txt" \
  http://localhost:3001/upload

# download
curl -s -o /dev/null -w '%{http_code}\n' \
  http://localhost:3001/download/test.txt
curl -s -o /dev/null -w '%{http_code}\n' \
  --path-as-is http://localhost:3001/download/../../etc/passwd

# websocket — install wscat first: `npm i -g wscat`
wscat -c ws://localhost:3001/ws/echo
wscat -c "ws://localhost:3001/ws/echo?q=' OR 1=1--"
```

Use `--path-as-is` on curl so it doesn't normalize `..` segments out of
the URL before they reach the wire — the WAF needs to see the literal
traversal pattern. Same caveat applies to any HTTP client: Node's
`fetch` and the `URL` constructor both normalize, so for Node-based
proofs use `http.request({ path: '/download/../../etc/passwd' })`.

## CRS tuning applied for the demo

The example disables three CRS rules so the benign-vs-malicious split
is visible at the default paranoia level:

- `920420` — fires on every request because `crs-setup.conf.example`
  ships rule 900220 commented out, leaving `tx.allowed_request_content_type`
  empty.
- `920350` — fires whenever the Host header is a numeric IP, which is
  unavoidable on `127.0.0.1` / `localhost`.
- `922110` — fires on Coraza's internally-rebuilt multipart
  Content-Type even when the wire-format Content-Type is well-formed.

Without these tweaks every POST stacks to the 949110 anomaly threshold
of 5 before any actual attack pattern is evaluated. Production
deployments behind a real proxy with a public hostname won't hit any
of these false positives.

## End-to-end harness

`scripts/proof.mjs` automates all of the above against an ephemeral
server. It honours `PORT` and `MODE` env vars and prints one
`<scenario> <status>` line per assertion plus a summary at the end:

```sh
PORT=3041 node -e 'process.env.REPO=process.cwd(); import("./examples/express-app/scripts/proof.mjs")'
```

## WebSocket upgrade inspection

The WebSocket upgrade is intercepted at the `http.Server` `upgrade`
event (Express's middleware chain doesn't run on `upgrade` — only on
`request`). The handler runs the upgrade GET through Coraza's request
phase and either:

- responds with `HTTP/1.1 403 Forbidden\r\n` + closes the socket if
  CRS interrupts, or
- hands the socket to `ws.WebSocketServer.handleUpgrade()` to complete
  the handshake.

Frame-level inspection (text frames after the upgrade) is intentionally
**not** wired through Coraza here — the WAF's `processRequestBundle`
contract is per-HTTP-request, not per-WebSocket-frame, and exposing it
that way would imply guarantees we can't honour today. Frame contents
are echoed verbatim with a `[srv]` prefix.
