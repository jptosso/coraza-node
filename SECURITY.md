# Security policy

This project is an experimental community effort, not an official Coraza /
OWASP release. That said — it's a WAF, so we take reports seriously when
they represent a concrete risk.

## How to report

**Use the GitHub Security Advisories tab.** Open a private advisory at
<https://github.com/coraza-incubator/coraza-node/security/advisories/new>. That's
the only supported channel. Please do not:

- Open a public issue for a vulnerability before an advisory is resolved.
- Email the maintainer directly. Advisories give us a durable record and
  let collaborators read along.
- Post proof-of-concept payloads or exploit chains on social media or in
  blog posts before a fix ships.

A useful report includes:

- The affected package(s) and version(s) — `@coraza/core@0.1.0-…`, adapter,
  example app involved.
- A **working** reproduction: the exact request, the expected verdict,
  the observed verdict. Include the CRS rule ID that should have fired,
  or the rule that fired when it shouldn't have.
- The threat model it breaks. Bypass of a specific CRS family? Adapter
  side-channel? RCE? Just "theoretically possible" is not enough — see
  below.

We reply within 7 days. If your advisory is accepted, we'll cut a fix on
develop, merge to main, publish the patch version to npm, and credit you
in the advisory (opt-out available).

## What we accept

- **Working exploits**, with a PoC, against the latest `main`. Detection
  bypass, RCE, adapter crash that masks the WAF, unauthenticated DoS
  that brings the process down — anything a real attacker could use.
- **Regressions in default behaviour** — something the WAF used to block
  and quietly stopped blocking. Pin a commit range if you can.
- **Configuration footguns** where the documented safe default doesn't
  actually fail closed.

## What we do not accept

- **Theoretical vulnerabilities without a working exploit.** "This
  *could* be a bypass if the attacker controls X, Y, and Z" is not a
  report; it's a research note. Open a regular issue instead.
- **Upstream Coraza engine bugs.** The WASM we ship embeds
  [`corazawaf/coraza`](https://github.com/corazawaf/coraza). If the bug
  reproduces against coraza-proxy-wasm or coraza-caddy, it belongs
  upstream: <https://github.com/corazawaf/coraza/security/advisories/new>.
- **Upstream CoreRuleSet false-negatives / false-positives.** Report
  those at <https://github.com/coreruleset/coreruleset/security/advisories/new>
  (or in the CRS issue tracker for non-security behaviour).
- **TinyGo or Node runtime vulnerabilities** that happen to surface
  through the WASM loader. Report to the appropriate upstream.
- **Denial of service via large but well-formed bodies.** Our adapters
  clip oversized fields before handing them to the WAF (see
  `docs/threat-model.md`); if you have a DoS that bypasses those clips,
  that *is* in scope.
- **Issues that only reproduce with non-default configuration** chosen
  specifically to weaken the WAF (e.g. `onWAFError: 'allow'` combined
  with a known-bad rule set). The docs already mark those knobs as
  availability-over-security.

We may downgrade a report to a regular issue if it's reproducible but
not a security boundary break. That's not a slight on the reporter —
it just keeps the advisory feed usable.

## Scope

In scope:

- Every `@coraza/*` package published from this repo.
- The compiled `coraza.wasm` binary shipped inside `@coraza/core`.
- The example apps under `examples/*-app/` when run in their documented
  block-mode configuration.
- CI workflows and release tooling (if a compromise would ship a
  trojaned package to npm).

Out of scope:

- Example apps run in dev / detect mode on a laptop.
- Docs site (<https://coraza-incubator.github.io/coraza-node>).
- The benchmark harnesses under `bench/`.
- Dependencies' own advisories — see upstream.

## Disclosure timeline

- T+0: advisory opened.
- T+7 days: initial triage response.
- T+30 days: fix target for high-severity bypass.
- T+90 days: hard limit before we publish the advisory even without a
  fix if the issue is materially working against users. We'd rather
  ship the mitigation guidance than keep silence.

## Credits

Confirmed reporters are credited in the published advisory and in the
release notes of the patching version, unless they ask to stay anonymous.

## See also

- `docs/threat-model.md` — what the WAF is designed to catch, what it
  isn't, and the known caveats (ReDoS via V8 Irregexp, Unicode
  case-insensitive, UTF-8 encoding).
- `AGENTS.md` — the per-commit security-impact checklist contributors
  are expected to answer.
