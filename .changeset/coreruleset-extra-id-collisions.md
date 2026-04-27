---
'@coraza/coreruleset': patch
---

`recommended({ extra })` (and the `balanced`/`strict`/`permissive` presets
that delegate to it) now validates user-supplied SecLang for rule-id
collisions instead of silently accepting them. Fixes #30.

- Direct collisions with the ids `recommended()` itself emits
  (`900000`–`900003`, depending on options) now **throw** at config-build
  time with a message that names the colliding id, what the preset uses
  it for, and which option to reach for instead. Example:
  `rule id 900001 in `extra` collides with the recommended() preset
  (it sets tx.inbound_anomaly_score_threshold). Pick an id >= 1,000,000
  or override the threshold via the `inboundAnomalyScoreThreshold` option.`
- Ids inside the CRS-reserved range `900000`–`999999` that are *not*
  emitted by recommended() are still allowed (some advanced users
  override CRS rules deliberately) but trigger a `console.warn` at
  config time, since the chosen id may collide on a future CRS upgrade.
- Ids `>= 1,000,000` (the documented user range) and `extra: ''` /
  `extra: undefined` continue to pass silently.

This is a runtime-behavior change — input that previously parsed (but
silently produced an invalid SecLang blob with two `SecAction`s sharing
an id) now throws. The previous behavior was a bug: depending on the
engine's directive ordering, the user's override was either dead code or
a load-time error. Surfacing the conflict at config time is strictly
safer.
