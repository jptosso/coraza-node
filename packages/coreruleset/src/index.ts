// @coraza/coreruleset — thin SecLang config builder for the OWASP CoreRuleSet.
//
// The CRS rule files are already embedded inside the @coraza/core WASM (via
// the `coraza-coreruleset` Go module). This package's job is to emit the
// SecLang `Include` directives + tuning knobs that tell Coraza which rules
// to load at runtime. No file I/O happens here.

export type Paranoia = 1 | 2 | 3 | 4

export type LanguageTag = 'php' | 'java' | 'dotnet' | 'nodejs' | 'iis'

/**
 * High-level CRS rule categories. Excluding a category drops the rule IDs
 * in that range via `SecRuleRemoveById`. Ranges follow upstream CRS.
 *
 * Use case guidance:
 *   - `scanner-detection`: noisy for internal APIs. Drop if you don't care
 *     about fingerprinting scanner clients (rules 910/913 series).
 *   - `dos-protection`: request-rate rules (912). Coraza's implementation
 *     isn't a great DOS defense — typically better done upstream.
 *   - `session-fixation`: rules 943 series. Drop for stateless APIs.
 *   - `outbound-data-leak`: 950–953 series, response-phase. Drop if you
 *     don't enable `inspectResponse`.
 *   - The attack categories (`xss`, `sqli`, `lfi`, `rfi`, `rce`) are the
 *     core protections — excluding them defeats most of CRS's value.
 */
export type CrsCategory =
  | 'scanner-detection'
  | 'method-enforcement'
  | 'dos-protection'
  | 'protocol-attacks'
  | 'protocol-enforcement'
  | 'lfi'
  | 'rfi'
  | 'rce'
  | 'php'
  | 'nodejs'
  | 'xss'
  | 'sqli'
  | 'session-fixation'
  | 'java'
  | 'blocking-eval'
  | 'outbound-data-leak'
  | 'outbound-sql-error-leak'
  | 'outbound-java-error-leak'
  | 'outbound-php-error-leak'
  | 'outbound-info-leak'

const CATEGORY_RANGES: Record<CrsCategory, [number, number]> = {
  'scanner-detection': [910000, 913999],
  'method-enforcement': [911000, 911999],
  'dos-protection': [912000, 912999],
  'protocol-attacks': [920000, 921999],
  'protocol-enforcement': [920000, 920999],
  lfi: [930000, 930999],
  rfi: [931000, 931999],
  rce: [932000, 932999],
  php: [933000, 933999],
  nodejs: [934000, 934999],
  xss: [941000, 941999],
  sqli: [942000, 942999],
  'session-fixation': [943000, 943999],
  java: [944000, 944999],
  'blocking-eval': [949000, 949999],
  'outbound-data-leak': [950000, 950999],
  'outbound-sql-error-leak': [951000, 951999],
  'outbound-java-error-leak': [952000, 952999],
  'outbound-php-error-leak': [953000, 953999],
  'outbound-info-leak': [954000, 954999],
}

export interface CrsOptions {
  /** Paranoia level 1 (low FP) → 4 (strict). Default: 1. */
  paranoia?: Paranoia
  /**
   * Language tags to EXCLUDE. Default: ['php', 'java', 'dotnet'] — keeps
   * nodejs + generic application-agnostic rules active.
   */
  exclude?: LanguageTag[]
  /** Anomaly score thresholds (inbound, outbound). Defaults: 5, 4. */
  inboundAnomalyThreshold?: number
  outboundAnomalyThreshold?: number
  /** Block at thresholds (default true); otherwise anomaly mode only. */
  anomalyBlock?: boolean
  /**
   * Drop entire CRS rule categories by ID range. Useful when you don't use
   * response-side rules, don't serve PHP/Java, or have upstream DOS defense.
   * See `CrsCategory` for available categories.
   */
  excludeCategories?: readonly CrsCategory[]
  /** Additional custom SecLang directives appended after CRS. */
  extra?: string
}

const DEFAULT_EXCLUDE: LanguageTag[] = ['php', 'java', 'dotnet']

/**
 * Build SecLang configuration that activates CRS with sensible defaults for
 * a Node.js application. Pass the return value as `rules` to `createWAF`.
 *
 *   const rules = recommended({ paranoia: 2 })
 *   const waf = await createWAF({ rules })
 */
export function recommended(options: CrsOptions = {}): string {
  const paranoia = options.paranoia ?? 1
  const exclude = options.exclude ?? DEFAULT_EXCLUDE
  const inbound = options.inboundAnomalyThreshold ?? 5
  const outbound = options.outboundAnomalyThreshold ?? 4
  const anomalyBlock = options.anomalyBlock ?? true
  const extra = options.extra ?? ''

  const parts: string[] = []
  parts.push('Include @coraza.conf-recommended')
  // The coraza-coreruleset Go package ships this file with the `.example`
  // suffix (mirrors upstream CRS distribution). Users override with SecAction
  // directives below rather than editing the file.
  parts.push('Include @crs-setup.conf.example')
  parts.push(`SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=${paranoia}"`)
  parts.push(
    `SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=${inbound}"`,
  )
  parts.push(
    `SecAction "id:900002,phase:1,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=${outbound}"`,
  )
  if (!anomalyBlock) {
    parts.push('SecAction "id:900003,phase:1,nolog,pass,t:none,setvar:tx.early_blocking=0"')
  }
  parts.push('Include @owasp_crs/*.conf')
  for (const tag of exclude) {
    parts.push(`SecRuleRemoveByTag "language-${tag}"`)
  }
  if (options.excludeCategories?.length) {
    for (const cat of options.excludeCategories) {
      const [lo, hi] = CATEGORY_RANGES[cat]
      parts.push(`SecRuleRemoveById ${lo}-${hi}`)
    }
  }
  if (extra.trim().length > 0) {
    parts.push(extra)
  }
  return parts.join('\n') + '\n'
}

/** Return a SecRuleRemoveById directive for a single category. Low-level. */
export function excludeCategory(cat: CrsCategory): string {
  const [lo, hi] = CATEGORY_RANGES[cat]
  return `SecRuleRemoveById ${lo}-${hi}`
}

/** Balanced profile: paranoia 1, anomaly threshold 5/4, blocks on threshold. */
export function balanced(overrides: CrsOptions = {}): string {
  return recommended({ paranoia: 1, ...overrides })
}

/** Strict profile: paranoia 2, stricter inbound threshold. */
export function strict(overrides: CrsOptions = {}): string {
  return recommended({ paranoia: 2, inboundAnomalyThreshold: 3, ...overrides })
}

/** Permissive profile: paranoia 1, looser thresholds, non-blocking on anomaly. */
export function permissive(overrides: CrsOptions = {}): string {
  return recommended({
    paranoia: 1,
    inboundAnomalyThreshold: 10,
    outboundAnomalyThreshold: 8,
    anomalyBlock: false,
    ...overrides,
  })
}

/** Lower-level helper: raw `SecRuleRemoveByTag` lines for a set of tags. */
export function excludeByTag(tags: string[]): string {
  return tags.map((t) => `SecRuleRemoveByTag "${t}"`).join('\n')
}

/** Lower-level helper: paranoia-setting directive for a specific level. */
export function paranoia(level: Paranoia): string {
  return `SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=${level}"`
}
