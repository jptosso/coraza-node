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
   * Languages the app DOES NOT serve, to drop from inbound detection.
   * Affects only REQUEST-*-APPLICATION-ATTACK-<LANG>.conf files (e.g. a
   * Node.js app never executes PHP, so `REQUEST-933` is noise). Outbound
   * RESPONSE-*-DATA-LEAKAGES-<LANG>.conf rules are unaffected — use
   * `outboundExclude` for that.
   *
   * Default: ['php', 'java', 'dotnet']. `nodejs`/`dotnet` have no
   * per-language REQUEST file and are accepted but have no file-level
   * effect; they remain here for forward compatibility.
   */
  exclude?: LanguageTag[]
  /**
   * Languages to drop from OUTBOUND detection (RESPONSE-*-DATA-LEAKAGES-*).
   * Default: [] — keep all response-side language packs, because a Node
   * service typically proxies responses from heterogeneous backends (Java
   * microservices, PHP legacy, IIS shares) and still wants to catch stack
   * traces / data leaks bubbling through. Set this only when you know the
   * upstream is homogeneous and want to trim outbound work.
   */
  outboundExclude?: LanguageTag[]
  /** Anomaly score thresholds (inbound, outbound). Defaults: 5, 4. */
  inboundAnomalyThreshold?: number
  outboundAnomalyThreshold?: number
  /** Block at thresholds (default true); otherwise anomaly mode only. */
  anomalyBlock?: boolean
  /** Drop entire CRS rule categories by ID range. See `CrsCategory`. */
  excludeCategories?: readonly CrsCategory[]
  /** Additional custom SecLang directives appended after CRS. */
  extra?: string
}

const DEFAULT_EXCLUDE: LanguageTag[] = ['php', 'java', 'dotnet']

// CRS 4.25.0 rule files shipped by `coraza-coreruleset` under @owasp_crs.
// Order matters: CRS evaluates phase 1 → 2 → 3 → 4 → 5, and the rules rely
// on initialization + common exceptions firing first. We emit in CRS's
// documented numeric order.
const CRS_FILES = [
  'REQUEST-901-INITIALIZATION.conf',
  'REQUEST-905-COMMON-EXCEPTIONS.conf',
  'REQUEST-911-METHOD-ENFORCEMENT.conf',
  'REQUEST-913-SCANNER-DETECTION.conf',
  'REQUEST-920-PROTOCOL-ENFORCEMENT.conf',
  'REQUEST-921-PROTOCOL-ATTACK.conf',
  'REQUEST-922-MULTIPART-ATTACK.conf',
  'REQUEST-930-APPLICATION-ATTACK-LFI.conf',
  'REQUEST-931-APPLICATION-ATTACK-RFI.conf',
  'REQUEST-932-APPLICATION-ATTACK-RCE.conf',
  'REQUEST-933-APPLICATION-ATTACK-PHP.conf',
  'REQUEST-934-APPLICATION-ATTACK-GENERIC.conf',
  'REQUEST-941-APPLICATION-ATTACK-XSS.conf',
  'REQUEST-942-APPLICATION-ATTACK-SQLI.conf',
  'REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf',
  'REQUEST-944-APPLICATION-ATTACK-JAVA.conf',
  'REQUEST-949-BLOCKING-EVALUATION.conf',
  'RESPONSE-950-DATA-LEAKAGES.conf',
  'RESPONSE-951-DATA-LEAKAGES-SQL.conf',
  'RESPONSE-952-DATA-LEAKAGES-JAVA.conf',
  'RESPONSE-953-DATA-LEAKAGES-PHP.conf',
  'RESPONSE-954-DATA-LEAKAGES-IIS.conf',
  'RESPONSE-955-WEB-SHELLS.conf',
  'RESPONSE-959-BLOCKING-EVALUATION.conf',
  'RESPONSE-980-CORRELATION.conf',
] as const

// Per-language file map. Entries only exist for languages that actually have
// a dedicated per-language file in CRS 4.25.0. `nodejs`/`dotnet` don't — they
// live inside the GENERIC pack — so excluding them is a no-op at file level.
const REQUEST_LANG_FILES: Partial<Record<LanguageTag, string>> = {
  php: 'REQUEST-933-APPLICATION-ATTACK-PHP.conf',
  java: 'REQUEST-944-APPLICATION-ATTACK-JAVA.conf',
}
const RESPONSE_LANG_FILES: Partial<Record<LanguageTag, string>> = {
  java: 'RESPONSE-952-DATA-LEAKAGES-JAVA.conf',
  php: 'RESPONSE-953-DATA-LEAKAGES-PHP.conf',
  iis: 'RESPONSE-954-DATA-LEAKAGES-IIS.conf',
}

function filesToSkip(
  exclude: LanguageTag[],
  outboundExclude: LanguageTag[],
): Set<string> {
  const skip = new Set<string>()
  for (const lang of exclude) {
    const f = REQUEST_LANG_FILES[lang]
    if (f) skip.add(f)
  }
  for (const lang of outboundExclude) {
    const f = RESPONSE_LANG_FILES[lang]
    if (f) skip.add(f)
  }
  return skip
}

/**
 * Build SecLang configuration that activates CRS with sensible defaults for
 * a Node.js application. Pass the return value as `rules` to `createWAF`.
 */
export function recommended(options: CrsOptions = {}): string {
  const paranoia = options.paranoia ?? 1
  const exclude = options.exclude ?? DEFAULT_EXCLUDE
  const outboundExclude = options.outboundExclude ?? []
  const inbound = options.inboundAnomalyThreshold ?? 5
  const outbound = options.outboundAnomalyThreshold ?? 4
  const anomalyBlock = options.anomalyBlock ?? true
  const extra = options.extra ?? ''

  const parts: string[] = []
  parts.push('Include @coraza.conf-recommended')
  // coraza-coreruleset ships this file with the `.example` suffix (mirrors
  // upstream CRS distribution). Users override with SecAction below rather
  // than editing the file.
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

  // Explicit per-file Include list is cheaper than `Include @owasp_crs/*.conf`
  // followed by `SecRuleRemoveByTag`: the parser never loads rules we'd then
  // throw away.
  const skip = filesToSkip(exclude, outboundExclude)
  for (const file of CRS_FILES) {
    if (!skip.has(file)) parts.push(`Include @owasp_crs/${file}`)
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
