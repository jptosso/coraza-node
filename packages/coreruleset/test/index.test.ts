import { describe, it, expect, vi, afterEach } from 'vitest'
import {
  recommended,
  balanced,
  strict,
  permissive,
  excludeByTag,
  excludeCategory,
  paranoia,
  __test,
} from '../src/index.js'

describe('recommended()', () => {
  it('emits CRS setup + sensible defaults', () => {
    const out = recommended()
    expect(out).toContain('Include @coraza.conf-recommended')
    expect(out).toContain('Include @crs-setup.conf.example')
    expect(out).toContain('setvar:tx.blocking_paranoia_level=1')
    expect(out).toContain('setvar:tx.inbound_anomaly_score_threshold=5')
    expect(out).toContain('setvar:tx.outbound_anomaly_score_threshold=4')
  })

  it('emits per-file Includes instead of a glob', () => {
    const out = recommended()
    // Wildcard form would re-introduce the wasteful parse-then-drop path.
    expect(out).not.toContain('Include @owasp_crs/*.conf')
    expect(out).toContain('Include @owasp_crs/REQUEST-901-INITIALIZATION.conf')
    expect(out).toContain('Include @owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf')
    expect(out).toContain('Include @owasp_crs/RESPONSE-980-CORRELATION.conf')
  })

  it('excludes REQUEST-933/944 by default (php/java) and keeps nodejs generic', () => {
    const out = recommended()
    expect(out).not.toContain('REQUEST-933-APPLICATION-ATTACK-PHP.conf')
    expect(out).not.toContain('REQUEST-944-APPLICATION-ATTACK-JAVA.conf')
    expect(out).toContain('REQUEST-934-APPLICATION-ATTACK-GENERIC.conf')
  })

  it('keeps ALL outbound RESPONSE-*-DATA-LEAKAGES-* by default', () => {
    // Rationale: a Node app often proxies responses from heterogeneous
    // backends, so the outbound per-language packs are not dead weight.
    const out = recommended()
    expect(out).toContain('RESPONSE-950-DATA-LEAKAGES.conf')
    expect(out).toContain('RESPONSE-951-DATA-LEAKAGES-SQL.conf')
    expect(out).toContain('RESPONSE-952-DATA-LEAKAGES-JAVA.conf')
    expect(out).toContain('RESPONSE-953-DATA-LEAKAGES-PHP.conf')
    expect(out).toContain('RESPONSE-954-DATA-LEAKAGES-IIS.conf')
    expect(out).toContain('RESPONSE-955-WEB-SHELLS.conf')
  })

  it('exclude: php drops REQUEST-933 but keeps RESPONSE-953', () => {
    const out = recommended({ exclude: ['php'] })
    expect(out).not.toContain('REQUEST-933-APPLICATION-ATTACK-PHP.conf')
    expect(out).toContain('RESPONSE-953-DATA-LEAKAGES-PHP.conf')
  })

  it('exclude: java drops REQUEST-944 but keeps RESPONSE-952', () => {
    const out = recommended({ exclude: ['java'] })
    expect(out).not.toContain('REQUEST-944-APPLICATION-ATTACK-JAVA.conf')
    expect(out).toContain('RESPONSE-952-DATA-LEAKAGES-JAVA.conf')
  })

  it('exclude: iis is a no-op at file level (no REQUEST-level IIS file)', () => {
    // Still keeps the inbound set intact and does not silently drop 954.
    const out = recommended({ exclude: ['iis'] })
    expect(out).toContain('RESPONSE-954-DATA-LEAKAGES-IIS.conf')
  })

  it('exclude: [] keeps inbound language packs in', () => {
    const out = recommended({ exclude: [] })
    expect(out).toContain('REQUEST-933-APPLICATION-ATTACK-PHP.conf')
    expect(out).toContain('REQUEST-944-APPLICATION-ATTACK-JAVA.conf')
  })

  it('outboundExclude: php drops RESPONSE-953 only', () => {
    const out = recommended({ outboundExclude: ['php'] })
    expect(out).not.toContain('RESPONSE-953-DATA-LEAKAGES-PHP.conf')
    expect(out).toContain('RESPONSE-952-DATA-LEAKAGES-JAVA.conf')
    expect(out).toContain('RESPONSE-954-DATA-LEAKAGES-IIS.conf')
    // And it must not also drop the inbound PHP file just because php is
    // in outboundExclude — that would conflate the two axes.
    // (Inbound PHP file is already dropped by DEFAULT_EXCLUDE, so use an
    // explicit override to prove outboundExclude does not affect inbound.)
    const both = recommended({ exclude: [], outboundExclude: ['php'] })
    expect(both).toContain('REQUEST-933-APPLICATION-ATTACK-PHP.conf')
    expect(both).not.toContain('RESPONSE-953-DATA-LEAKAGES-PHP.conf')
  })

  it('outboundExclude: java/iis each drop only their RESPONSE file', () => {
    const out = recommended({ outboundExclude: ['java', 'iis'] })
    expect(out).not.toContain('RESPONSE-952-DATA-LEAKAGES-JAVA.conf')
    expect(out).not.toContain('RESPONSE-954-DATA-LEAKAGES-IIS.conf')
    expect(out).toContain('RESPONSE-953-DATA-LEAKAGES-PHP.conf')
  })

  it('outboundExclude: languages with no RESPONSE file are a no-op', () => {
    const out = recommended({ outboundExclude: ['dotnet', 'nodejs'] })
    // All per-language RESPONSE files intact.
    expect(out).toContain('RESPONSE-952-DATA-LEAKAGES-JAVA.conf')
    expect(out).toContain('RESPONSE-953-DATA-LEAKAGES-PHP.conf')
    expect(out).toContain('RESPONSE-954-DATA-LEAKAGES-IIS.conf')
  })

  it('honors paranoia override', () => {
    expect(recommended({ paranoia: 3 })).toContain('setvar:tx.blocking_paranoia_level=3')
  })

  it('honors anomaly score overrides', () => {
    const out = recommended({ inboundAnomalyThreshold: 8, outboundAnomalyThreshold: 6 })
    expect(out).toContain('setvar:tx.inbound_anomaly_score_threshold=8')
    expect(out).toContain('setvar:tx.outbound_anomaly_score_threshold=6')
  })

  it('disables early blocking when anomalyBlock=false', () => {
    expect(recommended({ anomalyBlock: false })).toContain('setvar:tx.early_blocking=0')
    expect(recommended({ anomalyBlock: true })).not.toContain('setvar:tx.early_blocking=0')
  })

  it('appends extra directives when provided', () => {
    const out = recommended({ extra: 'SecRule REQUEST_URI "@contains /admin" "id:1,deny,status:403"' })
    expect(out).toContain('SecRule REQUEST_URI')
    expect(out.trim().endsWith('status:403"')).toBe(true)
  })

  it('ignores extra if empty/whitespace', () => {
    const out = recommended({ extra: '   ' })
    expect(out).not.toContain('SecRule REQUEST_URI')
  })
})

describe('presets', () => {
  it('balanced is paranoia 1', () => {
    expect(balanced()).toContain('paranoia_level=1')
  })

  it('balanced respects overrides', () => {
    expect(balanced({ paranoia: 4 })).toContain('paranoia_level=4')
  })

  it('strict is paranoia 2 with inbound threshold 3', () => {
    const out = strict()
    expect(out).toContain('paranoia_level=2')
    expect(out).toContain('inbound_anomaly_score_threshold=3')
  })

  it('strict respects overrides', () => {
    expect(strict({ paranoia: 4 })).toContain('paranoia_level=4')
  })

  it('permissive raises thresholds and disables early blocking', () => {
    const out = permissive()
    expect(out).toContain('inbound_anomaly_score_threshold=10')
    expect(out).toContain('outbound_anomaly_score_threshold=8')
    expect(out).toContain('tx.early_blocking=0')
  })

  it('permissive respects overrides', () => {
    expect(permissive({ paranoia: 2 })).toContain('paranoia_level=2')
  })

  it('presets inherit the explicit-Include behavior', () => {
    for (const out of [balanced(), strict(), permissive()]) {
      expect(out).not.toContain('Include @owasp_crs/*.conf')
      expect(out).toContain('Include @owasp_crs/REQUEST-901-INITIALIZATION.conf')
      expect(out).toContain('RESPONSE-953-DATA-LEAKAGES-PHP.conf')
    }
  })
})

describe('low-level helpers', () => {
  it('excludeByTag builds the expected directives', () => {
    expect(excludeByTag(['a', 'b'])).toBe(
      'SecRuleRemoveByTag "a"\nSecRuleRemoveByTag "b"',
    )
  })

  it('excludeByTag handles empty arrays', () => {
    expect(excludeByTag([])).toBe('')
  })

  it('paranoia() builds a SecAction for a specific level', () => {
    expect(paranoia(4)).toContain('paranoia_level=4')
  })

  it('excludeCategory builds SecRuleRemoveById directive for a range', () => {
    expect(excludeCategory('scanner-detection')).toBe('SecRuleRemoveById 910000-913999')
    expect(excludeCategory('dos-protection')).toBe('SecRuleRemoveById 912000-912999')
    expect(excludeCategory('outbound-data-leak')).toBe('SecRuleRemoveById 950000-950999')
  })
})

describe('recommended() — extra id-collision validation (issue #30)', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('throws when extra reuses an id emitted by recommended() (900001)', () => {
    expect(() =>
      recommended({
        extra:
          'SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=10"',
      }),
    ).toThrow(/rule id 900001 in `extra` collides with the recommended\(\) preset/)
  })

  it('error message names the colliding id and the option to use instead', () => {
    let caught: Error | null = null
    try {
      recommended({
        extra:
          'SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=10"',
      })
    } catch (err) {
      caught = err as Error
    }
    expect(caught).not.toBeNull()
    expect(caught!.message).toContain('900001')
    expect(caught!.message).toContain('tx.inbound_anomaly_score_threshold')
    expect(caught!.message).toContain('inboundAnomalyScoreThreshold')
  })

  it('throws on collision with id 900000 (paranoia)', () => {
    expect(() =>
      recommended({
        extra: 'SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=4"',
      }),
    ).toThrow(/rule id 900000/)
  })

  it('throws on collision with 900003 only when it is actually emitted (anomalyBlock=false)', () => {
    // anomalyBlock=true (default): 900003 is NOT emitted, so it should NOT throw —
    // it falls into the "warn" path below.
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect(() =>
      recommended({
        extra: 'SecAction "id:900003,phase:1,nolog,pass,t:none,setvar:tx.early_blocking=0"',
      }),
    ).not.toThrow()
    warn.mockRestore()

    // anomalyBlock=false: 900003 IS emitted, so it must throw.
    expect(() =>
      recommended({
        anomalyBlock: false,
        extra: 'SecAction "id:900003,phase:1,nolog,pass,t:none,setvar:tx.early_blocking=0"',
      }),
    ).toThrow(/rule id 900003/)
  })

  it('warns (does not throw) for ids in 900000-999999 that recommended() does not emit', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect(() =>
      recommended({
        extra:
          'SecAction "id:950000,phase:1,nolog,pass,t:none,setvar:tx.foo=1"',
      }),
    ).not.toThrow()
    expect(warn).toHaveBeenCalledTimes(1)
    expect(warn.mock.calls[0]?.[0]).toContain('950000')
    expect(warn.mock.calls[0]?.[0]).toContain('CRS-reserved')
  })

  it('passes silently for ids >= 1,000,000 (the documented user range)', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect(() =>
      recommended({
        extra: 'SecRule REQUEST_URI "@contains /admin" "id:1000000,deny,status:403"',
      }),
    ).not.toThrow()
    expect(warn).not.toHaveBeenCalled()
  })

  it('extra: "" passes without scanning', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect(() => recommended({ extra: '' })).not.toThrow()
    expect(warn).not.toHaveBeenCalled()
  })

  it('extra: undefined passes without scanning', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect(() => recommended({})).not.toThrow()
    expect(warn).not.toHaveBeenCalled()
  })

  it('id token regex tolerates whitespace and trailing comma', () => {
    expect(__test.extractRuleIds('id : 900001 ,phase:1')).toEqual([900001])
    expect(__test.extractRuleIds('"id:1234,phase:1"')).toEqual([1234])
    expect(__test.extractRuleIds('  id:42 ')).toEqual([42])
  })

  it('id token regex does not mis-parse 9000010 as 900001 (boundary)', () => {
    // Critical: substring matching would falsely trigger a collision on
    // legal id 9000010. The regex must match whole-id only.
    expect(__test.extractRuleIds('SecAction "id:9000010,phase:1"')).toEqual([
      9000010,
    ])
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect(() =>
      recommended({
        extra: 'SecAction "id:9000010,phase:1,nolog,pass,t:none,setvar:tx.x=1"',
      }),
    ).not.toThrow()
    expect(warn).not.toHaveBeenCalled()
  })

  it('does not match `id:` inside an unrelated identifier (e.g. `myid:900001`)', () => {
    // The leading non-ident-char guard means `myid:900001` should not parse
    // as a rule id. (It's not valid SecLang anyway, but the regex must be
    // robust against incidental substrings.)
    expect(__test.extractRuleIds('myid:900001')).toEqual([])
  })

  it('extracts multiple ids and reports the first collision found', () => {
    expect(() =>
      recommended({
        extra:
          'SecRule REQUEST_URI "@contains /a" "id:1000001,deny"\nSecAction "id:900002,phase:1,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=99"',
      }),
    ).toThrow(/rule id 900002/)
  })
})

describe('recommended() with excludeCategories', () => {
  it('emits SecRuleRemoveById for each category', () => {
    const out = recommended({
      excludeCategories: ['scanner-detection', 'dos-protection'],
    })
    expect(out).toContain('SecRuleRemoveById 910000-913999')
    expect(out).toContain('SecRuleRemoveById 912000-912999')
  })

  it('omits the block when no categories specified', () => {
    const out = recommended()
    expect(out).not.toContain('SecRuleRemoveById')
  })

  it('ignores an empty category array', () => {
    const out = recommended({ excludeCategories: [] })
    expect(out).not.toContain('SecRuleRemoveById')
  })
})
