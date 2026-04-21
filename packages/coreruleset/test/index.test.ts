import { describe, it, expect } from 'vitest'
import {
  recommended,
  balanced,
  strict,
  permissive,
  excludeByTag,
  excludeCategory,
  paranoia,
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
