import assert from 'node:assert/strict';
import test from 'node:test';
import {
  computeGroupSpectrum,
  computeRelativeMeterScale,
  mapOnsetMarkersToX,
  resolveTransitExit,
} from '../src/components/telemetry-math.ts';
import {
  extractDomainFromRule,
  filterPaletteItems,
  findProbeableGroup,
  isHostnameQuery,
  normalizeHostQuery,
  previewRuleMatch,
  type PaletteCommand,
} from '../src/components/palette-logic.ts';
import { EN, type I18nKey } from '../src/i18n-en.ts';
import { ZH } from '../src/i18n-zh.ts';
import { countLogSeverities, matchesLogFilters } from '../src/pages/log-helpers.ts';
import { AppStore } from '../src/store.ts';
import {
  THEME_META_COLORS,
  migrateThemePreference,
  resolveTheme,
  themeColorScheme,
} from '../src/theme.ts';
import type { OutboundGroup, RuleItem } from '../src/types.ts';

test('theme migration, resolution, color-scheme polarity, and theme-color mapping', () => {
  assert.equal(migrateThemePreference('dark'), 'obsidian');
  assert.equal(migrateThemePreference('light'), 'daylight');
  assert.equal(migrateThemePreference('amber'), 'amber');
  assert.equal(migrateThemePreference('obsidian'), 'obsidian');
  assert.equal(migrateThemePreference('daylight'), 'daylight');
  assert.equal(migrateThemePreference('system'), 'system');
  assert.equal(migrateThemePreference('unknown'), 'system');
  assert.equal(migrateThemePreference(null), 'system');

  assert.equal(resolveTheme('system', false), 'obsidian');
  assert.equal(resolveTheme('system', true), 'daylight');
  assert.equal(resolveTheme('amber', true), 'amber');
  assert.equal(resolveTheme('daylight', false), 'daylight');

  // CSS color-scheme MUST ONLY be 'light' or 'dark' — never 'obsidian' or 'amber'.
  assert.equal(themeColorScheme('obsidian'), 'dark');
  assert.equal(themeColorScheme('amber'), 'dark');
  assert.equal(themeColorScheme('daylight'), 'light');

  assert.equal(THEME_META_COLORS.obsidian, '#111318');
  assert.equal(THEME_META_COLORS.daylight, '#f6f5f2');
  assert.equal(THEME_META_COLORS.amber, '#131210');
});

test('AppStore applies resolved theme, CSS color-scheme, and meta theme-color to DOM', () => {
  const origDoc = globalThis.document;
  const metaEl = { name: 'theme-color', content: '' };
  const fakeDoc = {
    documentElement: { dataset: {} as Record<string, string>, style: { colorScheme: '' } },
    head: { appendChild: () => {} },
    querySelector: (sel: string) => (sel === 'meta[name="theme-color"]' ? metaEl : null),
    createElement: () => metaEl,
  };
  globalThis.document = fakeDoc as unknown as Document;

  try {
    const store = new AppStore();
    store.setTheme('amber');
    assert.equal(store.resolvedTheme, 'amber');
    assert.equal(fakeDoc.documentElement.dataset.theme, 'amber');
    assert.equal(fakeDoc.documentElement.style.colorScheme, 'dark');
    assert.equal(metaEl.content, '#131210');

    store.setTheme('daylight');
    assert.equal(fakeDoc.documentElement.dataset.theme, 'daylight');
    assert.equal(fakeDoc.documentElement.style.colorScheme, 'light');
    assert.equal(metaEl.content, '#f6f5f2');

    store.setTheme('obsidian');
    assert.equal(fakeDoc.documentElement.dataset.theme, 'obsidian');
    assert.equal(fakeDoc.documentElement.style.colorScheme, 'dark');
    assert.equal(metaEl.content, '#111318');
  } finally {
    globalThis.document = origDoc;
  }
});

test('computeGroupSpectrum computes 5-tier counts, P50 median, and relative meter scaling', () => {
  const stats = computeGroupSpectrum([
    { name: 'hk-1', state: 'up', latency_ms: 40 },
    { name: 'jp-1', state: 'up', latency_ms: 120 },
    { name: 'sg-1', state: 'up', latency_ms: 210 },
    { name: 'us-1', state: 'up', latency_ms: 420 },
    { name: 'down-1', state: 'down' },
    { name: 'brk-1', state: 'up', latency_ms: 50, breaker_open: true },
    { name: 'new-1', state: 'unknown' },
  ]);

  assert.equal(stats.total, 7);
  assert.equal(stats.probed, 4);
  assert.equal(stats.p50, 165); // avg(120, 210)
  assert.equal(stats.maxHealthy, 420);
  assert.deepEqual(stats.counts, { fast: 1, good: 1, mid: 1, slow: 1, down: 2, unprobed: 1 });

  assert.equal(computeRelativeMeterScale(420, 420, true), 1);
  assert.equal(computeRelativeMeterScale(210, 420, true), 0.5);
  assert.equal(computeRelativeMeterScale(10, 420, true), 0.06); // clamped floor
  assert.equal(computeRelativeMeterScale(null, 420, true), 0);
  assert.equal(computeRelativeMeterScale(50, 420, false), 0);
});

test('AppStore onset markers record, cap at 12, prune against history, and map to SVG X', () => {
  const store = new AppStore();
  store.history = [
    { up: 100, down: 200, ts: 1000 },
    { up: 200, down: 400, ts: 2000 },
    { up: 300, down: 600, ts: 3000 },
  ];

  store.recordOnset('HK-01', 'node', 1500);
  store.recordOnset('Rule', 'mode', 2500);
  store.recordOnset('Stale', 'reload', 500); // older than history[0].ts -> pruned immediately
  assert.equal(store.onsetMarkers.length, 2);

  const mapped = mapOnsetMarkersToX(store.onsetMarkers, store.history, 400);
  assert.equal(mapped.length, 2);
  assert.equal(mapped[0].x, 100);
  assert.equal(mapped[1].x, 300);

  for (let i = 0; i < 20; i++) {
    store.recordOnset(`node-${i}`, 'node', 2000 + i * 10);
  }
  assert.equal(store.onsetMarkers.length, 12);

  // Advance history past all earlier markers and prune
  store.history = [
    { up: 100, down: 200, ts: 5000 },
    { up: 200, down: 400, ts: 6000 },
  ];
  store.pruneOnsets();
  assert.equal(store.onsetMarkers.length, 0);
});

test('palette-logic normalizes hostnames, previews ordered rules, and filters commands/nodes', () => {
  assert.equal(normalizeHostQuery('https://Api.Example.COM:443/v1'), 'api.example.com');
  assert.equal(normalizeHostQuery('github.com:443'), 'github.com');
  assert.equal(isHostnameQuery('example.com'), true);
  assert.equal(isHostnameQuery('> reload'), false);
  assert.equal(isHostnameQuery('hk-01'), false);

  const rules: RuleItem[] = [
    { index: 1, type: 'domain', action: 'reject', target: 'block', summary: 'ads.example.com' },
    { index: 2, type: 'rule_set', action: 'route', target: 'direct', summary: 'geosite-cn' },
    { index: 3, type: 'domain_suffix', action: 'route', target: 'proxy', summary: '.github.com' },
    { index: 4, type: 'domain_keyword', action: 'route', target: 'media', summary: 'stream' },
    { index: 5, type: 'final', action: 'route', target: 'fallback', summary: '' },
  ];

  const m1 = previewRuleMatch('ads.example.com', rules, 'rule');
  assert.equal(m1.action, 'reject');
  assert.equal(m1.opaqueHint, false);

  const m2 = previewRuleMatch('api.github.com', rules, 'rule');
  assert.equal(m2.target, 'proxy');
  assert.equal(m2.opaqueHint, true); // preceded by rule_set

  const m3 = previewRuleMatch('any.example.org', rules, 'direct');
  assert.equal(m3.target, 'direct');

  assert.equal(extractDomainFromRule(rules[0]), 'ads.example.com');
  assert.equal(extractDomainFromRule(rules[2]), 'github.com');

  const groups: OutboundGroup[] = [
    {
      name: 'Auto',
      mode: 'url-test',
      selected: 'HK-01',
      override: false,
      members: [
        { name: 'HK-01', state: 'up', latency_ms: 35 },
        { name: 'JP-Tokyo', state: 'up', latency_ms: 72 },
      ],
    },
  ];
  const cmds: PaletteCommand[] = [
    { id: 'mode:rule', label: 'Mode: Rule', keywords: 'rule', pinned: true },
    { id: 'action:reload', label: 'Reload Configuration', keywords: 'reload', pinned: true },
  ];

  const cmdOnly = filterPaletteItems('> rel', groups, cmds);
  assert.equal(cmdOnly.length, 1);
  assert.equal(cmdOnly[0].kind, 'command');

  const nodeMatch = filterPaletteItems('tokyo', groups, cmds);
  assert.equal(nodeMatch.length, 1);
  assert.equal(nodeMatch[0].kind, 'node');
});

test('log helpers filter entries and compute severity counts cleanly', () => {
  const entries = [
    { seq: 1, timestamp_ns: 1, level: 'info', domain: 'route', event: 1, session: 1, message: 'matched' },
    { seq: 2, timestamp_ns: 2, level: 'warn', domain: 'dns', event: 2, session: 1, message: 'retry' },
    { seq: 3, timestamp_ns: 3, level: 'error', domain: 'net', event: 3, session: 1, message: 'reset' },
  ];
  assert.deepEqual(countLogSeverities(entries), { info: 1, warn: 1, error: 1 });
  assert.equal(matchesLogFilters(entries[0], 'warn', 'all', ''), false);
  assert.equal(matchesLogFilters(entries[1], 'warn', 'dns', 'ret'), true);
});

test('resolveTransitExit handles rule, direct, and global modes accurately and findProbeableGroup skips selectors', () => {
  const groups: OutboundGroup[] = [
    {
      name: 'Manual',
      mode: 'selector',
      selected: 'HK-01',
      override: false,
      members: [
        { name: 'HK-01', state: 'up', latency_ms: 42 },
        { name: 'US-02', state: 'up', latency_ms: 190 },
      ],
    },
    {
      name: 'AutoBest',
      mode: 'url-test',
      selected: 'JP-01',
      override: false,
      members: [{ name: 'JP-01', state: 'up', latency_ms: 68 }],
    },
  ];
  const labels = { direct: 'Direct', global: 'Global', noGroup: 'None', fallbackSub: 'Outbounds' };

  const directExit = resolveTransitExit({ mode: 'direct', outbound: '' }, groups, labels);
  assert.equal(directExit.label, 'Direct');
  assert.equal(directExit.subtitle, 'Direct');
  assert.equal(directExit.rttMs, undefined);

  const globalMember = resolveTransitExit({ mode: 'global', outbound: 'US-02' }, groups, labels);
  assert.equal(globalMember.label, 'US-02');
  assert.equal(globalMember.subtitle, 'Manual');
  assert.equal(globalMember.rttMs, 190);
  assert.equal(globalMember.tier, 'mid');

  const globalGroup = resolveTransitExit({ mode: 'global', outbound: 'AutoBest' }, groups, labels);
  assert.equal(globalGroup.label, 'JP-01');
  assert.equal(globalGroup.subtitle, 'AutoBest');
  assert.equal(globalGroup.rttMs, 68);

  const ruleExit = resolveTransitExit({ mode: 'rule', outbound: '' }, groups, labels);
  assert.equal(ruleExit.label, 'HK-01');
  assert.equal(ruleExit.rttMs, 42);

  assert.equal(findProbeableGroup(groups)?.name, 'AutoBest');
  assert.equal(findProbeableGroup([groups[0]]), null);
});

test('EN and ZH i18n dictionaries maintain 100% key parity and clean user-facing copy', () => {
  const enKeys = Object.keys(EN) as I18nKey[];
  const zhKeys = Object.keys(ZH) as I18nKey[];
  assert.deepEqual([...enKeys].sort(), [...zhKeys].sort());
  const forbidden = /\.\.\.|\/v1\/|\b(?:kdl|sqlite|wal)\b/i;
  for (const k of enKeys) {
    assert.ok(EN[k].length > 0, `empty EN key ${k}`);
    assert.ok(ZH[k].length > 0, `empty ZH key ${k}`);
    assert.equal(forbidden.test(EN[k]), false, `forbidden text in EN.${k}: ${EN[k]}`);
    assert.equal(forbidden.test(ZH[k]), false, `forbidden text in ZH.${k}: ${ZH[k]}`);
  }
});
