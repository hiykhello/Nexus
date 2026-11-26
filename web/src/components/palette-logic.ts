import type { OutboundGroup, OutboundMember, RuleItem } from '../api.ts';
import type { I18nKey } from '../i18n.ts';

export function findProbeableGroup(groups: OutboundGroup[]): OutboundGroup | null {
  return groups.find((g) => g.mode !== 'select' && g.mode !== 'selector') ?? null;
}

export function buildPaletteCommands(
  tr: (key: I18nKey, params?: Record<string, string | number>) => string,
): PaletteCommand[] {
  return [
    { id: 'mode:rule', label: tr('palette.cmd.rule'), keywords: 'rule mode', hint: 'mode', pinned: true },
    { id: 'mode:global', label: tr('palette.cmd.global'), keywords: 'global mode', hint: 'mode', pinned: true },
    { id: 'mode:direct', label: tr('palette.cmd.direct'), keywords: 'direct mode', hint: 'mode', pinned: true },
    { id: 'action:probe', label: tr('palette.cmd.probe'), keywords: 'probe latency test', hint: 'probe', pinned: true },
    { id: 'action:flush-fakeip', label: tr('palette.cmd.flushFakeip'), keywords: 'flush fakeip cache', pinned: true },
    { id: 'action:flush-dns', label: tr('palette.cmd.flushDns'), keywords: 'flush clear dns cache' },
    { id: 'action:reload', label: tr('palette.cmd.reload'), keywords: 'reload config', pinned: true },
    { id: 'theme:obsidian', label: tr('palette.cmd.theme', { name: tr('theme.obsidian') }), keywords: 'theme dark obsidian' },
    { id: 'theme:daylight', label: tr('palette.cmd.theme', { name: tr('theme.daylight') }), keywords: 'theme light paper daylight' },
    { id: 'theme:amber', label: tr('palette.cmd.theme', { name: tr('theme.amber') }), keywords: 'theme amber studio' },
    { id: 'theme:system', label: tr('palette.cmd.theme', { name: tr('theme.system') }), keywords: 'theme auto system' },
    { id: 'nav:/', label: tr('palette.cmd.nav', { page: tr('nav.overview') }), keywords: 'nav overview 1' },
    { id: 'nav:/outbounds', label: tr('palette.cmd.nav', { page: tr('nav.outbounds') }), keywords: 'nav outbounds proxies 2' },
    { id: 'nav:/connections', label: tr('palette.cmd.nav', { page: tr('nav.connections') }), keywords: 'nav connections 3' },
    { id: 'nav:/services', label: tr('palette.cmd.nav', { page: tr('nav.rules') }), keywords: 'nav rules dns 4' },
    { id: 'nav:/logs', label: tr('palette.cmd.nav', { page: tr('nav.logs') }), keywords: 'nav logs 5' },
    { id: 'nav:/diagnostics', label: tr('palette.cmd.nav', { page: tr('nav.diagnostics') }), keywords: 'nav diagnostics auth 6' },
  ];
}

const HOST_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i;

export interface PaletteCommand {
  id: string;
  label: string;
  keywords: string;
  hint?: string;
  pinned?: boolean;
}

export type PaletteItem =
  | { kind: 'command'; id: string; command: PaletteCommand }
  | { kind: 'node'; id: string; group: string; member: OutboundMember; active: boolean };

export interface RulePreviewResult {
  ruleIndex: number | null;
  ruleType: string;
  action: string;
  target: string;
  summary: string;
  opaqueHint: boolean;
}

export function normalizeHostQuery(raw: string): string {
  let s = raw.trim();
  if (!s || s.startsWith('>') || /\s/.test(s)) return '';
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  s = s.split('/')[0] ?? '';
  if (s.startsWith('[')) return '';
  const colonIdx = s.lastIndexOf(':');
  if (colonIdx > 0 && /^\d+$/.test(s.slice(colonIdx + 1))) {
    s = s.slice(0, colonIdx);
  }
  s = s.replace(/\.$/, '').toLowerCase();
  return HOST_RE.test(s) ? s : '';
}

export function isHostnameQuery(raw: string): boolean {
  return normalizeHostQuery(raw).length > 0;
}

function splitMatchers(summary: string): string[] {
  return summary
    .split(/[,\s|]+/)
    .map((tok) => tok.replace(/^[^=]*=/, '').trim().toLowerCase())
    .filter(Boolean);
}

export function extractDomainFromRule(rule: RuleItem): string {
  const type = rule.type.toLowerCase();
  if (type === 'domain' || type === 'domain_suffix' || type === 'domain-suffix' || type === 'host') {
    for (const tok of splitMatchers(rule.summary)) {
      const clean = tok.replace(/^\.+/, '');
      if (HOST_RE.test(clean)) return clean;
    }
  }
  for (const tok of splitMatchers(rule.summary)) {
    const clean = tok.replace(/^\.+/, '');
    if (HOST_RE.test(clean)) return clean;
  }
  return '';
}

export function previewRuleMatch(
  host: string,
  rules: RuleItem[],
  activeMode: string,
  globalOutbound = '',
): RulePreviewResult {
  const h = host.trim().toLowerCase();
  if (activeMode === 'direct') {
    return {
      ruleIndex: null,
      ruleType: 'mode',
      action: 'direct',
      target: 'direct',
      summary: 'direct',
      opaqueHint: false,
    };
  }
  if (activeMode === 'global') {
    return {
      ruleIndex: null,
      ruleType: 'mode',
      action: 'route',
      target: globalOutbound || 'global',
      summary: 'global',
      opaqueHint: false,
    };
  }

  let opaqueSeen = false;
  for (const r of rules) {
    const t = r.type.toLowerCase();
    const tokens = splitMatchers(r.summary);
    if (t.includes('rule_set') || t.includes('ruleset') || t.includes('geosite') || t.includes('geoip')) {
      opaqueSeen = true;
      continue;
    }
    if (t === 'domain' || t === 'host') {
      if (tokens.some((tok) => tok === h)) {
        return {
          ruleIndex: r.index,
          ruleType: r.type,
          action: r.action,
          target: r.target || r.action,
          summary: r.summary,
          opaqueHint: opaqueSeen,
        };
      }
    } else if (t === 'domain_suffix' || t === 'domain-suffix') {
      if (
        tokens.some((tok) => {
          const suf = tok.replace(/^\.+/, '');
          return suf.length > 0 && (h === suf || h.endsWith(`.${suf}`));
        })
      ) {
        return {
          ruleIndex: r.index,
          ruleType: r.type,
          action: r.action,
          target: r.target || r.action,
          summary: r.summary,
          opaqueHint: opaqueSeen,
        };
      }
    } else if (t === 'domain_keyword' || t === 'domain-keyword') {
      if (tokens.some((tok) => tok.length > 0 && h.includes(tok))) {
        return {
          ruleIndex: r.index,
          ruleType: r.type,
          action: r.action,
          target: r.target || r.action,
          summary: r.summary,
          opaqueHint: opaqueSeen,
        };
      }
    } else if (t === 'final' || t === 'default' || t === 'match' || t === '') {
      return {
        ruleIndex: r.index,
        ruleType: r.type || 'final',
        action: r.action,
        target: r.target || r.action,
        summary: r.summary || 'default',
        opaqueHint: opaqueSeen,
      };
    }
  }

  return {
    ruleIndex: null,
    ruleType: 'default',
    action: 'route',
    target: 'default',
    summary: 'default',
    opaqueHint: opaqueSeen,
  };
}

export function filterPaletteItems(
  rawQuery: string,
  groups: OutboundGroup[],
  commands: PaletteCommand[],
): PaletteItem[] {
  const trimmed = rawQuery.trim();
  const cmdOnly = trimmed.startsWith('>');
  const q = (cmdOnly ? trimmed.slice(1) : trimmed).trim().toLowerCase();
  const tokens = q ? q.split(/\s+/).filter(Boolean) : [];
  const matchesAll = (hay: string) => tokens.every((tok) => hay.includes(tok));

  const items: PaletteItem[] = [];

  if (!trimmed) {
    for (const c of commands) {
      if (c.pinned) items.push({ kind: 'command', id: `cmd:${c.id}`, command: c });
    }
    const primary = groups[0];
    if (primary) {
      for (const m of primary.members.slice(0, 6)) {
        items.push({
          kind: 'node',
          id: `node:${primary.name}:${m.name}`,
          group: primary.name,
          member: m,
          active: m.name === primary.selected,
        });
      }
    }
    return items;
  }

  for (const c of commands) {
    const hay = `${c.label} ${c.keywords}`.toLowerCase();
    if (tokens.length === 0 || matchesAll(hay)) {
      items.push({ kind: 'command', id: `cmd:${c.id}`, command: c });
    }
  }

  if (!cmdOnly) {
    for (const g of groups) {
      const switchable = g.mode === 'selector' || g.mode === 'select' || g.mode === 'url-test';
      if (!switchable) continue;
      for (const m of g.members) {
        const hay = `${g.name} ${m.name} ${m.state}`.toLowerCase();
        if (matchesAll(hay)) {
          items.push({
            kind: 'node',
            id: `node:${g.name}:${m.name}`,
            group: g.name,
            member: m,
            active: m.name === g.selected,
          });
        }
      }
    }
  }

  return items.slice(0, 24);
}
