import { formatTimestampNs, type LogEntry } from '../api.ts';

export const LOG_LEVELS = ['all', 'trace', 'debug', 'info', 'warn', 'error'] as const;

export const LOG_DOMAINS = [
  'all',
  'core',
  'net',
  'tls',
  'quic',
  'dns',
  'route',
  'tun',
  'proxy',
  'control',
  'state',
] as const;

const LEVEL_RANK: Record<string, number> = {
  trace: 0,
  debug: 1,
  info: 2,
  warn: 3,
  error: 4,
  fatal: 5,
};

export function matchesLogFilters(
  entry: LogEntry,
  level: string,
  domain: string,
  search: string,
): boolean {
  if (domain !== 'all' && entry.domain !== domain) return false;
  if (level !== 'all') {
    const minRank = LEVEL_RANK[level] ?? 0;
    const itemRank = LEVEL_RANK[entry.level] ?? 0;
    if (itemRank < minRank) return false;
  }
  const q = search.trim().toLowerCase();
  if (q && !`${entry.domain} ${entry.message}`.toLowerCase().includes(q)) return false;
  return true;
}

export function countLogSeverities(entries: LogEntry[]): { info: number; warn: number; error: number } {
  let info = 0;
  let warn = 0;
  let error = 0;
  for (const e of entries) {
    if (e.level === 'error' || e.level === 'fatal') error++;
    else if (e.level === 'warn') warn++;
    else if (e.level === 'info') info++;
  }
  return { info, warn, error };
}

export function levelBadgeClass(lvl: string): string {
  if (lvl === 'error' || lvl === 'fatal') return 'err';
  if (lvl === 'warn') return 'warn';
  if (lvl === 'info') return 'accent';
  if (lvl === 'debug') return 'ok';
  return '';
}

export function formatLogPlainLines(entries: LogEntry[]): string {
  return entries
    .map(
      (e) =>
        `#${e.seq} ${formatTimestampNs(e.timestamp_ns)} [${e.level}] (${e.domain}) ev=${e.event} ${e.message}`,
    )
    .join('\n');
}
