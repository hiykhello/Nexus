import { css } from 'lit';
import type { ResolvedTheme, ThemePreference } from './types.ts';

export const THEME_META_COLORS: Record<ResolvedTheme, string> = {
  obsidian: '#111318',
  daylight: '#f6f5f2',
  amber: '#131210',
};

export function migrateThemePreference(saved: string | null | undefined): ThemePreference {
  if (saved === 'obsidian' || saved === 'daylight' || saved === 'amber' || saved === 'system') {
    return saved;
  }
  if (saved === 'dark') return 'obsidian';
  if (saved === 'light') return 'daylight';
  return 'system';
}

export function resolveTheme(pref: ThemePreference, prefersLight: boolean): ResolvedTheme {
  if (pref === 'obsidian' || pref === 'daylight' || pref === 'amber') return pref;
  return prefersLight ? 'daylight' : 'obsidian';
}

export function themeColorScheme(resolved: ResolvedTheme): 'light' | 'dark' {
  return resolved === 'daylight' ? 'light' : 'dark';
}

export const themeVarsCss = css`
  :host,
  :host([data-theme='obsidian']),
  :host([data-theme='amber']) {
    color-scheme: dark;
    --nx-signal: #34d399;
    --nx-signal-bg: rgba(16, 185, 129, 0.14);
    --nx-signal-border: rgba(16, 185, 129, 0.36);
    --nx-ok-fg: #34d399;
    --nx-ok-bg: rgba(16, 185, 129, 0.14);
    --nx-ok-border: rgba(16, 185, 129, 0.34);
    --nx-warn-fg: #fbbf24;
    --nx-warn-bg: rgba(245, 158, 11, 0.14);
    --nx-warn-border: rgba(245, 158, 11, 0.34);
    --nx-err-fg: #f87171;
    --nx-err-bg: rgba(239, 68, 68, 0.14);
    --nx-err-border: rgba(239, 68, 68, 0.36);
    --nx-lat-fast-fg: #34d399;
    --nx-lat-fast-bg: rgba(16, 185, 129, 0.14);
    --nx-lat-good-fg: #60a5fa;
    --nx-lat-good-bg: rgba(59, 130, 246, 0.16);
    --nx-lat-mid-fg: #fbbf24;
    --nx-lat-mid-bg: rgba(245, 158, 11, 0.14);
    --nx-lat-slow-fg: #fb923c;
    --nx-lat-slow-bg: rgba(249, 115, 22, 0.15);
    --nx-lat-down-fg: #f87171;
    --nx-lat-down-bg: rgba(239, 68, 68, 0.14);
    --nx-meter-opacity: 0.065;
  }

  :host,
  :host([data-theme='obsidian']) {
    --nx-sidebar: #131923;
    --nx-bg: #111318;
    --nx-inset: #263244;
    --nx-surface: #171e29;
    --nx-well: #1e2736;
    --nx-row-hover: #212c3d;
    --nx-overlay: #1b2432;
    --nx-scrim: rgba(9, 11, 16, 0.72);
    --nx-border: #263142;
    --nx-border-strong: #37465e;
    --nx-text: #f1f5f9;
    --nx-text-secondary: #a3b3c9;
    --nx-muted: #94a3b8;
    --nx-accent: #2563eb;
    --nx-accent-text: #60a5fa;
    --nx-accent-hover: #1d4ed8;
    --nx-accent-soft: rgba(59, 130, 246, 0.16);
    --nx-accent-border: rgba(59, 130, 246, 0.45);
    --nx-accent-fg: #ffffff;
    --nx-down: #60a5fa;
    --nx-up: #10b981;
    --nx-lat-unprobed-fg: #94a3b8;
    --nx-lat-unprobed-bg: #1e2736;
  }

  :host([data-theme='daylight']) {
    color-scheme: light;
    --nx-sidebar: #ffffff;
    --nx-bg: #f6f5f2;
    --nx-inset: #eef2f6;
    --nx-surface: #ffffff;
    --nx-well: #f8fafc;
    --nx-row-hover: #f1f5f9;
    --nx-overlay: #ffffff;
    --nx-scrim: rgba(15, 23, 42, 0.42);
    --nx-border: #e2e8f0;
    --nx-border-strong: #cbd5e1;
    --nx-text: #0f172a;
    --nx-text-secondary: #475569;
    --nx-muted: #526071;
    --nx-accent: #2563eb;
    --nx-accent-text: #1d4ed8;
    --nx-accent-hover: #1d4ed8;
    --nx-accent-soft: rgba(37, 99, 235, 0.1);
    --nx-accent-border: rgba(37, 99, 235, 0.4);
    --nx-accent-fg: #ffffff;
    --nx-signal: #059669;
    --nx-signal-bg: #ecfdf5;
    --nx-signal-border: rgba(5, 150, 105, 0.3);
    --nx-down: #2563eb;
    --nx-up: #059669;
    --nx-ok-fg: #059669;
    --nx-ok-bg: #ecfdf5;
    --nx-ok-border: rgba(5, 150, 105, 0.28);
    --nx-warn-fg: #d97706;
    --nx-warn-bg: #fef3c7;
    --nx-warn-border: rgba(217, 119, 6, 0.28);
    --nx-err-fg: #dc2626;
    --nx-err-bg: #fef2f2;
    --nx-err-border: rgba(220, 38, 38, 0.28);
    --nx-lat-fast-fg: #059669;
    --nx-lat-fast-bg: #ecfdf5;
    --nx-lat-good-fg: #2563eb;
    --nx-lat-good-bg: #eff6ff;
    --nx-lat-mid-fg: #92400e;
    --nx-lat-mid-bg: #fef3c7;
    --nx-lat-slow-fg: #c2410c;
    --nx-lat-slow-bg: #ffedd5;
    --nx-lat-down-fg: #b91c1c;
    --nx-lat-down-bg: #fee2e2;
    --nx-lat-unprobed-fg: #526071;
    --nx-lat-unprobed-bg: #eef2f6;
    --nx-meter-opacity: 0.06;
  }

  :host([data-theme='amber']) {
    --nx-sidebar: #0d0c0b;
    --nx-bg: #131210;
    --nx-inset: #161412;
    --nx-surface: #1b1916;
    --nx-well: #24211d;
    --nx-row-hover: #2b2722;
    --nx-overlay: #1b1916;
    --nx-scrim: rgba(10, 9, 8, 0.72);
    --nx-border: #2f2a23;
    --nx-border-strong: #453d34;
    --nx-text: #f5f1e8;
    --nx-text-secondary: #c2b8aa;
    --nx-muted: #a89f91;
    --nx-accent: #f59e0b;
    --nx-accent-text: #fbbf24;
    --nx-accent-hover: #d97706;
    --nx-accent-soft: rgba(245, 158, 11, 0.16);
    --nx-accent-border: rgba(245, 158, 11, 0.45);
    --nx-accent-fg: #14120f;
    --nx-down: #f59e0b;
    --nx-up: #10b981;
    --nx-lat-unprobed-fg: #aaa296;
    --nx-lat-unprobed-bg: #24211d;
  }
`;
