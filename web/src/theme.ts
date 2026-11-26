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
    --nx-lat-good-fg: #2dd4bf;
    --nx-lat-good-bg: rgba(20, 184, 166, 0.14);
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
    --nx-sidebar: #0c0e12;
    --nx-bg: #111318;
    --nx-inset: #14171d;
    --nx-surface: #181b22;
    --nx-well: #1f232c;
    --nx-row-hover: #252a35;
    --nx-overlay: #181b22;
    --nx-scrim: rgba(9, 11, 16, 0.72);
    --nx-border: #262b36;
    --nx-border-strong: #343b4a;
    --nx-modal-shadow: 0 16px 40px rgba(0, 0, 0, 0.54);
    --nx-text: #edf0f5;
    --nx-text-secondary: #b8c1d1;
    --nx-muted: #9aa3b5;
    --nx-accent: #2563eb;
    --nx-accent-text: #7eb1ff;
    --nx-accent-hover: #1d4ed8;
    --nx-accent-soft: rgba(59, 130, 246, 0.16);
    --nx-accent-border: rgba(59, 130, 246, 0.45);
    --nx-accent-fg: #ffffff;
    --nx-down: #38bdf8;
    --nx-up: #c084fc;
    --nx-lat-unprobed-fg: #9aa3b5;
    --nx-lat-unprobed-bg: #1f232c;
  }

  :host([data-theme='daylight']) {
    color-scheme: light;
    --nx-sidebar: #eceae4;
    --nx-bg: #f6f5f2;
    --nx-inset: #eae7e0;
    --nx-surface: #ffffff;
    --nx-well: #f0eee9;
    --nx-row-hover: #e6e3db;
    --nx-overlay: #ffffff;
    --nx-scrim: rgba(15, 23, 42, 0.42);
    --nx-border: #ddd9d0;
    --nx-border-strong: #c9c4b8;
    --nx-modal-shadow: 0 14px 36px rgba(15, 23, 42, 0.16);
    --nx-text: #181c24;
    --nx-text-secondary: #3b4252;
    --nx-muted: #505868;
    --nx-accent: #1d4ed8;
    --nx-accent-text: #1d4ed8;
    --nx-accent-hover: #1e40af;
    --nx-accent-soft: rgba(29, 78, 216, 0.1);
    --nx-accent-border: rgba(29, 78, 216, 0.4);
    --nx-accent-fg: #ffffff;
    --nx-signal: #047857;
    --nx-signal-bg: #dcfce7;
    --nx-signal-border: rgba(4, 120, 87, 0.3);
    --nx-down: #0369a1;
    --nx-up: #6d28d9;
    --nx-ok-fg: #15803d;
    --nx-ok-bg: #dcfce7;
    --nx-ok-border: rgba(21, 128, 61, 0.28);
    --nx-warn-fg: #92400e;
    --nx-warn-bg: #fef3c7;
    --nx-warn-border: rgba(146, 64, 14, 0.28);
    --nx-err-fg: #b91c1c;
    --nx-err-bg: #fee2e2;
    --nx-err-border: rgba(185, 28, 28, 0.28);
    --nx-lat-fast-fg: #15803d;
    --nx-lat-fast-bg: #dcfce7;
    --nx-lat-good-fg: #0f766e;
    --nx-lat-good-bg: #ccfbf1;
    --nx-lat-mid-fg: #92400e;
    --nx-lat-mid-bg: #fef3c7;
    --nx-lat-slow-fg: #c2410c;
    --nx-lat-slow-bg: #ffedd5;
    --nx-lat-down-fg: #b91c1c;
    --nx-lat-down-bg: #fee2e2;
    --nx-lat-unprobed-fg: #505868;
    --nx-lat-unprobed-bg: #eae7e0;
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
    --nx-border: #2e2a24;
    --nx-border-strong: #3f3930;
    --nx-modal-shadow: 0 16px 40px rgba(0, 0, 0, 0.56);
    --nx-text: #f2eee7;
    --nx-text-secondary: #c4bcb0;
    --nx-muted: #aaa296;
    --nx-accent: #e59a2e;
    --nx-accent-text: #f0b14b;
    --nx-accent-hover: #d4881c;
    --nx-accent-soft: rgba(229, 154, 46, 0.16);
    --nx-accent-border: rgba(229, 154, 46, 0.45);
    --nx-accent-fg: #14120f;
    --nx-down: #f0b14b;
    --nx-up: #60a5fa;
    --nx-lat-unprobed-fg: #aaa296;
    --nx-lat-unprobed-bg: #24211d;
  }
`;
