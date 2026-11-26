import { css } from 'lit';

export const themeVarsCss = css`
  :host,
  :host([data-theme='dark']) {
    --nx-bg: #111318;
    --nx-sidebar: #171920;
    --nx-surface: #1c1e25;
    --nx-surface-grad: linear-gradient(180deg, #1e2028 0%, #1a1c23 100%);
    --nx-well: #262932;
    --nx-inset: #323642;
    --nx-row-hover: #2d313d;
    --nx-overlay: rgba(24, 26, 34, 0.96);
    --nx-border: rgba(255, 255, 255, 0.085);
    --nx-border-strong: rgba(255, 255, 255, 0.16);
    --nx-shadow: 0 2px 10px rgba(0, 0, 0, 0.28);
    --nx-shadow-hover: 0 8px 24px rgba(0, 0, 0, 0.38);

    --nx-text: #f5f6f9;
    --nx-text-secondary: #a6acb8;
    --nx-muted: #939baa;

    --nx-accent: #5899ff;
    --nx-accent-text: #5899ff;
    --nx-accent-hover: #70a8ff;
    --nx-accent-soft: rgba(88, 153, 255, 0.16);
    --nx-accent-border: rgba(88, 153, 255, 0.45);
    --nx-accent-fg: #0b1220;

    --nx-down: #38bdf8;
    --nx-up: #c084fc;

    --nx-ok-fg: #34d399;
    --nx-ok-bg: rgba(16, 185, 129, 0.15);
    --nx-ok-border: rgba(34, 197, 94, 0.34);

    --nx-warn-fg: #fbbf24;
    --nx-warn-bg: rgba(245, 158, 11, 0.15);
    --nx-warn-border: rgba(245, 158, 11, 0.34);

    --nx-err-fg: #fb7185;
    --nx-err-bg: rgba(244, 63, 94, 0.15);
    --nx-err-border: rgba(244, 63, 94, 0.36);

    --nx-lat-fast-fg: #34d399;
    --nx-lat-fast-bg: rgba(16, 185, 129, 0.15);
    --nx-lat-good-fg: #2dd4bf;
    --nx-lat-good-bg: rgba(20, 184, 166, 0.15);
    --nx-lat-mid-fg: #fbbf24;
    --nx-lat-mid-bg: rgba(245, 158, 11, 0.15);
    --nx-lat-slow-fg: #fb923c;
    --nx-lat-slow-bg: rgba(249, 115, 22, 0.16);
    --nx-lat-down-fg: #fb7185;
    --nx-lat-down-bg: rgba(244, 63, 94, 0.15);
    --nx-lat-unprobed-fg: #939baa;
    --nx-lat-unprobed-bg: #323642;
  }

  :host([data-theme='light']) {
    --nx-bg: #f0f2f6;
    --nx-sidebar: #f7f8fb;
    --nx-surface: #fcfdff;
    --nx-surface-grad: linear-gradient(180deg, #fcfdff 0%, #f8f9fc 100%);
    --nx-well: #eef1f6;
    --nx-inset: #e2e6ee;
    --nx-row-hover: #eaeff7;
    --nx-overlay: rgba(255, 255, 255, 0.98);
    --nx-border: rgba(15, 23, 42, 0.09);
    --nx-border-strong: rgba(15, 23, 42, 0.16);
    --nx-shadow: 0 1px 4px rgba(15, 23, 42, 0.05);
    --nx-shadow-hover: 0 6px 18px rgba(15, 23, 42, 0.09);

    --nx-text: #0f172a;
    --nx-text-secondary: #475569;
    --nx-muted: #5a6578;

    --nx-accent: #2563eb;
    --nx-accent-text: #1d4ed8;
    --nx-accent-hover: #1d4ed8;
    --nx-accent-soft: rgba(37, 99, 235, 0.11);
    --nx-accent-border: rgba(37, 99, 235, 0.42);
    --nx-accent-fg: #ffffff;

    --nx-down: #0369a1;
    --nx-up: #7c3aed;

    --nx-ok-fg: #047857;
    --nx-ok-bg: #dcfce7;
    --nx-ok-border: rgba(22, 163, 74, 0.3);

    --nx-warn-fg: #b45309;
    --nx-warn-bg: #fef3c7;
    --nx-warn-border: rgba(217, 119, 6, 0.3);

    --nx-err-fg: #be123c;
    --nx-err-bg: #ffe4e6;
    --nx-err-border: rgba(225, 29, 72, 0.3);

    --nx-lat-fast-fg: #047857;
    --nx-lat-fast-bg: #dcfce7;
    --nx-lat-good-fg: #0f766e;
    --nx-lat-good-bg: #ccfbf1;
    --nx-lat-mid-fg: #b45309;
    --nx-lat-mid-bg: #fef3c7;
    --nx-lat-slow-fg: #c2410c;
    --nx-lat-slow-bg: #ffedd5;
    --nx-lat-down-fg: #be123c;
    --nx-lat-down-bg: #ffe4e6;
    --nx-lat-unprobed-fg: #5a6578;
    --nx-lat-unprobed-bg: #e2e6ee;
  }
`;
