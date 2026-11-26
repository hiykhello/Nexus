import { css } from 'lit';

export const themeVarsCss = css`
  :host,
  :host([data-theme='dark']) {
    color-scheme: dark;
    --nx-bg: #111317;
    --nx-sidebar: #14171d;
    --nx-surface: #191c22;
    --nx-well: #20242c;
    --nx-inset: #20242c;
    --nx-row-hover: #252a34;
    --nx-overlay: #191c22;
    --nx-scrim: rgba(9, 11, 16, 0.68);
    --nx-border: #262a33;
    --nx-border-strong: #323744;
    --nx-modal-shadow: 0 16px 40px rgba(0, 0, 0, 0.52);

    --nx-text: #eceff4;
    --nx-text-secondary: #b8c0ce;
    --nx-muted: #9aa3b2;

    --nx-accent: #2563eb;
    --nx-accent-text: #60a5fa;
    --nx-accent-hover: #1d4ed8;
    --nx-accent-soft: rgba(59, 130, 246, 0.16);
    --nx-accent-border: rgba(59, 130, 246, 0.45);
    --nx-accent-fg: #ffffff;

    --nx-down: #38bdf8;
    --nx-up: #c084fc;

    --nx-ok-fg: #22c55e;
    --nx-ok-bg: rgba(34, 197, 94, 0.14);
    --nx-ok-border: rgba(34, 197, 94, 0.34);

    --nx-warn-fg: #f59e0b;
    --nx-warn-bg: rgba(245, 158, 11, 0.14);
    --nx-warn-border: rgba(245, 158, 11, 0.34);

    --nx-err-fg: #f87171;
    --nx-err-bg: rgba(239, 68, 68, 0.14);
    --nx-err-border: rgba(239, 68, 68, 0.36);

    --nx-lat-fast-fg: #22c55e;
    --nx-lat-fast-bg: rgba(34, 197, 94, 0.14);
    --nx-lat-good-fg: #2dd4bf;
    --nx-lat-good-bg: rgba(20, 184, 166, 0.14);
    --nx-lat-mid-fg: #f59e0b;
    --nx-lat-mid-bg: rgba(245, 158, 11, 0.14);
    --nx-lat-slow-fg: #fb923c;
    --nx-lat-slow-bg: rgba(249, 115, 22, 0.15);
    --nx-lat-down-fg: #f87171;
    --nx-lat-down-bg: rgba(239, 68, 68, 0.14);
    --nx-lat-unprobed-fg: #9aa3b2;
    --nx-lat-unprobed-bg: #20242c;
  }

  :host([data-theme='light']) {
    color-scheme: light;
    --nx-bg: #f5f6f8;
    --nx-sidebar: #fafbfd;
    --nx-surface: #ffffff;
    --nx-well: #eceff3;
    --nx-inset: #eceff3;
    --nx-row-hover: #e5e9f0;
    --nx-overlay: #ffffff;
    --nx-scrim: rgba(15, 23, 42, 0.42);
    --nx-border: #e0e4ec;
    --nx-border-strong: #cbd2df;
    --nx-modal-shadow: 0 14px 36px rgba(15, 23, 42, 0.16);

    --nx-text: #151820;
    --nx-text-secondary: #3e4656;
    --nx-muted: #555e6e;

    --nx-accent: #1d4ed8;
    --nx-accent-text: #1d4ed8;
    --nx-accent-hover: #1e40af;
    --nx-accent-soft: rgba(29, 78, 216, 0.1);
    --nx-accent-border: rgba(29, 78, 216, 0.4);
    --nx-accent-fg: #ffffff;

    --nx-down: #0369a1;
    --nx-up: #7c3aed;

    --nx-ok-fg: #15803d;
    --nx-ok-bg: #dcfce7;
    --nx-ok-border: rgba(21, 128, 61, 0.28);

    --nx-warn-fg: #b45309;
    --nx-warn-bg: #fef3c7;
    --nx-warn-border: rgba(180, 83, 9, 0.28);

    --nx-err-fg: #b91c1c;
    --nx-err-bg: #fee2e2;
    --nx-err-border: rgba(185, 28, 28, 0.28);

    --nx-lat-fast-fg: #15803d;
    --nx-lat-fast-bg: #dcfce7;
    --nx-lat-good-fg: #0f766e;
    --nx-lat-good-bg: #ccfbf1;
    --nx-lat-mid-fg: #b45309;
    --nx-lat-mid-bg: #fef3c7;
    --nx-lat-slow-fg: #c2410c;
    --nx-lat-slow-bg: #ffedd5;
    --nx-lat-down-fg: #b91c1c;
    --nx-lat-down-bg: #fee2e2;
    --nx-lat-unprobed-fg: #555e6e;
    --nx-lat-unprobed-bg: #eceff3;
  }
`;
