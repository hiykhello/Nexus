import { css } from 'lit';
export { themeVarsCss } from './theme.ts';

export const sharedStyles = css`
  *,
  *::before,
  *::after {
    box-sizing: border-box;
  }
  :host {
    display: block;
    color: var(--nx-text);
  }
  .page {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .page-head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }
  .bento-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 12px;
  }
  .bento-2 {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
  }
  @media (max-width: 900px) {
    .bento-2 {
      grid-template-columns: 1fr;
    }
  }
  .card {
    background: var(--nx-surface);
    border: 1px solid var(--nx-border);
    border-radius: 12px;
    padding: 14px;
  }
  .well {
    background: var(--nx-well);
    border-radius: 8px;
    padding: 12px;
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .between {
    justify-content: space-between;
  }
  .col {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  h2 {
    margin: 0;
    font-size: 19px;
    font-weight: 700;
    letter-spacing: -0.015em;
    text-wrap: balance;
  }
  h3 {
    margin: 0;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--nx-muted);
  }
  .metric {
    font-size: 24px;
    font-weight: 700;
    letter-spacing: -0.02em;
    font-variant-numeric: tabular-nums;
    line-height: 1.2;
  }
  .tabular {
    font-variant-numeric: tabular-nums;
  }
  .rate-slot {
    display: inline-block;
    min-width: 9ch;
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .num-col {
    text-align: right;
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }
  .secondary {
    color: var(--nx-text-secondary);
    font-size: 13px;
  }
  .muted {
    color: var(--nx-muted);
    font-size: 12.5px;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace;
    font-size: 12px;
    font-variant-numeric: tabular-nums;
  }
  .truncate {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  button,
  .btn,
  a,
  .chip,
  .badge {
    -webkit-tap-highlight-color: transparent;
    touch-action: manipulation;
    user-select: none;
  }
  button,
  .btn {
    appearance: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    border: 1px solid var(--nx-border-strong);
    background: var(--nx-well);
    color: var(--nx-text);
    border-radius: 8px;
    padding: 7px 12px;
    font-size: 12.5px;
    font-weight: 600;
    line-height: 1.2;
    cursor: pointer;
    transition:
      background 120ms ease-out,
      border-color 120ms ease-out,
      transform 120ms cubic-bezier(0.23, 1, 0.32, 1);
    font-family: inherit;
  }
  button:active:not(:disabled),
  .chip:active {
    transform: scale(0.98);
  }
  button:focus-visible,
  a:focus-visible,
  input:focus-visible,
  select:focus-visible,
  [tabindex]:focus-visible {
    outline: 2px solid var(--nx-accent);
    outline-offset: 2px;
  }
  button.primary {
    background: var(--nx-accent);
    border-color: var(--nx-accent);
    color: var(--nx-accent-fg);
  }
  button.danger {
    color: var(--nx-err-fg);
    border-color: var(--nx-err-border);
    background: var(--nx-err-bg);
  }
  button.ghost {
    background: transparent;
    border-color: transparent;
    color: var(--nx-text-secondary);
  }
  button.sm {
    padding: 5px 9px;
    font-size: 12px;
    border-radius: 6px;
  }
  button:disabled {
    opacity: 0.48;
    cursor: not-allowed;
  }
  input,
  select {
    border: 1px solid var(--nx-border-strong);
    background: var(--nx-well);
    color: var(--nx-text);
    border-radius: 8px;
    padding: 7px 11px;
    font-size: 13px;
    font-family: inherit;
    transition: border-color 120ms ease-out, background 120ms ease-out;
  }
  option {
    background: var(--nx-surface);
    color: var(--nx-text);
  }
  input::placeholder {
    color: var(--nx-muted);
  }
  .segmented {
    display: inline-flex;
    background: var(--nx-inset);
    border: 1px solid var(--nx-border);
    border-radius: 10px;
    padding: 3px;
    gap: 2px;
  }
  .segmented button {
    border: none;
    background: transparent;
    color: var(--nx-text-secondary);
    padding: 5px 11px;
    border-radius: 7px;
    font-size: 12px;
    font-weight: 600;
  }
  .segmented button.active {
    background: var(--nx-accent);
    color: var(--nx-accent-fg);
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    border: 1px solid var(--nx-border);
    background: var(--nx-well);
    color: var(--nx-text-secondary);
    cursor: pointer;
    transition:
      background 120ms ease-out,
      border-color 120ms ease-out,
      transform 120ms cubic-bezier(0.23, 1, 0.32, 1);
  }
  .chip.active {
    background: var(--nx-accent-soft);
    border-color: var(--nx-accent-border);
    color: var(--nx-accent-text, var(--nx-accent));
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    font-variant-numeric: tabular-nums;
    background: var(--nx-inset);
    border: 1px solid var(--nx-border);
    color: var(--nx-text-secondary);
    white-space: nowrap;
  }
  .badge.ok {
    color: var(--nx-ok-fg);
    background: var(--nx-ok-bg);
    border-color: var(--nx-ok-border);
  }
  .badge.warn {
    color: var(--nx-warn-fg);
    background: var(--nx-warn-bg);
    border-color: var(--nx-warn-border);
  }
  .badge.err {
    color: var(--nx-err-fg);
    background: var(--nx-err-bg);
    border-color: var(--nx-err-border);
  }
  .badge.accent {
    color: var(--nx-accent-text, var(--nx-accent));
    background: var(--nx-accent-soft);
    border-color: var(--nx-accent-border);
  }
  .badge.lat-fast {
    color: var(--nx-lat-fast-fg);
    background: var(--nx-lat-fast-bg);
    border-color: transparent;
  }
  .badge.lat-good {
    color: var(--nx-lat-good-fg);
    background: var(--nx-lat-good-bg);
    border-color: transparent;
  }
  .badge.lat-mid {
    color: var(--nx-lat-mid-fg);
    background: var(--nx-lat-mid-bg);
    border-color: transparent;
  }
  .badge.lat-slow {
    color: var(--nx-lat-slow-fg);
    background: var(--nx-lat-slow-bg);
    border-color: transparent;
  }
  .badge.lat-down {
    color: var(--nx-lat-down-fg);
    background: var(--nx-lat-down-bg);
    border-color: transparent;
  }
  .badge.lat-unprobed {
    color: var(--nx-lat-unprobed-fg);
    background: var(--nx-lat-unprobed-bg);
    border-color: transparent;
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: currentColor;
    display: inline-block;
  }
  .toast {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 9px 12px;
    border-radius: 8px;
    font-size: 13px;
    border: 1px solid var(--nx-border-strong);
    background: var(--nx-well);
  }
  .toast.ok {
    border-color: var(--nx-ok-border);
    background: var(--nx-ok-bg);
    color: var(--nx-ok-fg);
  }
  .toast.err {
    border-color: var(--nx-err-border);
    background: var(--nx-err-bg);
    color: var(--nx-err-fg);
  }
  .table-wrap {
    overflow-x: auto;
    overscroll-behavior: contain;
    border-radius: 8px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  th,
  td {
    text-align: left;
    padding: 8px 10px;
    border-bottom: 1px solid var(--nx-border);
    vertical-align: middle;
  }
  th {
    color: var(--nx-muted);
    font-weight: 600;
    font-size: 11.5px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    white-space: nowrap;
  }
  tbody tr:last-child td {
    border-bottom: none;
  }
  tbody tr.clickable {
    cursor: pointer;
  }
  tbody tr.selected {
    background: var(--nx-accent-soft);
  }
  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 10px;
    text-align: center;
    padding: 28px 16px;
    color: var(--nx-muted);
    font-size: 13px;
  }
  @media (hover: hover) and (pointer: fine) {
    button:hover:not(:disabled) {
      border-color: var(--nx-accent-border);
      background: var(--nx-row-hover);
    }
    button.primary:hover:not(:disabled) {
      background: var(--nx-accent-hover);
      border-color: var(--nx-accent-hover);
    }
    button.danger:hover:not(:disabled) {
      border-color: var(--nx-err-fg);
    }
    button.ghost:hover:not(:disabled) {
      background: var(--nx-well);
      color: var(--nx-text);
    }
    .segmented button:hover:not(:disabled):not(.active) {
      background: var(--nx-surface);
      color: var(--nx-text);
    }
    .chip:hover:not(.active) {
      border-color: var(--nx-border-strong);
      color: var(--nx-text);
    }
    tbody tr.clickable:hover {
      background: var(--nx-row-hover);
    }
  }
  @media (pointer: coarse) {
    input,
    select {
      font-size: 16px;
      min-height: 44px;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: 0.01ms !important;
      scroll-behavior: auto !important;
    }
  }
`;
