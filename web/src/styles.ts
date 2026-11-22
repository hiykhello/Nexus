import { css } from 'lit';

export const sharedStyles = css`
  :host {
    display: block;
    color: var(--nx-text);
  }
  .page {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 14px;
  }
  .card {
    background: var(--nx-surface);
    border: 1px solid var(--nx-border);
    border-radius: 12px;
    padding: 16px;
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
  }
  .between {
    justify-content: space-between;
  }
  h2 {
    margin: 0;
    font-size: 18px;
    font-weight: 700;
  }
  h3 {
    margin: 0 0 8px 0;
    font-size: 14px;
    font-weight: 600;
    color: var(--nx-muted);
  }
  .metric {
    font-size: 24px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
  }
  .muted {
    color: var(--nx-muted);
    font-size: 13px;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12px;
  }
  button {
    appearance: none;
    border: 1px solid var(--nx-border);
    background: var(--nx-surface-alt);
    color: var(--nx-text);
    border-radius: 8px;
    padding: 7px 13px;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
  }
  button:hover:not(:disabled) {
    border-color: var(--nx-accent);
  }
  button.primary {
    background: var(--nx-accent);
    border-color: var(--nx-accent);
    color: #fff;
  }
  button.danger {
    color: var(--nx-danger);
    border-color: var(--nx-danger);
  }
  button:disabled {
    opacity: 0.5;
    cursor: default;
  }
  input, select {
    border: 1px solid var(--nx-border);
    background: var(--nx-surface-alt);
    color: var(--nx-text);
    border-radius: 8px;
    padding: 7px 10px;
    font-size: 13px;
  }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    background: var(--nx-surface-alt);
    border: 1px solid var(--nx-border);
  }
  .badge.ok {
    color: #16a34a;
    border-color: #16a34a66;
  }
  .badge.warn {
    color: #d97706;
    border-color: #d9770666;
  }
  .badge.err {
    color: var(--nx-danger);
    border-color: var(--nx-danger);
  }
  .error-banner {
    background: rgba(220, 38, 38, 0.12);
    border: 1px solid rgba(220, 38, 38, 0.45);
    color: var(--nx-danger);
    padding: 10px 14px;
    border-radius: 10px;
    font-size: 13px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  th, td {
    text-align: left;
    padding: 8px 10px;
    border-bottom: 1px solid var(--nx-border);
  }
  th {
    color: var(--nx-muted);
    font-weight: 600;
    font-size: 12px;
  }
  tr.clickable:hover {
    background: var(--nx-surface-alt);
    cursor: pointer;
  }
`;
