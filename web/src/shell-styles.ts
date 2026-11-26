import { css } from 'lit';

export const shellStyles = css`
  :host {
    display: block;
    min-height: 100dvh;
    background: var(--nx-bg);
    color: var(--nx-text);
    font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  }
  .shell {
    display: grid;
    grid-template-columns: 224px 1fr;
    min-height: 100dvh;
  }
  aside {
    background: var(--nx-sidebar);
    border-right: 1px solid var(--nx-border);
    padding: 16px 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 10px;
    position: sticky;
    top: 0;
    height: 100dvh;
  }
  .brand-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 4px 6px;
    gap: 6px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 9px;
  }
  .brand-mark {
    width: 26px;
    height: 26px;
    border-radius: 7px;
    background: var(--nx-accent);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    color: var(--nx-accent-fg);
    font-weight: 700;
    font-size: 13px;
  }
  .brand-text {
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 0.1em;
  }
  .palette-btn {
    width: 100%;
    justify-content: space-between;
    padding: 7px 10px;
    background: var(--nx-well);
    border: 1px solid var(--nx-border);
    color: var(--nx-muted);
    font-size: 12px;
    font-weight: 500;
  }
  .palette-btn-mob {
    display: none;
  }
  nav {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  nav a {
    display: flex;
    align-items: center;
    gap: 9px;
    text-decoration: none;
    color: var(--nx-text-secondary);
    padding: 8px 10px;
    border-radius: 8px;
    font-size: 13.5px;
    font-weight: 600;
  }
  nav a.active {
    background: var(--nx-accent-soft);
    color: var(--nx-accent-text, var(--nx-accent));
  }
  .sidebar-foot {
    margin-top: auto;
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding-top: 10px;
    border-top: 1px solid var(--nx-border);
  }
  .mini-rates {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    padding: 8px 10px;
    border-radius: 8px;
    background: var(--nx-well);
    font-size: 11.5px;
  }
  .theme-swatches {
    display: grid;
    grid-template-columns: 1.15fr repeat(3, 1fr);
    gap: 4px;
    background: var(--nx-inset);
    border: 1px solid var(--nx-border);
    border-radius: 9px;
    padding: 3px;
  }
  .swatch-btn {
    border: 1px solid transparent;
    background: transparent;
    color: var(--nx-text-secondary);
    border-radius: 6px;
    padding: 5px 4px;
    font-size: 11px;
    font-weight: 600;
    min-height: 28px;
    transition: none;
  }
  .swatch-btn.active {
    background: var(--nx-surface);
    color: var(--nx-text);
    border-color: var(--nx-accent);
    outline: 1px solid var(--nx-accent);
  }
  .swatch-chip {
    width: 18px;
    height: 12px;
    border-radius: 4px;
    border: 1px solid var(--nx-border-strong);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 2px;
  }
  .swatch-dot {
    width: 5px;
    height: 5px;
    border-radius: 50%;
  }
  .controls-row {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 5px;
  }
  .controls-row button {
    padding: 6px;
    font-size: 11.5px;
  }
  main {
    padding: 20px 24px max(24px, env(safe-area-inset-bottom));
    max-width: 1280px;
    width: 100%;
    margin: 0 auto;
    min-width: 0;
  }
  .auth-banner {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    margin-bottom: 14px;
    padding: 10px 14px;
    border-radius: 10px;
    background: var(--nx-warn-bg);
    border: 1px solid var(--nx-warn-border);
    color: var(--nx-warn-fg);
    font-size: 13px;
    font-weight: 500;
  }
  @media (hover: hover) and (pointer: fine) {
    nav a:hover:not(.active) {
      background: var(--nx-well);
      color: var(--nx-text);
    }
    .swatch-btn:hover:not(.active) {
      background: var(--nx-well);
    }
  }
  @media (pointer: coarse) {
    .swatch-btn,
    .palette-btn-mob {
      min-height: 44px;
    }
  }
  @media (max-width: 860px) {
    .shell {
      grid-template-columns: 1fr;
    }
    aside {
      position: sticky;
      top: 0;
      height: auto;
      z-index: 30;
      border-right: none;
      border-bottom: 1px solid var(--nx-border);
      padding: max(10px, env(safe-area-inset-top)) max(12px, env(safe-area-inset-right)) 10px
        max(12px, env(safe-area-inset-left));
      gap: 8px;
    }
    .palette-btn {
      display: none;
    }
    .palette-btn-mob {
      display: inline-flex;
    }
    nav {
      flex-direction: row;
      overflow-x: auto;
      overscroll-behavior: contain;
      padding-bottom: 2px;
    }
    nav a {
      padding: 7px 10px;
      white-space: nowrap;
    }
    .mini-rates,
    .hint-line {
      display: none;
    }
    .sidebar-foot {
      margin-top: 0;
      padding-top: 0;
      border-top: none;
    }
    main {
      padding: 14px max(14px, env(safe-area-inset-right))
        max(20px, env(safe-area-inset-bottom)) max(14px, env(safe-area-inset-left));
    }
  }
`;
