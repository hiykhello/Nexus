import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { Router, routerLink } from '@elelcode/lit-router';
import { formatRate } from './api.ts';
import './auth-modal.ts';
import { icons } from './icons.ts';
import { getLocale, onLocaleChange, t, toggleLocale, type I18nKey } from './i18n.ts';
import { appStore } from './store.ts';
import { sharedStyles, themeVarsCss } from './styles.ts';
import './pages/overview-page.ts';
import './pages/outbounds-page.ts';
import './pages/connections-page.ts';
import './pages/rules-services-page.ts';
import './pages/logs-page.ts';
import './pages/diagnostics-page.ts';

interface NavSpec {
  path: string;
  key: string;
  labelKey: I18nKey;
  component: string;
  icon: () => ReturnType<typeof icons.overview>;
  exact?: boolean;
}

const NAV_ITEMS: NavSpec[] = [
  { path: '/', key: '1', labelKey: 'nav.overview', component: 'nexus-overview-page', icon: icons.overview, exact: true },
  { path: '/outbounds', key: '2', labelKey: 'nav.outbounds', component: 'nexus-outbounds-page', icon: icons.outbounds },
  { path: '/connections', key: '3', labelKey: 'nav.connections', component: 'nexus-connections-page', icon: icons.connections },
  { path: '/services', key: '4', labelKey: 'nav.rules', component: 'nexus-rules-services-page', icon: icons.rules },
  { path: '/logs', key: '5', labelKey: 'nav.logs', component: 'nexus-logs-page', icon: icons.logs },
  { path: '/diagnostics', key: '6', labelKey: 'nav.diagnostics', component: 'nexus-diagnostics-page', icon: icons.diagnostics },
];

const routes = NAV_ITEMS.map((item) => ({
  path: item.path,
  title: () => `${t(item.labelKey)} · Nexus`,
  component: item.component,
}));

@customElement('nexus-app')
export class NexusApp extends LitElement {
  static styles = [
    themeVarsCss,
    sharedStyles,
    css`
      :host {
        display: block;
        min-height: 100dvh;
        background: var(--nx-bg);
        color: var(--nx-text);
        font-family:
          Inter,
          system-ui,
          -apple-system,
          BlinkMacSystemFont,
          'Segoe UI',
          sans-serif;
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
        padding: 4px 6px 6px;
        gap: 8px;
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
      @media (hover: hover) and (pointer: fine) {
        nav a:hover:not(.active) {
          background: var(--nx-well);
          color: var(--nx-text);
        }
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
      .controls-row {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 5px;
      }
      .controls-row button {
        padding: 6px 4px;
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
    `,
  ];

  @state() private authModalOpen = false;

  private readonly router = new Router({ routes, autoStart: true });
  private unsubs: (() => void)[] = [];

  connectedCallback(): void {
    super.connectedCallback();
    appStore.start();
    this.syncHostTheme();
    this.unsubs.push(
      appStore.subscribe(() => {
        this.syncHostTheme();
        this.requestUpdate();
      }, 'change'),
      appStore.subscribe(() => this.requestUpdate(), 'auth-required'),
      onLocaleChange(() => {
        const cur = NAV_ITEMS.find((n) => n.path === window.location.pathname) ?? NAV_ITEMS[0];
        document.title = `${t(cur.labelKey)} · Nexus`;
        this.requestUpdate();
      }),
    );
    window.addEventListener('keydown', this.handleKeydown);
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    window.removeEventListener('keydown', this.handleKeydown);
    for (const u of this.unsubs) u();
    this.unsubs = [];
    appStore.stop();
    this.router.stop();
  }

  private syncHostTheme(): void {
    this.setAttribute('data-theme', appStore.resolvedTheme);
  }

  private isTypingTarget(ev: KeyboardEvent): boolean {
    for (const node of ev.composedPath()) {
      if (node instanceof HTMLElement) {
        const tag = node.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || node.isContentEditable) {
          return true;
        }
      }
    }
    return false;
  }

  private focusActiveSearch(): void {
    const view = this.shadowRoot?.querySelector('router-view');
    const page = (view?.shadowRoot?.querySelector('.viewport')?.firstElementChild ??
      view?.firstElementChild) as HTMLElement | null;
    const input = page?.shadowRoot?.querySelector<HTMLInputElement>('[data-search-input]');
    if (input) {
      input.focus();
      input.select();
    }
  }

  private handleKeydown = (ev: KeyboardEvent): void => {
    if (ev.key === 'Escape' && this.authModalOpen) {
      this.authModalOpen = false;
      return;
    }
    if (ev.metaKey || ev.ctrlKey || ev.altKey || this.isTypingTarget(ev)) return;

    const match = NAV_ITEMS.find((n) => n.key === ev.key);
    if (match) {
      ev.preventDefault();
      this.router.push(match.path);
      return;
    }
    if (ev.key === '/') {
      ev.preventDefault();
      this.focusActiveSearch();
      return;
    }
    if (ev.key === 'r' || ev.key === 'R') {
      ev.preventDefault();
      void appStore.refreshNow();
    }
  };

  render() {
    const st = appStore.streamState;
    const badgeCls = st === 'live' ? 'ok' : st === 'polling' || st === 'connecting' ? 'warn' : 'err';
    const streamLabel =
      st === 'live' && appStore.streamTransport === 'ws' ? t('stream.liveWs') : t(`stream.${st}`);
    const locale = getLocale();

    return html`
      <div class="shell">
        <aside>
          <div class="brand-row">
            <div class="brand">
              <span class="brand-mark" aria-hidden="true">N</span>
              <span class="brand-text">NEXUS</span>
            </div>
            <span class="badge ${badgeCls}" title=${appStore.streamError || streamLabel}>
              <span class="dot"></span>${streamLabel}
            </span>
          </div>

          <nav aria-label=${t('nav.mainLabel')}>
            ${NAV_ITEMS.map(
              (item) => html`
                <a
                  title="${t(item.labelKey)} (${item.key})"
                  ${routerLink(this.router, item.path, { exact: item.exact, activeClass: 'active' })}
                >
                  ${item.icon()}<span>${t(item.labelKey)}</span>
                </a>
              `,
            )}
          </nav>

          <div class="sidebar-foot">
            <div class="mini-rates mono">
              <span class="rate-slot" style="color:var(--nx-down)">↓ ${formatRate(appStore.downRate)}</span>
              <span class="rate-slot" style="color:var(--nx-up)">↑ ${formatRate(appStore.upRate)}</span>
            </div>

            <div class="controls-row">
              <button
                class="sm"
                title=${t(`theme.${appStore.themePref}`)}
                @click=${() => appStore.cycleTheme()}
              >
                ${appStore.resolvedTheme === 'dark' ? icons.moon() : icons.sun()}
                ${t(`theme.${appStore.themePref}`)}
              </button>
              <button class="sm" @click=${() => toggleLocale()}>
                ${icons.globe()} ${locale === 'zh' ? '中文' : 'EN'}
              </button>
              <button
                class="sm ${appStore.authRequired ? 'danger' : ''}"
                @click=${() => (this.authModalOpen = true)}
              >
                ${icons.lock()} ${t('auth.configure')}
              </button>
            </div>

            <div class="muted hint-line" style="font-size:11px; text-align:center">
              ${t('shortcuts.hint')}
            </div>
          </div>
        </aside>

        <main>
          ${appStore.authRequired
            ? html`
                <div class="auth-banner" role="alert">
                  <span>${t('auth.banner')}</span>
                  <button class="primary sm" @click=${() => (this.authModalOpen = true)}>
                    ${icons.lock()} ${t('auth.openConfig')}
                  </button>
                </div>
              `
            : ''}
          <router-view .router=${this.router}></router-view>
        </main>
      </div>

      <nexus-auth-modal
        .open=${this.authModalOpen}
        @close=${() => (this.authModalOpen = false)}
      ></nexus-auth-modal>
    `;
  }
}
