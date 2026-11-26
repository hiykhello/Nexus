import { LitElement, html } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { Router, routerLink } from '@elelcode/lit-router';
import { formatRate, type ThemePreference } from './api.ts';
import './auth-modal.ts';
import './components/command-palette.ts';
import { icons } from './icons.ts';
import { getLocale, onLocaleChange, t, toggleLocale, type I18nKey } from './i18n.ts';
import { shellStyles } from './shell-styles.ts';
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

const SWATCHES: Array<{ pref: ThemePreference; bg: string; accent: string; signal: string }> = [
  { pref: 'obsidian', bg: '#181b22', accent: '#2563eb', signal: '#34d399' },
  { pref: 'daylight', bg: '#f6f5f2', accent: '#1d4ed8', signal: '#047857' },
  { pref: 'amber', bg: '#1b1916', accent: '#e59a2e', signal: '#34d399' },
];

const routes = NAV_ITEMS.map((item) => ({
  path: item.path,
  title: () => `${t(item.labelKey)} · Nexus`,
  component: item.component,
}));

@customElement('nexus-app')
export class NexusApp extends LitElement {
  static styles = [themeVarsCss, sharedStyles, shellStyles];

  @state() private authModalOpen = false;
  @state() private paletteOpen = false;
  @state() private paletteQuery = '';

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
      appStore.onNavigate((path) => this.router.push(path)),
      appStore.onOpenPalette((q) => {
        this.paletteQuery = q;
        this.paletteOpen = true;
      }),
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
    if ((ev.metaKey || ev.ctrlKey) && ev.key.toLowerCase() === 'k') {
      ev.preventDefault();
      this.paletteQuery = '';
      this.paletteOpen = !this.paletteOpen;
      return;
    }
    if (this.paletteOpen) return;
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
            <div class="row" style="gap:6px">
              <button
                type="button"
                class="sm palette-btn-mob"
                aria-label=${t('palette.trigger')}
                @click=${() => {
                  this.paletteQuery = '';
                  this.paletteOpen = true;
                }}
              >
                ${icons.search()}
              </button>
              <span class="badge ${badgeCls}" title=${appStore.streamError || streamLabel}>
                <span class="dot" style=${st === 'live' ? 'background:var(--nx-signal)' : ''}></span>
                ${streamLabel}
              </span>
            </div>
          </div>

          <button
            type="button"
            class="palette-btn"
            aria-label=${t('palette.trigger')}
            @click=${() => {
              this.paletteQuery = '';
              this.paletteOpen = true;
            }}
          >
            <span class="row" style="gap:6px">${icons.search()} ${t('palette.trigger')}</span>
            <span class="mono" style="font-size:11px">⌘K</span>
          </button>

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

            <div class="theme-swatches" role="group" aria-label=${t('theme.label')}>
              <button
                type="button"
                class="swatch-btn ${appStore.themePref === 'system' ? 'active' : ''}"
                aria-pressed=${appStore.themePref === 'system' ? 'true' : 'false'}
                title=${t('theme.system')}
                @click=${() => appStore.setTheme('system')}
              >
                ${t('theme.system')}
              </button>
              ${SWATCHES.map(
                (sw) => html`
                  <button
                    type="button"
                    class="swatch-btn ${appStore.themePref === sw.pref ? 'active' : ''}"
                    aria-pressed=${appStore.themePref === sw.pref ? 'true' : 'false'}
                    aria-label=${t(`theme.${sw.pref}` as I18nKey)}
                    title=${t(`theme.${sw.pref}` as I18nKey)}
                    @click=${() => appStore.setTheme(sw.pref)}
                  >
                    <span class="swatch-chip" style="background:${sw.bg}" aria-hidden="true">
                      <span class="swatch-dot" style="background:${sw.accent}"></span>
                      <span class="swatch-dot" style="background:${sw.signal}"></span>
                    </span>
                  </button>
                `,
              )}
            </div>

            <div class="controls-row">
              <button type="button" class="sm" @click=${() => toggleLocale()}>
                ${icons.globe()} ${locale === 'zh' ? '中文' : 'EN'}
              </button>
              <button
                type="button"
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

      <nexus-command-palette
        .open=${this.paletteOpen}
        .initialQuery=${this.paletteQuery}
        @close=${() => {
          this.paletteOpen = false;
          this.paletteQuery = '';
        }}
      ></nexus-command-palette>
    `;
  }
}
