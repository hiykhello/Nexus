import { LitElement, html, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import {
  getLatencyTier,
  nexusApi,
  type DnsQueryResponse,
  type OutboundGroup,
  type RouteMode,
  type RuleItem,
  type ThemePreference,
} from '../api.ts';
import { icons } from '../icons.ts';
import { onLocaleChange, t } from '../i18n.ts';
import { appStore } from '../store.ts';
import { sharedStyles } from '../styles.ts';
import {
  buildPaletteCommands,
  filterPaletteItems,
  findProbeableGroup,
  normalizeHostQuery,
  previewRuleMatch,
  type PaletteItem,
} from './palette-logic.ts';

@customElement('nexus-command-palette')
export class NexusCommandPalette extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .backdrop {
        position: fixed;
        inset: 0;
        background: var(--nx-scrim);
        display: flex;
        align-items: flex-start;
        justify-content: center;
        padding: min(11dvh, 78px) 14px 16px;
        z-index: 120;
      }
      @media (prefers-reduced-transparency: no-preference) {
        .backdrop { backdrop-filter: blur(4px); }
      }
      .panel {
        width: min(580px, 100%);
        max-height: 78dvh;
        background: var(--nx-overlay);
        border: 1px solid var(--nx-border-strong);
        border-radius: 12px;
        box-shadow: var(--nx-modal-shadow);
        display: flex;
        flex-direction: column;
        overflow: hidden;
      }
      .input-row {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 10px 12px;
        border-bottom: 1px solid var(--nx-border);
      }
      .input-row input {
        flex: 1;
        min-width: 0;
        border: none;
        background: transparent;
        padding: 4px 2px;
        font-size: 14px;
      }
      .input-row input:focus-visible { outline: none; }
      .diag-card {
        margin: 10px 10px 4px;
        padding: 10px 12px;
        border-radius: 8px;
        background: var(--nx-well);
        display: flex;
        flex-direction: column;
        gap: 6px;
      }
      .diag-line {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 6px;
        font-size: 12.5px;
      }
      .list {
        overflow-y: auto;
        overscroll-behavior: contain;
        padding: 6px;
        display: flex;
        flex-direction: column;
        gap: 2px;
      }
      .item {
        width: 100%;
        border: 1px solid transparent;
        background: transparent;
        color: var(--nx-text);
        border-radius: 8px;
        padding: 8px 10px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 10px;
        text-align: left;
        font-size: 13px;
        font-weight: 600;
        transition: none;
      }
      .item.active {
        background: var(--nx-accent-soft);
        border-color: var(--nx-accent-border);
      }
      .item-main {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        min-width: 0;
        flex: 1;
      }
      .foot {
        padding: 7px 12px;
        border-top: 1px solid var(--nx-border);
        font-size: 11px;
        color: var(--nx-muted);
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
      }
      @media (hover: hover) and (pointer: fine) {
        .item:hover:not(.active) { background: var(--nx-row-hover); }
      }
      @media (pointer: coarse) {
        .input-row input { font-size: 16px; min-height: 44px; }
        .item { min-height: 44px; }
      }
    `,
  ];

  @property({ type: Boolean }) open = false;
  @property({ type: String }) initialQuery = '';

  @state() private query = '';
  @state() private activeIndex = 0;
  @state() private groups: OutboundGroup[] = [];
  @state() private rules: RuleItem[] = [];
  @state() private dnsLoading = false;
  @state() private dnsResult: DnsQueryResponse | null = null;
  @state() private dnsError = '';
  @state() private statusMsg = '';

  private prevFocus: HTMLElement | null = null;
  private dnsTimer: ReturnType<typeof setTimeout> | null = null;
  private dnsAbort: AbortController | null = null;
  private dnsSeq = 0;
  private unsubLocale: (() => void) | null = null;

  connectedCallback(): void {
    super.connectedCallback();
    this.unsubLocale = onLocaleChange(() => this.requestUpdate());
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    this.cancelDns();
    this.unsubLocale?.();
    this.unsubLocale = null;
  }

  private captureActiveElement(): HTMLElement | null {
    let el: Element | null = document.activeElement;
    while (el && el.shadowRoot?.activeElement) el = el.shadowRoot.activeElement;
    return el instanceof HTMLElement ? el : null;
  }

  protected updated(changed: Map<string, unknown>): void {
    if (!changed.has('open')) return;
    if (this.open) {
      this.prevFocus = this.captureActiveElement();
      this.query = this.initialQuery;
      this.activeIndex = 0;
      this.statusMsg = '';
      this.groups = appStore.latestGroups;
      this.rules = appStore.latestRules;
      void this.ensureData();
      this.scheduleDnsCheck();
      void this.updateComplete.then(() => {
        const inp = this.shadowRoot?.querySelector<HTMLInputElement>('#nx-pal-input');
        inp?.focus();
        inp?.select();
      });
    } else {
      this.cancelDns();
      this.prevFocus?.focus();
      this.prevFocus = null;
    }
  }

  private async ensureData(): Promise<void> {
    try {
      const [gRes, rRes] = await Promise.all([
        this.groups.length > 0 ? Promise.resolve(null) : nexusApi.outbounds().catch(() => null),
        this.rules.length > 0 ? Promise.resolve(null) : nexusApi.rules().catch(() => null),
      ]);
      if (gRes?.groups) {
        this.groups = gRes.groups;
        appStore.setGroupsCache(gRes.groups);
      }
      if (rRes?.rules) {
        this.rules = rRes.rules;
        appStore.setRulesCache(rRes.rules);
      }
    } catch {
      // ignore offline palette refresh
    }
  }

  private cancelDns(): void {
    if (this.dnsTimer !== null) {
      clearTimeout(this.dnsTimer);
      this.dnsTimer = null;
    }
    this.dnsAbort?.abort();
    this.dnsAbort = null;
    this.dnsLoading = false;
  }

  private scheduleDnsCheck(): void {
    this.cancelDns();
    const host = normalizeHostQuery(this.query);
    if (!host) {
      this.dnsResult = null;
      this.dnsError = '';
      return;
    }
    const seq = ++this.dnsSeq;
    this.dnsLoading = true;
    this.dnsError = '';
    this.dnsTimer = setTimeout(() => {
      this.dnsTimer = null;
      const ctrl = new AbortController();
      this.dnsAbort = ctrl;
      void nexusApi
        .dnsQuery({ name: host, type: 'A' }, ctrl.signal)
        .then((res) => {
          if (seq !== this.dnsSeq || !this.open) return;
          this.dnsResult = res;
          this.dnsLoading = false;
        })
        .catch((err) => {
          if (seq !== this.dnsSeq || !this.open) return;
          if (err instanceof DOMException && err.name === 'AbortError') return;
          this.dnsResult = null;
          this.dnsError = t('palette.dnsFailed');
          this.dnsLoading = false;
        });
    }, 200);
  }

  private close(): void {
    this.dispatchEvent(new CustomEvent('close', { bubbles: true, composed: true }));
  }

  private async executeItem(item: PaletteItem): Promise<void> {
    if (item.kind === 'node') {
      try {
        await nexusApi.selectGroup(item.group, item.member.name);
        appStore.recordOnset(item.member.name, 'node');
        this.groups = this.groups.map((g) =>
          g.name === item.group ? { ...g, selected: item.member.name } : g,
        );
        appStore.setGroupsCache(this.groups);
        void appStore.refreshNow();
        this.close();
      } catch (err) {
        this.statusMsg = err instanceof Error ? err.message : String(err);
      }
      return;
    }
    const id = item.command.id;
    try {
      if (id.startsWith('mode:')) {
        const m = id.slice(5) as RouteMode;
        appStore.setModeLocal(await nexusApi.setMode(m));
        appStore.recordOnset(t(`overview.mode.${m}`), 'mode');
      } else if (id === 'action:probe') {
        const target = findProbeableGroup(this.groups);
        if (!target) {
          this.statusMsg = t('palette.noProbeGroup');
          return;
        }
        await nexusApi.probeGroup(target.name);
      } else if (id === 'action:flush-fakeip') {
        await nexusApi.flushFakeIp();
      } else if (id === 'action:flush-dns') {
        await nexusApi.clearCache('dns');
      } else if (id === 'action:reload') {
        await nexusApi.reload();
        appStore.recordOnset(t('chart.reloadLabel'), 'reload');
        void appStore.refreshNow();
      } else if (id.startsWith('theme:')) {
        appStore.setTheme(id.slice(6) as ThemePreference);
      } else if (id.startsWith('nav:')) {
        appStore.requestNavigate(id.slice(4));
      }
      this.close();
    } catch (err) {
      this.statusMsg = err instanceof Error ? err.message : String(err);
    }
  }

  private scrollActiveIntoView(): void {
    void this.updateComplete.then(() => {
      this.shadowRoot?.querySelector('.item.active')?.scrollIntoView({ block: 'nearest' });
    });
  }

  private handleKeydown(ev: KeyboardEvent, items: PaletteItem[], host: string): void {
    if (ev.key === 'Escape') {
      ev.preventDefault();
      this.close();
    } else if (ev.key === 'Tab') {
      const nodes = Array.from(
        this.shadowRoot?.querySelectorAll<HTMLElement>('input:not(:disabled), button:not(:disabled)') ?? [],
      );
      if (nodes.length > 0) {
        ev.preventDefault();
        const cur = nodes.indexOf(this.shadowRoot?.activeElement as HTMLElement);
        const next = ev.shiftKey
          ? (cur <= 0 ? nodes.length - 1 : cur - 1)
          : (cur + 1) % nodes.length;
        nodes[next].focus();
      }
    } else if (ev.key === 'ArrowDown' && items.length > 0) {
      ev.preventDefault();
      this.activeIndex = (this.activeIndex + 1) % items.length;
      this.scrollActiveIntoView();
    } else if (ev.key === 'ArrowUp' && items.length > 0) {
      ev.preventDefault();
      this.activeIndex = (this.activeIndex - 1 + items.length) % items.length;
      this.scrollActiveIntoView();
    } else if (ev.key === 'Enter') {
      ev.preventDefault();
      const sel = items[this.activeIndex];
      if (sel) void this.executeItem(sel);
      else if (host) {
        appStore.requestDnsQuery(host);
        this.close();
      }
    }
  }

  render() {
    if (!this.open) return html``;
    const items = filterPaletteItems(this.query, this.groups, buildPaletteCommands(t));
    if (this.activeIndex >= items.length) this.activeIndex = Math.max(0, items.length - 1);
    const activeId = items[this.activeIndex]?.id ?? '';
    const host = normalizeHostQuery(this.query);
    const preview = host
      ? previewRuleMatch(host, this.rules, appStore.mode?.mode ?? 'rule', appStore.mode?.outbound ?? '')
      : null;
    const firstAns = this.dnsResult?.answers?.[0];

    return html`
      <div class="backdrop" @click=${(e: Event) => e.target === e.currentTarget && this.close()}>
        <div
          class="panel"
          role="dialog"
          aria-modal="true"
          aria-label=${t('palette.trigger')}
          @keydown=${(e: KeyboardEvent) => this.handleKeydown(e, items, host)}
        >
          <div class="input-row">
            ${icons.search()}
            <input
              id="nx-pal-input"
              type="text"
              role="combobox"
              aria-expanded="true"
              aria-controls="nx-pal-list"
              aria-activedescendant=${activeId}
              aria-label=${t('palette.inputLabel')}
              autocomplete="off"
              spellcheck="false"
              autocapitalize="none"
              autocorrect="off"
              placeholder=${t('palette.placeholder')}
              .value=${this.query}
              @input=${(e: Event) => {
                this.query = (e.target as HTMLInputElement).value;
                this.activeIndex = 0;
                this.scheduleDnsCheck();
              }}
            />
            <button type="button" class="ghost sm" aria-label=${t('common.close')} @click=${() => this.close()}>
              ${icons.close()}
            </button>
          </div>

          ${host && preview
            ? html`
                <div class="diag-card">
                  <div class="row between">
                    <span class="muted" style="font-size:11px;font-weight:600;text-transform:uppercase">
                      ${t('palette.section.diag')} · ${t('palette.rulePreview')}
                    </span>
                    <button type="button" class="sm" @click=${() => { appStore.requestDnsQuery(host); this.close(); }}>
                      ${t('palette.openDns')}
                    </button>
                  </div>
                  <div class="diag-line mono">
                    <strong>${host}</strong>
                    <span class="muted">→</span>
                    <span class="badge accent">${preview.action} · ${preview.target}</span>
                    <span class="muted">→</span>
                    ${this.dnsLoading
                      ? html`<span class="muted">${t('palette.dnsPending')}</span>`
                      : this.dnsResult
                        ? html`
                            <span class="badge ${this.dnsResult.rcode === 0 ? 'ok' : 'warn'}">${this.dnsResult.rcode_name}</span>
                            <span>${firstAns ? firstAns.data : t('dns.noAnswers')}</span>
                            <span class="muted tabular">TTL ${this.dnsResult.ttl}s · ${this.dnsResult.elapsed_ms}ms</span>
                          `
                        : html`<span class="muted">${this.dnsError}</span>`}
                  </div>
                  ${preview.opaqueHint ? html`<div class="muted" style="font-size:11px">${t('palette.ruleOpaque')}</div>` : ''}
                </div>
              `
            : ''}

          ${this.statusMsg ? html`<div class="toast err" style="margin:6px 10px 0">${this.statusMsg}</div>` : ''}

          <div id="nx-pal-list" class="list" role="listbox">
            ${items.length === 0
              ? html`<div class="empty-state" style="padding:18px 12px">${t('palette.empty')}</div>`
              : items.map((item, idx) => {
                  const isAct = idx === this.activeIndex;
                  if (item.kind === 'command') {
                    return html`
                      <button
                        type="button"
                        id=${item.id}
                        role="option"
                        aria-selected=${isAct ? 'true' : 'false'}
                        class="item ${isAct ? 'active' : ''}"
                        @mouseenter=${() => (this.activeIndex = idx)}
                        @click=${() => void this.executeItem(item)}
                      >
                        <span class="item-main truncate">${item.command.label}</span>
                        ${item.command.hint ? html`<span class="muted mono" style="font-size:11px">${item.command.hint}</span>` : ''}
                      </button>
                    `;
                  }
                  const tier = item.member.breaker_open ? 'down' : getLatencyTier(item.member.latency_ms, item.member.state);
                  return html`
                    <button
                      type="button"
                      id=${item.id}
                      role="option"
                      aria-selected=${isAct ? 'true' : 'false'}
                      class="item ${isAct ? 'active' : ''}"
                      @mouseenter=${() => (this.activeIndex = idx)}
                      @click=${() => void this.executeItem(item)}
                    >
                      <span class="item-main">
                        <span class="muted mono" style="font-size:11px">${item.group}</span>
                        <span class="truncate">${item.member.name}</span>
                        ${item.active ? html`<span class="badge ok">${t('outbounds.selected')}</span>` : ''}
                      </span>
                      <span class="badge lat-${tier}">
                        ${item.member.latency_ms !== undefined ? `${item.member.latency_ms} ms` : t('outbounds.unprobed')}
                      </span>
                    </button>
                  `;
                })}
          </div>
          <div class="foot">
            <span>${t('palette.hint')}</span>
            <span class="mono">Ctrl+K</span>
          </div>
        </div>
      </div>
    `;
  }
}
