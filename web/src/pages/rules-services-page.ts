import { LitElement, html, css, nothing } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import {
  formatBytes,
  nexusApi,
  type RuleItem,
  type SsmapiStatsResponse,
  type SsmapiUserItem,
} from '../api.ts';
import { icons } from '../icons.ts';
import { onLocaleChange, t } from '../i18n.ts';
import { appStore } from '../store.ts';
import { sharedStyles } from '../styles.ts';
import { extractDomainFromRule } from '../components/palette-logic.ts';
import './dns-query-card.ts';
import type { NexusDnsQueryCard } from './dns-query-card.ts';

@customElement('nexus-rules-services-page')
export class NexusRulesServicesPage extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .summary-cell {
        word-break: break-word;
        max-width: 440px;
      }
      .user-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 10px;
        padding: 7px 10px;
        border-radius: 8px;
        background: var(--nx-well);
      }
      tbody tr.rule-hit td {
        background: var(--nx-accent-soft);
      }
    `,
  ];

  @state() private rules: RuleItem[] = [];
  @state() private search = '';
  @state() private actionFilter = 'all';
  @state() private selectedRuleIndex = -1;
  @state() private ssmUsers: SsmapiUserItem[] = [];
  @state() private ssmStats: SsmapiStatsResponse | null = null;
  @state() private ssmAvailable = false;
  @state() private error = '';
  @state() private loading = false;

  private unsubs: (() => void)[] = [];

  connectedCallback(): void {
    super.connectedCallback();
    this.unsubs.push(
      appStore.subscribe(() => void this.refresh(), 'refresh'),
      appStore.subscribe(() => this.consumeRuleFilter(), 'change'),
      onLocaleChange(() => this.requestUpdate()),
    );
    this.consumeRuleFilter();
    void this.refresh();
  }

  private consumeRuleFilter(): void {
    const f = appStore.consumePendingRuleFilter();
    if (f) {
      this.search = f;
      this.actionFilter = 'all';
    }
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    for (const u of this.unsubs) u();
    this.unsubs = [];
  }

  private async refresh(): Promise<void> {
    this.loading = true;
    try {
      const rulesRes = await nexusApi.rules();
      this.rules = rulesRes.rules ?? [];
      appStore.setRulesCache(this.rules);
      this.error = '';
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
    } finally {
      this.loading = false;
    }

    try {
      const [usersRes, statsRes] = await Promise.all([
        nexusApi.ssmapiUsers(),
        nexusApi.ssmapiStats(),
      ]);
      this.ssmUsers = usersRes.users ?? [];
      this.ssmStats = statsRes;
      this.ssmAvailable = true;
    } catch {
      this.ssmUsers = [];
      this.ssmStats = null;
      this.ssmAvailable = false;
    }
  }

  private actionBadge(action: string): string {
    const a = action.toLowerCase();
    if (a === 'route') return 'ok';
    if (a === 'reject' || a === 'block') return 'err';
    if (a === 'sniff' || a === 'hijack-dns' || a === 'resolve') return 'accent';
    return 'warn';
  }

  private filteredRules(): RuleItem[] {
    const q = this.search.trim().toLowerCase();
    return this.rules.filter((r) => {
      if (this.actionFilter !== 'all' && r.action.toLowerCase() !== this.actionFilter) return false;
      if (!q) return true;
      return `${r.index} ${r.type} ${r.action} ${r.target} ${r.summary}`.toLowerCase().includes(q);
    });
  }

  private handleRuleClick(rule: RuleItem): void {
    const domain = extractDomainFromRule(rule);
    if (!domain) return;
    this.selectedRuleIndex = rule.index;
    const dnsCard = this.shadowRoot?.querySelector<NexusDnsQueryCard>('nexus-dns-query-card');
    dnsCard?.queryDomain(domain);
  }

  render() {
    const list = this.filteredRules();
    const actions = Array.from(new Set(this.rules.map((r) => r.action.toLowerCase())));
    const hasFilter = this.search.trim().length > 0 || this.actionFilter !== 'all';
    const routeCount = this.rules.filter((r) => r.action.toLowerCase() === 'route' && r.target.toLowerCase() !== 'direct').length;
    const directCount = this.rules.filter((r) => r.target.toLowerCase() === 'direct' || r.action.toLowerCase() === 'direct').length;
    const rejectCount = this.rules.filter((r) => ['reject', 'block'].includes(r.action.toLowerCase())).length;

    return html`
      <div class="page">
        <div class="page-head">
          <h2>${t('rules.title')}</h2>
          <button class="sm" ?disabled=${this.loading} @click=${() => void this.refresh()}>
            ${icons.refresh()} ${t('common.refresh')}
          </button>
        </div>

        <nexus-dns-query-card></nexus-dns-query-card>

        ${this.error
          ? html`
              <div class="toast err" role="status" aria-live="polite">
                <span>${this.error}</span>
                <button
                  class="ghost sm"
                  aria-label=${t('common.dismiss')}
                  @click=${() => (this.error = '')}
                >
                  ${icons.close()}
                </button>
              </div>
            `
          : ''}

        <div class="card col" style="gap:12px">
          <div class="row between">
            <div class="row">
              <h3>${t('rules.tableTitle')}</h3>
              <span class="muted tabular">${list.length} / ${this.rules.length}</span>
            </div>
            <div class="row">
              <span class="badge ok">${t('rules.dist.route', { count: routeCount })}</span>
              <span class="badge accent">${t('rules.dist.direct', { count: directCount })}</span>
              <span class="badge err">${t('rules.dist.reject', { count: rejectCount })}</span>
            </div>
          </div>

          <div class="row">
            <input
              data-search-input
              type="search"
              aria-label=${t('rules.search')}
              spellcheck="false"
              autocapitalize="none"
              autocorrect="off"
              style="flex:1; min-width:220px"
              placeholder=${t('rules.search')}
              .value=${this.search}
              @input=${(e: Event) => (this.search = (e.target as HTMLInputElement).value)}
            />
            <span class="muted" style="font-size:11.5px">${t('rules.clickHint')}</span>
          </div>

          ${actions.length > 0
            ? html`
                <div class="row">
                  <button
                    class="chip ${this.actionFilter === 'all' ? 'active' : ''}"
                    @click=${() => (this.actionFilter = 'all')}
                  >
                    ${t('common.all')}
                  </button>
                  ${actions.map(
                    (a) => html`
                      <button
                        class="chip ${this.actionFilter === a ? 'active' : ''}"
                        @click=${() => (this.actionFilter = a)}
                      >
                        ${a}
                      </button>
                    `,
                  )}
                </div>
              `
            : ''}

          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>${t('rules.col.index')}</th>
                  <th>${t('rules.col.type')}</th>
                  <th>${t('rules.col.action')}</th>
                  <th>${t('rules.col.target')}</th>
                  <th>${t('rules.col.summary')}</th>
                </tr>
              </thead>
              <tbody>
                ${list.length === 0
                  ? html`
                      <tr>
                        <td colspan="5">
                          <div class="empty-state">
                            <span>${t('rules.empty')}</span>
                            ${hasFilter
                              ? html`<button class="sm" @click=${() => { this.search = ''; this.actionFilter = 'all'; }}>${t('common.clearFilters')}</button>`
                              : html`<button class="sm" ?disabled=${this.loading} @click=${() => void this.refresh()}>${icons.refresh()} ${t('common.refresh')}</button>`}
                          </div>
                        </td>
                      </tr>
                    `
                  : list.map((r) => {
                      const domain = extractDomainFromRule(r);
                      return html`
                        <tr
                          class="${domain ? 'clickable' : ''} ${this.selectedRuleIndex === r.index ? 'rule-hit' : ''}"
                          tabindex=${domain ? '0' : nothing}
                          title=${domain ? `${t('dns.query')}: ${domain}` : ''}
                          @click=${() => domain && this.handleRuleClick(r)}
                          @keydown=${(e: KeyboardEvent) => {
                            if (domain && e.target === e.currentTarget && (e.key === 'Enter' || e.key === ' ')) {
                              e.preventDefault();
                              this.handleRuleClick(r);
                            }
                          }}
                        >
                          <td class="mono muted">#${r.index}</td>
                          <td><span class="badge">${r.type || '-'}</span></td>
                          <td><span class="badge ${this.actionBadge(r.action)}">${r.action}</span></td>
                          <td>
                            ${r.target
                              ? html`<span class="badge accent">${r.target}</span>`
                              : html`<span class="muted">-</span>`}
                          </td>
                          <td class="mono summary-cell">${r.summary || '-'}</td>
                        </tr>
                      `;
                    })}
              </tbody>
            </table>
          </div>
        </div>

        <div class="card col">
          <div class="row between">
            <h3>${t('rules.ssmapi')}</h3>
            <span class="badge ${this.ssmAvailable ? 'ok' : ''}">
              ${this.ssmAvailable
                ? `${this.ssmStats?.userCount ?? this.ssmUsers.length} ${t('rules.users')}`
                : t('common.off')}
            </span>
          </div>
          ${!this.ssmAvailable
            ? html`<div class="muted">${t('rules.ssmapiOff')}</div>`
            : html`
                <div class="row muted mono">
                  <span>↑ ${formatBytes(this.ssmStats?.uplinkBytes ?? 0)}</span>
                  <span>·</span>
                  <span>↓ ${formatBytes(this.ssmStats?.downlinkBytes ?? 0)}</span>
                  <span>·</span>
                  <span>TCP ${this.ssmStats?.tcpSessions ?? 0} / UDP ${this.ssmStats?.udpSessions ?? 0}</span>
                </div>
                <div class="col" style="gap:6px">
                  ${this.ssmUsers.slice(0, 12).map(
                    (u) => html`
                      <div class="user-row">
                        <div class="row">
                          <strong class="mono">${u.username}</strong>
                          <span class="badge ${u.enabled ? 'ok' : 'err'}">
                            ${u.enabled ? t('common.on') : t('common.off')}
                          </span>
                        </div>
                        <span class="mono muted">
                          ↑ ${formatBytes(u.uplinkBytes)} / ↓ ${formatBytes(u.downlinkBytes)}
                        </span>
                      </div>
                    `,
                  )}
                </div>
              `}
        </div>
      </div>
    `;
  }
}
