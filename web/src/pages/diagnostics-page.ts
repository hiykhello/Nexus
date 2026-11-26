import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import {
  getBearerToken,
  nexusApi,
  setBearerToken,
  type ControlEventItem,
  type DiagnosticsResponse,
  type HealthResponse,
} from '../api.ts';
import { icons } from '../icons.ts';
import { onLocaleChange, t } from '../i18n.ts';
import { appStore } from '../store.ts';
import { sharedStyles } from '../styles.ts';

@customElement('nexus-diagnostics-page')
export class NexusDiagnosticsPage extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .metrics-pre {
        margin: 8px 0 0;
        padding: 12px;
        border-radius: 10px;
        background: var(--nx-well);
        border: 1px solid var(--nx-border);
        max-height: 260px;
        overflow: auto;
        white-space: pre-wrap;
        word-break: break-all;
        font-size: 11.5px;
        line-height: 1.45;
      }
      .kpi-card {
        display: flex;
        flex-direction: column;
        gap: 6px;
      }
    `,
  ];

  @state() private diag: DiagnosticsResponse | null = null;
  @state() private health: HealthResponse | null = null;
  @state() private events: ControlEventItem[] = [];
  @state() private metricsText = '';
  @state() private metricsEnabled = false;
  @state() private showRawMetrics = false;
  @state() private tokenInput = getBearerToken();
  @state() private copied = false;
  @state() private busy = false;
  @state() private toast = '';
  @state() private toastKind: 'ok' | 'err' = 'ok';

  private unsubs: (() => void)[] = [];

  connectedCallback(): void {
    super.connectedCallback();
    this.unsubs.push(
      appStore.subscribe(() => void this.refresh(), 'refresh'),
      onLocaleChange(() => this.requestUpdate()),
    );
    void this.refresh();
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    for (const u of this.unsubs) u();
    this.unsubs = [];
  }

  private async refresh(): Promise<void> {
    this.busy = true;
    try {
      const [diag, health, evs] = await Promise.all([
        nexusApi.diagnostics(),
        nexusApi.health(),
        nexusApi.events(0).catch(() => null),
      ]);
      this.diag = diag;
      this.health = health;
      this.events = (evs?.events ?? []).slice(-30).reverse();
    } catch (err) {
      this.toast = err instanceof Error ? err.message : String(err);
      this.toastKind = 'err';
    } finally {
      this.busy = false;
    }

    try {
      this.metricsText = await nexusApi.metricsText();
      this.metricsEnabled = true;
    } catch {
      this.metricsText = '';
      this.metricsEnabled = false;
    }
  }

  private async saveToken(): Promise<void> {
    setBearerToken(this.tokenInput);
    try {
      const h = await nexusApi.health();
      this.health = h;
      this.toast = t('auth.verified', { instance: h.instance });
      this.toastKind = 'ok';
      await this.refresh();
    } catch (err) {
      this.toast = t('auth.failed', { error: err instanceof Error ? err.message : String(err) });
      this.toastKind = 'err';
    }
  }

  private clearToken(): void {
    this.tokenInput = '';
    setBearerToken('');
    this.toast = t('auth.cleared');
    this.toastKind = 'ok';
  }

  private async notifyNetworkChange(): Promise<void> {
    this.busy = true;
    try {
      await nexusApi.networkChange();
      this.toast = t('diag.networkNotified');
      this.toastKind = 'ok';
      await this.refresh();
    } catch (err) {
      this.toast = err instanceof Error ? err.message : String(err);
      this.toastKind = 'err';
    } finally {
      this.busy = false;
    }
  }

  private async copyJsonReport(): Promise<void> {
    const report = {
      captured_at: new Date().toISOString(),
      health: this.health,
      status: appStore.status,
      mode: appStore.mode,
      diagnostics: this.diag,
      recent_events: this.events,
    };
    try {
      await navigator.clipboard.writeText(JSON.stringify(report, null, 2));
      this.copied = true;
      setTimeout(() => (this.copied = false), 1600);
    } catch {
      // clipboard unavailable
    }
  }

  private parsedMetricLines(): Array<{ name: string; value: string }> {
    return this.metricsText
      .split('\n')
      .filter((l) => l && !l.startsWith('#'))
      .slice(0, 12)
      .map((line) => {
        const sp = line.lastIndexOf(' ');
        return sp > 0
          ? { name: line.slice(0, sp), value: line.slice(sp + 1) }
          : { name: line, value: '' };
      });
  }

  render() {
    const metricLines = this.metricsEnabled ? this.parsedMetricLines() : [];

    return html`
      <div class="page">
        <div class="page-head">
          <div class="row">
            <h2>${t('diag.title')}</h2>
            ${this.health
              ? html`<span class="badge ok">${this.health.status.toUpperCase()} · ${this.health.instance}</span>`
              : ''}
          </div>
          <div class="row">
            <button class="sm" ?disabled=${this.busy} @click=${() => void this.notifyNetworkChange()}>
              ${icons.bolt()} ${t('diag.networkChange')}
            </button>
            <button class="sm" @click=${() => void this.copyJsonReport()}>
              ${icons.copy()} ${this.copied ? t('common.copied') : t('diag.copyJson')}
            </button>
            <button class="primary sm" ?disabled=${this.busy} @click=${() => void this.refresh()}>
              ${icons.refresh()} ${t('common.refresh')}
            </button>
          </div>
        </div>

        ${this.toast
          ? html`
              <div class="toast ${this.toastKind}" role="status" aria-live="polite">
                <span>${this.toast}</span>
                <button
                  class="ghost sm"
                  aria-label=${t('common.dismiss')}
                  @click=${() => (this.toast = '')}
                >
                  ${icons.close()}
                </button>
              </div>
            `
          : ''}

        ${this.diag
          ? html`
              <div class="bento-grid">
                <div class="card kpi-card">
                  <h3>${t('diag.authorized')}</h3>
                  <div class="metric" style="color:var(--nx-ok-fg)">${this.diag.authorized_requests}</div>
                  <div class="muted mono">${t('overview.gen')} #${this.diag.control_generation}</div>
                </div>
                <div class="card kpi-card">
                  <h3>${t('diag.unauthorized')}</h3>
                  <div class="metric" style="color:${this.diag.unauthorized_requests > 0 ? 'var(--nx-err-fg)' : 'inherit'}">
                    ${this.diag.unauthorized_requests}
                  </div>
                  <div class="muted">HTTP 401</div>
                </div>
                <div class="card kpi-card">
                  <h3>${t('diag.expired')}</h3>
                  <div class="metric">${this.diag.expired_requests} / ${this.diag.reply_failed}</div>
                  <div class="muted">${t('diag.timeoutReply')}</div>
                </div>
                <div class="card kpi-card">
                  <h3>${t('diag.listenersConn')}</h3>
                  <div class="metric">${this.diag.listeners} / ${this.diag.active_connections}</div>
                  <div class="muted mono">${this.diag.instance}</div>
                </div>
              </div>
            `
          : ''}

        <div class="card col">
          <div class="row between">
            <h3>${t('auth.title')}</h3>
            <span class="badge mono">${t('diag.sessionStorageOnly')}</span>
          </div>
          <p class="muted" style="margin:0">${t('auth.desc')}</p>
          <div class="row">
            <input
              data-search-input
              type="password"
              style="flex:1; min-width:240px"
              placeholder=${t('auth.placeholder')}
              .value=${this.tokenInput}
              @input=${(e: Event) => (this.tokenInput = (e.target as HTMLInputElement).value)}
              @keydown=${(e: KeyboardEvent) => e.key === 'Enter' && void this.saveToken()}
            />
            <button class="primary" @click=${() => void this.saveToken()}>
              ${icons.lock()} ${t('auth.save')}
            </button>
            <button @click=${() => this.clearToken()}>${t('auth.clear')}</button>
          </div>
        </div>

        <div class="bento-2">
          <div class="card col">
            <div class="row between">
              <h3>${t('diag.events')}</h3>
              <span class="badge tabular">${this.events.length}</span>
            </div>
            ${this.events.length === 0
              ? html`<div class="empty-state">${t('diag.noEvents')}</div>`
              : html`
                  <div class="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>${t('diag.col.id')}</th>
                          <th>${t('diag.col.event')}</th>
                          <th>${t('diag.col.gen')}</th>
                        </tr>
                      </thead>
                      <tbody>
                        ${this.events.slice(0, 15).map(
                          (ev) => html`
                            <tr>
                              <td class="mono muted">#${ev.id}</td>
                              <td><span class="badge accent">${ev.event}</span></td>
                              <td class="mono muted">#${ev.control_generation}</td>
                            </tr>
                          `,
                        )}
                      </tbody>
                    </table>
                  </div>
                `}
          </div>

          <div class="card col">
            <div class="row between">
              <h3>${t('diag.metrics')}</h3>
              ${this.metricsEnabled
                ? html`
                    <button class="sm" @click=${() => (this.showRawMetrics = !this.showRawMetrics)}>
                      ${this.showRawMetrics ? t('diag.summary') : t('diag.raw')}
                    </button>
                  `
                : html`<span class="badge">${t('common.off')}</span>`}
            </div>
            ${!this.metricsEnabled
              ? html`<div class="empty-state">${t('diag.metricsOff')}</div>`
              : this.showRawMetrics
                ? html`<pre class="metrics-pre mono">${this.metricsText}</pre>`
                : html`
                    <div class="table-wrap">
                      <table>
                        <tbody>
                          ${metricLines.map(
                            (m) => html`
                              <tr>
                                <td class="mono muted" style="word-break:break-all">${m.name}</td>
                                <td class="mono" style="text-align:right; font-weight:600">${m.value}</td>
                              </tr>
                            `,
                          )}
                        </tbody>
                      </table>
                    </div>
                  `}
          </div>
        </div>
      </div>
    `;
  }
}
