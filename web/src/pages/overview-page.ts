import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import {
  formatBytes,
  formatRate,
  getLatencyTier,
  nexusApi,
  type OutboundGroup,
  type RouteMode,
} from '../api.ts';
import { icons } from '../icons.ts';
import { onLocaleChange, t } from '../i18n.ts';
import { appStore } from '../store.ts';
import { sharedStyles } from '../styles.ts';

@customElement('nexus-overview-page')
export class NexusOverviewPage extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .hero {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        justify-content: space-between;
        gap: 14px;
        background:
          radial-gradient(circle at top right, var(--nx-accent-soft), transparent 55%),
          var(--nx-surface-grad, var(--nx-surface));
      }
      .hero-title {
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 20px;
        font-weight: 700;
      }
      .kpi-card {
        display: flex;
        flex-direction: column;
        gap: 6px;
      }
      .kpi-down {
        color: var(--nx-down);
      }
      .kpi-up {
        color: var(--nx-up);
      }
      .spark-wrap {
        position: relative;
        margin-top: 10px;
        background: var(--nx-well);
        border: 1px solid var(--nx-border);
        border-radius: 10px;
        padding: 10px 8px 4px;
      }
      .spark {
        width: 100%;
        height: 112px;
        display: block;
      }
      .legend {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 14px;
        font-size: 12px;
        color: var(--nx-text-secondary);
      }
      .legend-item {
        display: inline-flex;
        align-items: center;
        gap: 6px;
      }
      .swatch {
        width: 9px;
        height: 9px;
        border-radius: 50%;
      }
      .group-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
        gap: 10px;
        margin-top: 10px;
      }
      .group-tile {
        display: flex;
        flex-direction: column;
        gap: 8px;
        background: var(--nx-well);
        border: 1px solid var(--nx-border);
        border-radius: 10px;
        padding: 12px;
      }
      .group-tile select {
        width: 100%;
        background: var(--nx-surface);
      }
    `,
  ];

  @state() private groups: OutboundGroup[] = [];
  @state() private busy = false;
  @state() private toast = '';
  @state() private toastKind: 'ok' | 'err' = 'ok';

  private unsubs: (() => void)[] = [];

  connectedCallback(): void {
    super.connectedCallback();
    this.unsubs.push(
      appStore.subscribe(() => this.requestUpdate(), 'change'),
      appStore.subscribe(() => void this.refreshGroups(), 'refresh'),
      onLocaleChange(() => this.requestUpdate()),
    );
    void this.refreshGroups();
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    for (const u of this.unsubs) u();
    this.unsubs = [];
  }

  private showToast(msg: string, kind: 'ok' | 'err' = 'ok'): void {
    this.toast = msg;
    this.toastKind = kind;
  }

  private async refreshGroups(): Promise<void> {
    try {
      const resp = await nexusApi.outbounds();
      this.groups = resp.groups ?? [];
    } catch {
      // handled by store banner if unauthorized
    }
  }

  private async handleRefresh(): Promise<void> {
    this.busy = true;
    try {
      await Promise.all([appStore.refreshNow(), this.refreshGroups()]);
    } finally {
      this.busy = false;
    }
  }

  private async setMode(mode: RouteMode): Promise<void> {
    this.busy = true;
    try {
      const res = await nexusApi.setMode(mode);
      appStore.setModeLocal(res);
      this.showToast(t('overview.modeUpdated', { mode: t(`overview.mode.${mode}`) }), 'ok');
    } catch (err) {
      this.showToast(err instanceof Error ? err.message : String(err), 'err');
    } finally {
      this.busy = false;
    }
  }

  private async doReload(): Promise<void> {
    this.busy = true;
    try {
      await nexusApi.reload();
      this.showToast(t('overview.reloaded'), 'ok');
      await appStore.refreshNow();
    } catch (err) {
      this.showToast(err instanceof Error ? err.message : String(err), 'err');
    } finally {
      this.busy = false;
    }
  }

  private async doFlushFakeip(): Promise<void> {
    this.busy = true;
    try {
      const res = await nexusApi.flushFakeIp();
      this.showToast(t('overview.flushedFakeip', { count: res.flushed }), 'ok');
    } catch (err) {
      this.showToast(err instanceof Error ? err.message : String(err), 'err');
    } finally {
      this.busy = false;
    }
  }

  private async doClearDns(): Promise<void> {
    this.busy = true;
    try {
      await nexusApi.clearCache('dns');
      this.showToast(t('overview.clearedDns'), 'ok');
    } catch (err) {
      this.showToast(err instanceof Error ? err.message : String(err), 'err');
    } finally {
      this.busy = false;
    }
  }

  private async quickSelect(group: string, member: string): Promise<void> {
    this.busy = true;
    try {
      await nexusApi.selectGroup(group, member);
      await this.refreshGroups();
    } catch (err) {
      this.showToast(err instanceof Error ? err.message : String(err), 'err');
    } finally {
      this.busy = false;
    }
  }

  private sparkPoints(key: 'up' | 'down', maxVal: number): string {
    const pts = appStore.history;
    if (pts.length < 2) return '';
    return pts
      .map((pt, idx) => {
        const x = (idx / Math.max(1, pts.length - 1)) * 400;
        const y = 98 - (pt[key] / maxVal) * 86;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ');
  }

  private sparkArea(key: 'up' | 'down', maxVal: number): string {
    const line = this.sparkPoints(key, maxVal);
    if (!line) return '';
    return `0,104 ${line} 400,104`;
  }

  render() {
    const st = appStore.status;
    const mode = (appStore.mode?.mode ?? 'rule') as RouteMode;
    const maxVal = Math.max(1024, ...appStore.history.map((h) => Math.max(h.up, h.down)));
    const downPts = this.sparkPoints('down', maxVal);
    const upPts = this.sparkPoints('up', maxVal);

    return html`
      <div class="page">
        <div class="page-head">
          <h2>${t('overview.title')}</h2>
          <div class="row">
            <button class="sm" @click=${() => void this.handleRefresh()} ?disabled=${this.busy}>
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

        <div class="card hero">
          <div class="col" style="gap:6px">
            <div class="hero-title">
              <span class="badge ${st ? 'ok' : 'err'}">
                <span class="dot"></span>
                ${st ? t('overview.heroRunning') : t(`stream.${appStore.streamState}`)}
              </span>
              <span class="mono" style="font-size:15px">${st?.instance ?? 'nexus'}</span>
            </div>
            <div class="row muted mono">
              <span>${t('overview.gen')} #${st?.control_generation ?? '0'}</span>
              <span>·</span>
              <span>${t('overview.listeners')}: ${st?.listeners ?? 0}</span>
              <span>·</span>
              <span>${t('overview.workers')}: ${st?.workers ?? 0}</span>
              ${appStore.mode?.outbound
                ? html`<span>·</span><span>global → ${appStore.mode.outbound}</span>`
                : ''}
            </div>
          </div>

          <div class="row">
            <div class="segmented" role="group" aria-label=${t('overview.mode')}>
              ${(['rule', 'global', 'direct'] as RouteMode[]).map(
                (m) => html`
                  <button
                    class=${mode === m ? 'active' : ''}
                    aria-pressed=${mode === m ? 'true' : 'false'}
                    ?disabled=${this.busy}
                    @click=${() => void this.setMode(m)}
                  >
                    ${t(`overview.mode.${m}`)}
                  </button>
                `,
              )}
            </div>
            <button class="sm" ?disabled=${this.busy} @click=${() => void this.doFlushFakeip()}>
              ${t('overview.flushFakeip')}
            </button>
            <button class="sm" ?disabled=${this.busy} @click=${() => void this.doClearDns()}>
              ${t('overview.clearDns')}
            </button>
            <button class="primary sm" ?disabled=${this.busy} @click=${() => void this.doReload()}>
              ${icons.refresh()} ${t('overview.reload')}
            </button>
          </div>
        </div>

        <div class="bento-grid">
          <div class="card kpi-card">
            <h3>${t('overview.download')}</h3>
            <div class="metric kpi-down">${formatRate(appStore.downRate)}</div>
            <div class="muted tabular">${t('overview.total')} ${formatBytes(st?.download_bytes_total ?? 0)}</div>
          </div>
          <div class="card kpi-card">
            <h3>${t('overview.upload')}</h3>
            <div class="metric kpi-up">${formatRate(appStore.upRate)}</div>
            <div class="muted tabular">${t('overview.total')} ${formatBytes(st?.upload_bytes_total ?? 0)}</div>
          </div>
          <div class="card kpi-card">
            <h3>${t('overview.sessions')}</h3>
            <div class="metric">${st?.active_sessions ?? 0}</div>
            <div class="muted tabular">${t('overview.listeners')}: ${st?.listeners ?? 0}</div>
          </div>
          <div class="card kpi-card">
            <h3>${t('overview.controlGen')}</h3>
            <div class="metric">#${st?.control_generation ?? '0'}</div>
            <div class="muted tabular">${t('overview.workers')}: ${st?.workers ?? 0}</div>
          </div>
        </div>

        <div class="card">
          <div class="row between">
            <h3>${t('overview.throughput')}</h3>
            <div class="legend tabular">
              <span class="legend-item">
                <span class="swatch" style="background:var(--nx-down)"></span>
                ${t('overview.download')} ${formatRate(appStore.downRate)}
              </span>
              <span class="legend-item">
                <span class="swatch" style="background:var(--nx-up)"></span>
                ${t('overview.upload')} ${formatRate(appStore.upRate)}
              </span>
              <span class="badge">${t('overview.peak')} ${formatRate(maxVal)}</span>
            </div>
          </div>
          <div class="spark-wrap">
            <svg class="spark" viewBox="0 0 400 104" preserveAspectRatio="none">
              <defs>
                <linearGradient id="nx-down-grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="var(--nx-down)" stop-opacity="0.28" />
                  <stop offset="100%" stop-color="var(--nx-down)" stop-opacity="0.01" />
                </linearGradient>
                <linearGradient id="nx-up-grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="var(--nx-up)" stop-opacity="0.22" />
                  <stop offset="100%" stop-color="var(--nx-up)" stop-opacity="0.01" />
                </linearGradient>
              </defs>
              <line x1="0" y1="34" x2="400" y2="34" stroke="var(--nx-border)" stroke-dasharray="3 4" />
              <line x1="0" y1="68" x2="400" y2="68" stroke="var(--nx-border)" stroke-dasharray="3 4" />
              ${downPts
                ? html`
                    <polygon fill="url(#nx-down-grad)" points=${this.sparkArea('down', maxVal)}></polygon>
                    <polyline fill="none" stroke="var(--nx-down)" stroke-width="2" points=${downPts}></polyline>
                  `
                : ''}
              ${upPts
                ? html`
                    <polygon fill="url(#nx-up-grad)" points=${this.sparkArea('up', maxVal)}></polygon>
                    <polyline fill="none" stroke="var(--nx-up)" stroke-width="2" points=${upPts}></polyline>
                  `
                : ''}
            </svg>
          </div>
        </div>

        <div class="card">
          <div class="row between">
            <h3>${t('overview.quickGroups')}</h3>
            <span class="badge">${this.groups.length}</span>
          </div>
          ${this.groups.length === 0
            ? html`<div class="empty-state">${t('overview.noGroups')}</div>`
            : html`
                <div class="group-grid">
                  ${this.groups.map((g) => {
                    const active = g.members.find((m) => m.name === g.selected);
                    const tier = getLatencyTier(active?.latency_ms, active?.state);
                    const canSwitch = g.mode === 'selector' || g.mode === 'select' || g.mode === 'url-test';
                    return html`
                      <div class="group-tile">
                        <div class="row between">
                          <strong class="truncate">${g.name}</strong>
                          <span class="badge lat-${tier}">
                            ${active?.latency_ms !== undefined ? `${active.latency_ms} ms` : g.mode}
                          </span>
                        </div>
                        <div class="row between muted" style="font-size:11.5px">
                          <span>${g.mode}</span>
                          ${g.override ? html`<span class="badge warn">${t('outbounds.override')}</span>` : ''}
                        </div>
                        <select
                          aria-label=${g.name}
                          .value=${g.selected}
                          ?disabled=${this.busy || !canSwitch}
                          @change=${(e: Event) =>
                            void this.quickSelect(g.name, (e.target as HTMLSelectElement).value)}
                        >
                          ${g.members.map(
                            (m) => html`
                              <option value=${m.name} ?selected=${m.name === g.selected}>
                                ${m.name}${m.latency_ms !== undefined ? ` (${m.latency_ms}ms)` : ''}
                              </option>
                            `,
                          )}
                        </select>
                      </div>
                    `;
                  })}
                </div>
              `}
        </div>
      </div>
    `;
  }
}
