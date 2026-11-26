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
import { renderThroughputChart, throughputChartStyles } from '../components/throughput-chart.ts';
import { renderTransitStrip, transitStripStyles } from '../components/transit-strip.ts';
import { icons } from '../icons.ts';
import { onLocaleChange, t } from '../i18n.ts';
import { appStore } from '../store.ts';
import { sharedStyles } from '../styles.ts';

@customElement('nexus-overview-page')
export class NexusOverviewPage extends LitElement {
  static styles = [
    sharedStyles,
    transitStripStyles,
    throughputChartStyles,
    css`
      .hero {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        justify-content: space-between;
        gap: 14px;
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
        border-radius: 8px;
        padding: 12px;
      }
      .group-tile select {
        width: 100%;
        background: var(--nx-surface);
      }
    `,
  ];

  @state() private groups: OutboundGroup[] = [];
  @state() private ruleCount = 0;
  @state() private busy = false;
  @state() private toast = '';
  @state() private toastKind: 'ok' | 'err' = 'ok';

  private unsubs: (() => void)[] = [];

  connectedCallback(): void {
    super.connectedCallback();
    this.groups = appStore.latestGroups;
    this.ruleCount = appStore.latestRules.length;
    this.unsubs.push(
      appStore.subscribe(() => {
        if (appStore.latestGroups.length > 0) this.groups = appStore.latestGroups;
        if (appStore.latestRules.length > 0) this.ruleCount = appStore.latestRules.length;
        this.requestUpdate();
      }, 'change'),
      appStore.subscribe(() => void this.refreshMeta(), 'refresh'),
      onLocaleChange(() => this.requestUpdate()),
    );
    void this.refreshMeta();
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

  private async refreshMeta(): Promise<void> {
    try {
      const [gRes, rRes] = await Promise.all([
        nexusApi.outbounds(),
        nexusApi.rules().catch(() => null),
      ]);
      this.groups = gRes.groups ?? [];
      appStore.setGroupsCache(this.groups);
      if (rRes?.rules) {
        this.ruleCount = rRes.rules.length;
        appStore.setRulesCache(rRes.rules);
      }
    } catch {
      // handled by store banner if unauthorized
    }
  }

  private async handleRefresh(): Promise<void> {
    this.busy = true;
    try {
      await Promise.all([appStore.refreshNow(), this.refreshMeta()]);
    } finally {
      this.busy = false;
    }
  }

  private async setMode(mode: RouteMode): Promise<void> {
    const prev = appStore.mode;
    appStore.setModeLocal({ mode, outbound: prev?.outbound ?? '' });
    this.busy = true;
    try {
      const res = await nexusApi.setMode(mode);
      appStore.setModeLocal(res);
      appStore.recordOnset(t(`overview.mode.${mode}`), 'mode');
      this.showToast(t('overview.modeUpdated', { mode: t(`overview.mode.${mode}`) }), 'ok');
    } catch (err) {
      if (prev) appStore.setModeLocal(prev);
      this.showToast(err instanceof Error ? err.message : String(err), 'err');
    } finally {
      this.busy = false;
    }
  }

  private async doReload(): Promise<void> {
    this.busy = true;
    try {
      await nexusApi.reload();
      appStore.recordOnset(t('chart.reloadLabel'), 'reload');
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
    const prev = this.groups;
    this.groups = prev.map((g) =>
      g.name === group
        ? { ...g, selected: member, override: g.mode === 'url-test' ? true : g.override }
        : g,
    );
    this.busy = true;
    try {
      await nexusApi.selectGroup(group, member);
      appStore.recordOnset(member, 'node');
      await this.refreshMeta();
    } catch (err) {
      this.groups = prev;
      this.showToast(err instanceof Error ? err.message : String(err), 'err');
    } finally {
      this.busy = false;
    }
  }

  render() {
    const st = appStore.status;
    const mode = (appStore.mode?.mode ?? 'rule') as RouteMode;
    const maxVal = Math.max(1024, ...appStore.history.map((h) => Math.max(h.up, h.down)));

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
                <span class="dot" style=${st ? 'background:var(--nx-signal)' : ''}></span>
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

        ${renderTransitStrip({
          status: st,
          mode: appStore.mode,
          groups: this.groups,
          ruleCount: this.ruleCount,
          downRate: appStore.downRate,
          upRate: appStore.upRate,
          streamState: appStore.streamState,
        })}

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
            <div class="muted tabular">${t('overview.mode')}: ${t(`overview.mode.${mode}`)}</div>
          </div>
          <div class="card kpi-card">
            <h3>${t('overview.peakCard')}</h3>
            <div class="metric">${formatRate(maxVal)}</div>
            <div class="muted mono truncate">
              ${appStore.mode?.outbound ? `→ ${appStore.mode.outbound}` : st?.instance ?? 'nexus'}
            </div>
          </div>
        </div>

        ${renderThroughputChart({
          history: appStore.history,
          onsetMarkers: appStore.onsetMarkers,
          downRate: appStore.downRate,
          upRate: appStore.upRate,
        })}

        <div class="card">
          <div class="row between">
            <h3>${t('overview.quickGroups')}</h3>
            <span class="muted tabular">${this.groups.length}</span>
          </div>
          ${this.groups.length === 0
            ? html`
                <div class="empty-state">
                  <span>${t('overview.noGroups')}</span>
                  <button class="sm" ?disabled=${this.busy} @click=${() => void this.handleRefresh()}>
                    ${icons.refresh()} ${t('common.refresh')}
                  </button>
                </div>
              `
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
                            ${active?.latency_ms !== undefined ? `${active.latency_ms} ms` : t('outbounds.unprobed')}
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
