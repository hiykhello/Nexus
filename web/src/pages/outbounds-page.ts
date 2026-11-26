import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import {
  getLatencyTier,
  latencyBars,
  nexusApi,
  type OutboundGroup,
  type OutboundMember,
  type OutboundProbeResult,
} from '../api.ts';
import { icons } from '../icons.ts';
import { onLocaleChange, t } from '../i18n.ts';
import { appStore } from '../store.ts';
import { sharedStyles } from '../styles.ts';

type SortOrder = 'default' | 'latency' | 'name';

@customElement('nexus-outbounds-page')
export class NexusOutboundsPage extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .split {
        display: grid;
        grid-template-columns: 240px 1fr;
        gap: 14px;
        align-items: start;
      }
      @media (max-width: 820px) {
        .split {
          grid-template-columns: 1fr;
        }
      }
      .rail {
        display: flex;
        flex-direction: column;
        gap: 6px;
      }
      .rail-item {
        width: 100%;
        text-align: left;
        display: flex;
        flex-direction: column;
        align-items: stretch;
        gap: 5px;
        padding: 10px 12px;
        border-radius: 10px;
        background: var(--nx-well);
        border: 1px solid var(--nx-border);
      }
      .rail-item.active {
        background: var(--nx-accent-soft);
        border-color: var(--nx-accent-border);
      }
      .node-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(225px, 1fr));
        gap: 10px;
        margin-top: 12px;
      }
      .node-card {
        display: flex;
        flex-direction: column;
        gap: 10px;
        padding: 12px;
        border-radius: 12px;
        background: var(--nx-well);
        border: 1px solid var(--nx-border);
        transition: border-color 120ms ease, background 120ms ease;
      }
      .node-card.switchable {
        cursor: pointer;
      }
      .node-card.switchable:hover {
        border-color: var(--nx-accent-border);
        background: var(--nx-row-hover);
      }
      .node-card.selected {
        border-color: var(--nx-accent);
        background: var(--nx-accent-soft);
      }
      .node-select-btn {
        border: none;
        background: transparent;
        padding: 0;
        color: var(--nx-text);
        font-size: 13.5px;
        font-weight: 700;
        text-align: left;
        justify-content: flex-start;
        max-width: 145px;
      }
      .node-select-btn:hover:not(:disabled) {
        background: transparent;
        color: var(--nx-accent-text, var(--nx-accent));
      }
      .node-select-btn:disabled {
        opacity: 1;
        cursor: default;
      }
      .bars {
        display: inline-flex;
        align-items: flex-end;
        gap: 2px;
        height: 12px;
      }
      .bars span {
        width: 3px;
        border-radius: 1px;
        background: var(--nx-inset);
      }
      .bars span.on {
        background: currentColor;
      }
    `,
  ];

  @state() private groups: OutboundGroup[] = [];
  @state() private activeGroup = '';
  @state() private search = '';
  @state() private sortOrder: SortOrder = 'default';
  @state() private busy = false;
  @state() private probingNodes = new Set<string>();
  @state() private liveProbes = new Map<string, OutboundProbeResult>();
  @state() private toast = '';
  @state() private toastKind: 'ok' | 'err' = 'ok';

  private unsubs: (() => void)[] = [];
  private probeRefreshTimer: ReturnType<typeof setTimeout> | null = null;

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
    if (this.probeRefreshTimer !== null) {
      clearTimeout(this.probeRefreshTimer);
      this.probeRefreshTimer = null;
    }
    for (const u of this.unsubs) u();
    this.unsubs = [];
  }

  private async refresh(): Promise<void> {
    try {
      const resp = await nexusApi.outbounds();
      this.groups = resp.groups ?? [];
      if (this.groups.length > 0 && !this.groups.some((g) => g.name === this.activeGroup)) {
        this.activeGroup = this.groups[0].name;
      }
    } catch (err) {
      this.toast = err instanceof Error ? err.message : String(err);
      this.toastKind = 'err';
    }
  }

  private async selectMember(group: string, member: string): Promise<void> {
    this.busy = true;
    try {
      await nexusApi.selectGroup(group, member);
      await this.refresh();
    } catch (err) {
      this.toast = err instanceof Error ? err.message : String(err);
      this.toastKind = 'err';
    } finally {
      this.busy = false;
    }
  }

  private async probeGroup(group: string): Promise<void> {
    this.busy = true;
    try {
      await nexusApi.probeGroup(group);
      this.toast = t('outbounds.groupProbed', { group });
      this.toastKind = 'ok';
      if (this.probeRefreshTimer !== null) clearTimeout(this.probeRefreshTimer);
      this.probeRefreshTimer = setTimeout(() => {
        this.probeRefreshTimer = null;
        if (this.isConnected) void this.refresh();
      }, 900);
    } catch (err) {
      this.toast = err instanceof Error ? err.message : String(err);
      this.toastKind = 'err';
    } finally {
      this.busy = false;
    }
  }

  private async probeNode(tag: string, ev: Event): Promise<void> {
    ev.stopPropagation();
    const nextSet = new Set(this.probingNodes);
    nextSet.add(tag);
    this.probingNodes = nextSet;
    try {
      const res = await nexusApi.probeOutbound(tag);
      const nextMap = new Map(this.liveProbes);
      nextMap.set(tag, res);
      this.liveProbes = nextMap;
      const rtt = res.latency_ms !== undefined && res.latency_ms !== null ? ` (${res.latency_ms} ms)` : '';
      this.toast = t('outbounds.nodeProbed', { node: tag, state: res.state, rtt });
      this.toastKind = res.state === 'up' ? 'ok' : 'err';
      void this.refresh();
    } catch (err) {
      this.toast = `${tag}: ${err instanceof Error ? err.message : String(err)}`;
      this.toastKind = 'err';
    } finally {
      const doneSet = new Set(this.probingNodes);
      doneSet.delete(tag);
      this.probingNodes = doneSet;
    }
  }

  private effectiveLatency(m: OutboundMember): number | null {
    const live = this.liveProbes.get(m.name);
    if (live && live.latency_ms !== undefined && live.latency_ms !== null) return live.latency_ms;
    return m.latency_ms ?? null;
  }

  private effectiveState(m: OutboundMember): string {
    return this.liveProbes.get(m.name)?.state ?? m.state;
  }

  private sortedMembers(members: OutboundMember[]): OutboundMember[] {
    const q = this.search.trim().toLowerCase();
    const filtered = q
      ? members.filter(
          (m) =>
            m.name.toLowerCase().includes(q) || this.effectiveState(m).toLowerCase().includes(q),
        )
      : [...members];
    if (this.sortOrder === 'name') {
      return filtered.sort((a, b) => a.name.localeCompare(b.name));
    }
    if (this.sortOrder === 'latency') {
      return filtered.sort((a, b) => {
        const la = this.effectiveLatency(a);
        const lb = this.effectiveLatency(b);
        return (la ?? 999999) - (lb ?? 999999);
      });
    }
    return filtered;
  }

  render() {
    const group = this.groups.find((g) => g.name === this.activeGroup) ?? this.groups[0] ?? null;
    const members = group ? this.sortedMembers(group.members) : [];
    const canProbeGroup =
      group !== null && group.mode !== 'select' && group.mode !== 'selector';
    const canSwitch =
      group !== null &&
      (group.mode === 'selector' || group.mode === 'select' || group.mode === 'url-test');

    return html`
      <div class="page">
        <div class="page-head">
          <h2>${t('outbounds.title')}</h2>
          <button class="sm" @click=${() => void this.refresh()} ?disabled=${this.busy}>
            ${icons.refresh()} ${t('common.refresh')}
          </button>
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

        ${this.groups.length === 0
          ? html`<div class="card empty-state">${t('outbounds.empty')}</div>`
          : html`
              <div class="split">
                <div class="card rail">
                  <div class="row between" style="margin-bottom:4px">
                    <h3>${t('outbounds.groups')}</h3>
                    <span class="badge">${this.groups.length}</span>
                  </div>
                  ${this.groups.map((g) => {
                    const upCount = g.members.filter((m) => m.state === 'up').length;
                    return html`
                      <button
                        class="rail-item ${g.name === group?.name ? 'active' : ''}"
                        @click=${() => (this.activeGroup = g.name)}
                      >
                        <div class="row between" style="width:100%">
                          <strong class="truncate">${g.name}</strong>
                          <span class="badge">${g.mode}</span>
                        </div>
                        <div class="row between muted" style="width:100%; font-size:11.5px">
                          <span class="truncate">${g.selected}</span>
                          <span class="tabular">${upCount}/${g.members.length}</span>
                        </div>
                      </button>
                    `;
                  })}
                </div>

                ${group
                  ? html`
                      <div class="card">
                        <div class="row between" style="gap:10px">
                          <div class="row">
                            <strong style="font-size:16px">${group.name}</strong>
                            <span class="badge accent">${group.mode}</span>
                            <span class="badge ok">${t('outbounds.selected')}: ${group.selected}</span>
                            ${group.override
                              ? html`<span class="badge warn">${t('outbounds.override')}</span>`
                              : ''}
                          </div>
                          <div class="row">
                            ${group.override
                              ? html`
                                  <button
                                    class="sm"
                                    ?disabled=${this.busy}
                                    @click=${() => void this.selectMember(group.name, '--auto')}
                                  >
                                    ${t('outbounds.resetAuto')}
                                  </button>
                                `
                              : ''}
                            ${canProbeGroup
                              ? html`
                                  <button
                                    class="primary sm"
                                    ?disabled=${this.busy}
                                    @click=${() => void this.probeGroup(group.name)}
                                  >
                                    ${icons.bolt()} ${t('outbounds.probeGroup')}
                                  </button>
                                `
                              : ''}
                          </div>
                        </div>

                        <div class="row" style="margin-top:12px">
                          <input
                            data-search-input
                            type="search"
                            style="flex:1; min-width:180px"
                            placeholder=${t('outbounds.search')}
                            .value=${this.search}
                            @input=${(e: Event) => (this.search = (e.target as HTMLInputElement).value)}
                          />
                          <select
                            aria-label=${t('outbounds.sortLabel')}
                            .value=${this.sortOrder}
                            @change=${(e: Event) =>
                              (this.sortOrder = (e.target as HTMLSelectElement).value as SortOrder)}
                          >
                            <option value="default">${t('outbounds.sort.default')}</option>
                            <option value="latency">${t('outbounds.sort.latency')}</option>
                            <option value="name">${t('outbounds.sort.name')}</option>
                          </select>
                        </div>

                        <div class="node-grid">
                          ${members.map((m) => {
                            const ms = this.effectiveLatency(m);
                            const st = this.effectiveState(m);
                            const tier = m.breaker_open ? 'down' : getLatencyTier(ms, st);
                            const bars = latencyBars(ms);
                            const probing = this.probingNodes.has(m.name);
                            const live = this.liveProbes.get(m.name);
                            const statusCode = live?.status_code ?? m.last_status;
                            const isSelected = m.name === group.selected;
                            return html`
                              <div
                                class="node-card ${isSelected ? 'selected' : ''} ${canSwitch ? 'switchable' : ''}"
                                @click=${() =>
                                  canSwitch && !this.busy && void this.selectMember(group.name, m.name)}
                              >
                                <div class="row between">
                                  <button
                                    type="button"
                                    class="node-select-btn truncate"
                                    title=${m.name}
                                    aria-pressed=${isSelected ? 'true' : 'false'}
                                    ?disabled=${!canSwitch || this.busy}
                                    @click=${(ev: Event) => {
                                      ev.stopPropagation();
                                      if (canSwitch) void this.selectMember(group.name, m.name);
                                    }}
                                  >
                                    ${m.name}
                                  </button>
                                  <span class="badge lat-${tier}">
                                    <span class="bars">
                                      ${[4, 7, 10, 12].map(
                                        (h, idx) =>
                                          html`<span
                                            class=${idx < bars ? 'on' : ''}
                                            style="height:${h}px"
                                          ></span>`,
                                      )}
                                    </span>
                                    ${m.breaker_open
                                      ? t('outbounds.breaker')
                                      : ms !== null
                                        ? `${ms} ms`
                                        : st === 'down'
                                          ? t('outbounds.down')
                                          : t('outbounds.unprobed')}
                                  </span>
                                </div>

                                <div class="row between">
                                  <div class="muted mono" style="font-size:11.5px">
                                    ${m.ewma_ms !== undefined ? `EWMA ${m.ewma_ms}ms` : st}
                                    ${statusCode !== undefined ? ` · HTTP ${statusCode}` : ''}
                                  </div>
                                  <button
                                    class="sm"
                                    ?disabled=${probing}
                                    @click=${(ev: Event) => void this.probeNode(m.name, ev)}
                                  >
                                    ${icons.bolt()}
                                    ${probing ? t('outbounds.probing') : t('outbounds.probeNode')}
                                  </button>
                                </div>
                              </div>
                            `;
                          })}
                        </div>
                      </div>
                    `
                  : ''}
              </div>
            `}
      </div>
    `;
  }
}
