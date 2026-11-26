import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import {
  nexusApi,
  type OutboundGroup,
  type OutboundMember,
  type OutboundProbeResult,
} from '../api.ts';
import {
  computeGroupSpectrum,
  latencySpectrumStyles,
  renderLatencySpectrum,
} from '../components/latency-spectrum.ts';
import { icons } from '../icons.ts';
import { onLocaleChange, t } from '../i18n.ts';
import { appStore } from '../store.ts';
import { sharedStyles } from '../styles.ts';
import { nodeCardStyles, renderOutboundNodeCard } from './outbound-node-card.ts';

type SortOrder = 'default' | 'latency' | 'name';

@customElement('nexus-outbounds-page')
export class NexusOutboundsPage extends LitElement {
  static styles = [
    sharedStyles,
    latencySpectrumStyles,
    nodeCardStyles,
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
        border-radius: 8px;
        background: var(--nx-well);
        border: 1px solid transparent;
        transition:
          background 120ms ease-out,
          border-color 120ms ease-out,
          transform 120ms cubic-bezier(0.23, 1, 0.32, 1);
      }
      .rail-item:active {
        transform: scale(0.98);
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
      @media (hover: hover) and (pointer: fine) {
        .rail-item:hover:not(.active) {
          background: var(--nx-row-hover);
        }
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
      appStore.setGroupsCache(this.groups);
      if (this.groups.length > 0 && !this.groups.some((g) => g.name === this.activeGroup)) {
        this.activeGroup = this.groups[0].name;
      }
    } catch (err) {
      this.toast = err instanceof Error ? err.message : String(err);
      this.toastKind = 'err';
    }
  }

  private async selectMember(group: string, member: string): Promise<void> {
    const prev = this.groups;
    this.groups = prev.map((g) => {
      if (g.name !== group) return g;
      if (member === '--auto') return { ...g, override: false };
      return { ...g, selected: member, override: g.mode === 'url-test' ? true : g.override };
    });
    this.busy = true;
    try {
      await nexusApi.selectGroup(group, member);
      appStore.recordOnset(member === '--auto' ? 'Auto' : member, 'node');
      await this.refresh();
    } catch (err) {
      this.groups = prev;
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

  private async probeNode(tag: string): Promise<void> {
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
    const activeSpectrum = group
      ? computeGroupSpectrum(group.members, (m) => this.effectiveLatency(m), (m) => this.effectiveState(m))
      : null;
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
          ? html`
              <div class="card empty-state">
                <span>${t('outbounds.empty')}</span>
                <button class="sm" ?disabled=${this.busy} @click=${() => void this.refresh()}>
                  ${icons.refresh()} ${t('common.refresh')}
                </button>
              </div>
            `
          : html`
              <div class="split">
                <div class="card rail">
                  <div class="row between" style="margin-bottom:4px">
                    <h3>${t('outbounds.groups')}</h3>
                    <span class="muted tabular">${this.groups.length}</span>
                  </div>
                  ${this.groups.map((g) => {
                    const upCount = g.members.filter((m) => m.state === 'up').length;
                    const gSpec = computeGroupSpectrum(g.members);
                    return html`
                      <button
                        class="rail-item ${g.name === group?.name ? 'active' : ''}"
                        @click=${() => (this.activeGroup = g.name)}
                      >
                        <div class="row between" style="width:100%">
                          <strong class="truncate">${g.name}</strong>
                          <span class="muted mono" style="font-size:11px">${g.mode}</span>
                        </div>
                        <div class="row between muted" style="width:100%; font-size:11.5px">
                          <span class="truncate">${g.selected}</span>
                          <span class="tabular">${upCount}/${g.members.length}</span>
                        </div>
                        ${renderLatencySpectrum(gSpec, { compact: true })}
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
                            <span class="muted mono">${group.mode}</span>
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

                        <div style="margin-top:8px">
                          ${renderLatencySpectrum(activeSpectrum, { showP50: true })}
                        </div>

                        <div class="row" style="margin-top:12px">
                          <input
                            data-search-input
                            type="search"
                            aria-label=${t('outbounds.search')}
                            spellcheck="false"
                            autocapitalize="none"
                            autocorrect="off"
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

                        ${members.length === 0
                          ? html`
                              <div class="empty-state">
                                <span>${t('outbounds.noMatch')}</span>
                                ${this.search.trim()
                                  ? html`<button class="sm" @click=${() => (this.search = '')}>${t('common.clearFilters')}</button>`
                                  : html`<button class="sm" @click=${() => void this.refresh()}>${icons.refresh()} ${t('common.refresh')}</button>`}
                              </div>
                            `
                          : html`
                              <div class="node-grid">
                                ${members.map((m) =>
                                  renderOutboundNodeCard({
                                    member: m,
                                    liveProbe: this.liveProbes.get(m.name),
                                    maxHealthy: activeSpectrum?.maxHealthy ?? 0,
                                    selected: m.name === group.selected,
                                    canSwitch,
                                    busy: this.busy,
                                    probing: this.probingNodes.has(m.name),
                                    onSelect: () => void this.selectMember(group.name, m.name),
                                    onProbe: (ev: Event) => {
                                      ev.stopPropagation();
                                      void this.probeNode(m.name);
                                    },
                                  }),
                                )}
                              </div>
                            `}
                      </div>
                    `
                  : ''}
              </div>
            `}
      </div>
    `;
  }
}
