import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import {
  createConnectionsStream,
  formatBytes,
  formatDuration,
  nexusApi,
  type ConnectionItem,
  type StreamState,
} from '../api.ts';
import { icons } from '../icons.ts';
import { onLocaleChange, t } from '../i18n.ts';
import type { ManagedStream } from '../sse.ts';
import { appStore } from '../store.ts';
import { sharedStyles } from '../styles.ts';
import { connectionDrawerStyles, renderConnectionDrawer } from './connection-drawer.ts';

type ConnSort = 'bytes' | 'down' | 'up' | 'duration' | 'newest';

@customElement('nexus-connections-page')
export class NexusConnectionsPage extends LitElement {
  static styles = [
    sharedStyles,
    connectionDrawerStyles,
    css`
      .target-cell {
        max-width: 260px;
      }
      .traffic-bar {
        display: flex;
        height: 2px;
        width: 100%;
        margin-top: 3px;
        border-radius: 1px;
        background: var(--nx-inset);
        overflow: hidden;
      }
      .traffic-bar span {
        height: 100%;
        flex-shrink: 0;
      }
    `,
  ];

  @state() private connections: ConnectionItem[] = [];
  @state() private detail: ConnectionItem | null = null;
  @state() private search = '';
  @state() private protoFilter = 'all';
  @state() private sortBy: ConnSort = 'bytes';
  @state() private paused = false;
  @state() private streamState: StreamState = 'connecting';
  @state() private confirmMode: 'none' | 'all' | 'filtered' = 'none';
  @state() private toast = '';
  @state() private toastKind: 'ok' | 'err' = 'ok';

  private stream: ManagedStream<ConnectionItem[]> | null = null;
  private unsubs: (() => void)[] = [];

  connectedCallback(): void {
    super.connectedCallback();
    if (appStore.latestConnections.length > 0) {
      this.connections = appStore.latestConnections;
    }
    this.unsubs.push(
      appStore.acquireChannel('connections'),
      appStore.onWsConnections((items) => {
        if (!this.paused) this.connections = items;
      }),
      appStore.subscribe(() => this.syncTransport(), 'transport-change'),
      appStore.subscribe(() => this.requestUpdate(), 'change'),
      appStore.subscribe(() => void this.refreshOnce(), 'refresh'),
      onLocaleChange(() => this.requestUpdate()),
    );
    this.syncTransport();
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    this.stream?.stop();
    this.stream = null;
    for (const u of this.unsubs) u();
    this.unsubs = [];
  }

  private syncTransport(): void {
    if (appStore.wsLive || appStore.authRequired) {
      this.stream?.stop();
      this.stream = null;
      this.streamState = appStore.authRequired ? 'unauthorized' : 'live';
      return;
    }
    if (appStore.shouldUseSseFallback) {
      if (!this.stream) this.startStream();
    } else {
      this.streamState = 'connecting';
    }
  }

  private startStream(): void {
    this.stream?.stop();
    this.stream = createConnectionsStream(
      (items) => {
        if (!this.paused) this.connections = items;
      },
      (st) => (this.streamState = st),
      (err) => {
        this.toast = err;
        this.toastKind = 'err';
      },
      2000,
    );
    this.stream.start();
  }

  private async refreshOnce(): Promise<void> {
    try {
      const resp = await nexusApi.connections();
      this.connections = resp.connections ?? [];
    } catch (err) {
      this.toast = err instanceof Error ? err.message : String(err);
      this.toastKind = 'err';
    }
  }

  private togglePause(): void {
    this.paused = !this.paused;
    if (!this.paused) void this.refreshOnce();
  }

  private async inspect(id: string): Promise<void> {
    try {
      this.detail = await nexusApi.connectionDetail(id);
    } catch (err) {
      this.toast = err instanceof Error ? err.message : String(err);
      this.toastKind = 'err';
    }
  }

  private async closeOne(id: string, ev: Event): Promise<void> {
    ev.stopPropagation();
    try {
      await nexusApi.closeConnection(id);
      if (this.detail?.id === id) this.detail = null;
      await this.refreshOnce();
    } catch (err) {
      this.toast = err instanceof Error ? err.message : String(err);
      this.toastKind = 'err';
    }
  }

  private async closeAll(): Promise<void> {
    this.confirmMode = 'none';
    try {
      const res = await nexusApi.closeAllConnections();
      this.detail = null;
      this.toast = t('connections.closedCount', { count: res.closed ?? 0 });
      this.toastKind = 'ok';
      await this.refreshOnce();
    } catch (err) {
      this.toast = err instanceof Error ? err.message : String(err);
      this.toastKind = 'err';
    }
  }

  private async closeFiltered(list: ConnectionItem[]): Promise<void> {
    this.confirmMode = 'none';
    const closable = list.filter((c) => c.can_close);
    let closed = 0;
    await Promise.all(
      closable.map(async (c) => {
        try {
          await nexusApi.closeConnection(c.id);
          closed++;
        } catch {
          // ignore already closed
        }
      }),
    );
    this.detail = null;
    this.toast = t('connections.closedCount', { count: closed });
    this.toastKind = 'ok';
    await this.refreshOnce();
  }

  private outboundBadgeClass(outbound: string): string {
    const o = outbound.toLowerCase();
    if (o === 'reject' || o === 'block') return 'err';
    if (o === 'direct') return 'ok';
    return 'accent';
  }

  private filteredList(): ConnectionItem[] {
    const q = this.search.trim().toLowerCase();
    const list = this.connections.filter((c) => {
      if (this.protoFilter !== 'all' && c.protocol.toLowerCase() !== this.protoFilter) return false;
      if (!q) return true;
      const hay = [
        c.id,
        c.inbound ?? '',
        c.protocol,
        c.path,
        c.source ?? '',
        c.target ?? '',
        c.outbound ?? '',
        c.route_rule ?? '',
        c.process_path ?? '',
        String(c.destination_port),
      ]
        .join(' ')
        .toLowerCase();
      return hay.includes(q);
    });

    const num = (v: string) => Number(v || 0);
    return list.sort((a, b) => {
      if (this.sortBy === 'down') return num(b.download_bytes) - num(a.download_bytes);
      if (this.sortBy === 'up') return num(b.upload_bytes) - num(a.upload_bytes);
      if (this.sortBy === 'duration') return b.duration_ms - a.duration_ms;
      if (this.sortBy === 'newest') return Number(b.id) - Number(a.id);
      return (
        num(b.upload_bytes) + num(b.download_bytes) - (num(a.upload_bytes) + num(a.download_bytes))
      );
    });
  }

  render() {
    const list = this.filteredList();
    const maxBytes = Math.max(
      1,
      ...list.map((c) => Number(c.upload_bytes || 0) + Number(c.download_bytes || 0)),
    );
    const protos = Array.from(
      new Set(['tcp', 'udp', ...this.connections.map((c) => c.protocol.toLowerCase())]),
    );
    const hasFilter = this.search.trim().length > 0 || this.protoFilter !== 'all';
    const activeState: StreamState = appStore.wsLive ? 'live' : this.streamState;
    const streamBadgeClass =
      activeState === 'live'
        ? 'ok'
        : activeState === 'polling' || activeState === 'connecting'
          ? 'warn'
          : 'err';
    const streamLabel =
      activeState === 'live' && appStore.wsLive ? t('stream.liveWs') : t(`stream.${activeState}`);

    return html`
      <div class="page">
        <div class="page-head">
          <div class="row">
            <h2>${t('connections.title')}</h2>
            <span class="muted tabular">${list.length} / ${this.connections.length}</span>
            <span class="badge ${streamBadgeClass}">
              <span class="dot"></span>${streamLabel}
            </span>
          </div>
          <div class="row">
            <button class="sm" @click=${() => this.togglePause()}>
              ${this.paused ? icons.play() : icons.pause()}
              ${this.paused ? t('common.resume') : t('common.pause')}
            </button>
            <button class="sm" @click=${() => void this.refreshOnce()}>
              ${icons.refresh()} ${t('common.refresh')}
            </button>
            ${this.confirmMode === 'all'
              ? html`
                  <button class="danger sm" @click=${() => void this.closeAll()}>
                    ${t('connections.confirmAll', { count: this.connections.length })}
                  </button>
                  <button class="sm" @click=${() => (this.confirmMode = 'none')}>
                    ${t('common.cancel')}
                  </button>
                `
              : this.confirmMode === 'filtered'
                ? html`
                    <button class="danger sm" @click=${() => void this.closeFiltered(list)}>
                      ${t('connections.confirmFiltered', { count: list.length })}
                    </button>
                    <button class="sm" @click=${() => (this.confirmMode = 'none')}>
                      ${t('common.cancel')}
                    </button>
                  `
                : html`
                    ${hasFilter && list.length > 0
                      ? html`
                          <button class="danger sm" @click=${() => (this.confirmMode = 'filtered')}>
                            ${t('connections.closeFiltered', { count: list.length })}
                          </button>
                        `
                      : ''}
                    <button
                      class="danger sm"
                      ?disabled=${this.connections.length === 0}
                      @click=${() => (this.confirmMode = 'all')}
                    >
                      ${icons.trash()} ${t('connections.closeAll')}
                    </button>
                  `}
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

        <div class="card col" style="gap:10px">
          <div class="row">
            <input
              data-search-input
              type="search"
              aria-label=${t('connections.search')}
              spellcheck="false"
              autocapitalize="none"
              autocorrect="off"
              style="flex:1; min-width:220px"
              placeholder=${t('connections.search')}
              .value=${this.search}
              @input=${(e: Event) => (this.search = (e.target as HTMLInputElement).value)}
            />
            <select
              aria-label=${t('connections.sortLabel')}
              .value=${this.sortBy}
              @change=${(e: Event) => (this.sortBy = (e.target as HTMLSelectElement).value as ConnSort)}
            >
              <option value="bytes">${t('connections.sort.bytes')}</option>
              <option value="down">${t('connections.sort.down')}</option>
              <option value="up">${t('connections.sort.up')}</option>
              <option value="duration">${t('connections.sort.duration')}</option>
              <option value="newest">${t('connections.sort.newest')}</option>
            </select>
          </div>
          <div class="row">
            <button
              class="chip ${this.protoFilter === 'all' ? 'active' : ''}"
              @click=${() => (this.protoFilter = 'all')}
            >
              ${t('common.all')}
            </button>
            ${protos.map(
              (p) => html`
                <button
                  class="chip ${this.protoFilter === p ? 'active' : ''}"
                  @click=${() => (this.protoFilter = p)}
                >
                  ${p.toUpperCase()}
                </button>
              `,
            )}
          </div>
        </div>

        ${renderConnectionDrawer(this.detail, {
          onCloseConn: (id, ev) => void this.closeOne(id, ev),
          onDismiss: () => (this.detail = null),
        })}

        <div class="card table-wrap" style="padding:8px 12px">
          <table>
            <thead>
              <tr>
                <th>${t('connections.col.id')}</th>
                <th>${t('connections.col.inbound')}</th>
                <th>${t('connections.col.target')}</th>
                <th>${t('connections.col.outbound')}</th>
                <th>${t('connections.col.rule')}</th>
                <th class="num-col">${t('connections.col.traffic')}</th>
                <th class="num-col">${t('connections.col.duration')}</th>
                <th>${t('connections.col.action')}</th>
              </tr>
            </thead>
            <tbody>
              ${list.length === 0
                ? html`
                    <tr>
                      <td colspan="8">
                        <div class="empty-state">
                          <span>${t('connections.empty')}</span>
                          ${hasFilter
                            ? html`<button class="sm" @click=${() => { this.search = ''; this.protoFilter = 'all'; }}>${t('common.clearFilters')}</button>`
                            : html`<button class="sm" @click=${() => void this.refreshOnce()}>${icons.refresh()} ${t('common.refresh')}</button>`}
                        </div>
                      </td>
                    </tr>
                  `
                : list.map(
                    (c) => html`
                      <tr
                        class="clickable ${this.detail?.id === c.id ? 'selected' : ''}"
                        tabindex="0"
                        @click=${() => void this.inspect(c.id)}
                        @keydown=${(e: KeyboardEvent) => {
                          if (e.target === e.currentTarget && (e.key === 'Enter' || e.key === ' ')) {
                            e.preventDefault();
                            void this.inspect(c.id);
                          }
                        }}
                      >
                        <td class="mono muted">#${c.id}</td>
                        <td>
                          <span>${c.inbound || '-'}</span>
                          <span class="badge">${c.protocol.toUpperCase()}</span>
                        </td>
                        <td class="mono target-cell truncate" title=${c.target || `:${c.destination_port}`}>
                          ${c.target || `:${c.destination_port}`}
                        </td>
                        <td>
                          <span class="badge ${this.outboundBadgeClass(c.outbound || c.path)}">
                            ${c.outbound || c.path}
                          </span>
                        </td>
                        <td class="mono muted">${c.route_rule || '-'}</td>
                        <td class="mono num-col">
                          <span style="color:var(--nx-up)">↑<span class="rate-slot">${formatBytes(c.upload_bytes)}</span></span>
                          /
                          <span style="color:var(--nx-down)">↓<span class="rate-slot">${formatBytes(c.download_bytes)}</span></span>
                          <div class="traffic-bar" aria-hidden="true">
                            <span
                              style="width:${((Number(c.upload_bytes || 0) / maxBytes) * 100).toFixed(1)}%;background:var(--nx-up)"
                            ></span>
                            <span
                              style="width:${((Number(c.download_bytes || 0) / maxBytes) * 100).toFixed(1)}%;background:var(--nx-down)"
                            ></span>
                          </div>
                        </td>
                        <td class="mono muted num-col">${formatDuration(c.duration_ms)}</td>
                        <td>
                          <button
                            class="danger sm"
                            ?disabled=${!c.can_close}
                            @click=${(e: Event) => void this.closeOne(c.id, e)}
                          >
                            ${t('connections.closeOne')}
                          </button>
                        </td>
                      </tr>
                    `,
                  )}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }
}
