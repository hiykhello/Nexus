import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import {
  createLogsStream,
  formatTimestampNs,
  nexusApi,
  type LogEntry,
  type StreamState,
} from '../api.ts';
import { icons } from '../icons.ts';
import { onLocaleChange, t } from '../i18n.ts';
import type { ManagedStream } from '../sse.ts';
import { appStore } from '../store.ts';
import { sharedStyles } from '../styles.ts';
import {
  LOG_DOMAINS,
  LOG_LEVELS,
  countLogSeverities,
  formatLogPlainLines,
  levelBadgeClass,
  matchesLogFilters,
} from './log-helpers.ts';

const MAX_ENTRIES = 600;

@customElement('nexus-logs-page')
export class NexusLogsPage extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .log-box {
        max-height: 60dvh;
        min-height: 280px;
        overflow-y: auto;
        overscroll-behavior: contain;
        display: flex;
        flex-direction: column;
        gap: 2px;
        background: var(--nx-well);
        border-radius: 8px;
        padding: 8px;
      }
      .log-line {
        display: grid;
        grid-template-columns: 62px 68px 64px 72px 1fr;
        gap: 8px;
        align-items: baseline;
        padding: 4px 8px;
        border-radius: 6px;
        line-height: 1.45;
      }
      .log-line.lvl-error,
      .log-line.lvl-fatal { background: var(--nx-err-bg); }
      .log-line.lvl-warn { background: var(--nx-warn-bg); }
      .sev-bar {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        padding: 0 2px 8px;
      }
      @media (hover: hover) and (pointer: fine) {
        .log-line:hover { background: var(--nx-row-hover); }
      }
      .msg { word-break: break-word; }
      @media (max-width: 720px) {
        .log-line { grid-template-columns: 56px 56px 1fr; }
        .hide-sm { display: none; }
      }
    `,
  ];

  @state() private entries: LogEntry[] = [];
  @state() private latestSeq = 0;
  @state() private evicted = 0;
  @state() private level = 'all';
  @state() private domain = 'all';
  @state() private search = '';
  @state() private paused = false;
  @state() private autoScroll = true;
  @state() private streamState: StreamState = 'connecting';
  @state() private copied = false;
  @state() private toast = '';
  @state() private toastKind: 'ok' | 'err' = 'ok';

  private stream: ManagedStream<LogEntry> | null = null;
  private releaseLogsChannel: (() => void) | null = null;
  private seenSeq = new Set<number>();
  private reloadToken = 0;
  private unsubs: (() => void)[] = [];
  private searchTimer: ReturnType<typeof setTimeout> | null = null;

  connectedCallback(): void {
    super.connectedCallback();
    this.unsubs.push(
      appStore.onWsLog((entry) => {
        if (
          !this.paused &&
          entry.seq > this.latestSeq &&
          matchesLogFilters(entry, this.level, this.domain, this.search)
        ) {
          this.appendEntry(entry);
        }
      }),
      appStore.subscribe(() => this.syncTransport(), 'transport-change'),
      appStore.subscribe(() => this.requestUpdate(), 'change'),
      appStore.subscribe(() => void this.reloadStream(), 'refresh'),
      onLocaleChange(() => this.requestUpdate()),
    );
    void this.reloadStream();
  }

  private stopStream(): void {
    this.stream?.stop();
    this.stream = null;
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    this.reloadToken++;
    this.stopStream();
    this.releaseLogsChannel?.();
    this.releaseLogsChannel = null;
    if (this.searchTimer !== null) {
      clearTimeout(this.searchTimer);
      this.searchTimer = null;
    }
    for (const u of this.unsubs) u();
    this.unsubs = [];
  }

  private getFilterParams() {
    return {
      level: this.level === 'all' ? undefined : this.level,
      domain: this.domain === 'all' ? undefined : this.domain,
      search: this.search.trim() || undefined,
      since: this.latestSeq > 0 ? this.latestSeq : undefined,
    };
  }

  private syncTransport(): void {
    if (appStore.wsLive || appStore.authRequired) {
      this.stopStream();
      this.streamState = appStore.authRequired ? 'unauthorized' : 'live';
      return;
    }
    if (appStore.shouldUseSseFallback) {
      if (!this.stream && this.isConnected) this.startFallbackSse(this.reloadToken);
    } else {
      this.streamState = 'connecting';
    }
  }

  private startFallbackSse(token: number): void {
    this.stopStream();
    this.stream = createLogsStream(
      () => this.getFilterParams(),
      (entry) => {
        if (!this.paused && token === this.reloadToken) this.appendEntry(entry);
      },
      (resp) => {
        if (!this.paused && token === this.reloadToken) {
          this.applySnapshot(resp.entries ?? [], resp.latest_seq ?? 0, resp.evicted ?? 0);
        }
      },
      (st) => {
        if (token === this.reloadToken) this.streamState = st;
      },
      (err) => {
        if (token === this.reloadToken) {
          this.toast = err;
          this.toastKind = 'err';
        }
      },
    );
    this.stream.start();
  }

  private async reloadStream(): Promise<void> {
    const token = ++this.reloadToken;
    this.stopStream();
    this.seenSeq.clear();
    this.entries = [];
    this.latestSeq = 0;

    try {
      const snap = await nexusApi.logs({
        level: this.level === 'all' ? undefined : this.level,
        domain: this.domain === 'all' ? undefined : this.domain,
        search: this.search.trim() || undefined,
        limit: 250,
      });
      if (!this.isConnected || token !== this.reloadToken) return;
      this.applySnapshot(snap.entries ?? [], snap.latest_seq ?? 0, snap.evicted ?? 0);
      appStore.setLogCursor(this.latestSeq);
    } catch (err) {
      if (!this.isConnected || token !== this.reloadToken) return;
      this.toast = err instanceof Error ? err.message : String(err);
      this.toastKind = 'err';
    }

    if (!this.isConnected || token !== this.reloadToken) return;
    if (!this.releaseLogsChannel) {
      this.releaseLogsChannel = appStore.acquireChannel('logs', this.latestSeq);
    }
    this.syncTransport();
  }

  private pruneSeenSeq(kept: LogEntry[]): void {
    if (this.seenSeq.size <= MAX_ENTRIES) return;
    this.seenSeq = new Set(kept.map((e) => e.seq));
  }

  private applySnapshot(items: LogEntry[], latest: number, evicted: number): void {
    this.latestSeq = Math.max(this.latestSeq, latest);
    this.evicted = evicted;
    let added = false;
    const next = [...this.entries];
    for (const item of items) {
      if (this.seenSeq.has(item.seq)) continue;
      this.seenSeq.add(item.seq);
      if (item.seq > this.latestSeq) this.latestSeq = item.seq;
      next.push(item);
      added = true;
    }
    if (added) {
      const kept = next.slice(-MAX_ENTRIES);
      this.pruneSeenSeq(kept);
      this.entries = kept;
      this.scrollToBottom();
    }
  }

  private appendEntry(entry: LogEntry): void {
    if (this.seenSeq.has(entry.seq)) return;
    this.seenSeq.add(entry.seq);
    if (entry.seq > this.latestSeq) this.latestSeq = entry.seq;
    const kept = [...this.entries.slice(-(MAX_ENTRIES - 1)), entry];
    this.pruneSeenSeq(kept);
    this.entries = kept;
    this.scrollToBottom();
  }

  private scrollToBottom(): void {
    if (!this.autoScroll) return;
    void this.updateComplete.then(() => {
      const el = this.shadowRoot?.querySelector('.log-box');
      if (el) el.scrollTop = el.scrollHeight;
    });
  }

  private scheduleReload(): void {
    if (this.searchTimer !== null) clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => {
      this.searchTimer = null;
      void this.reloadStream();
    }, 280);
  }

  private async updateCoreLevel(newLevel: string): Promise<void> {
    if (!newLevel) return;
    const targetDomain = this.domain === 'all' ? 'global' : this.domain;
    try {
      await nexusApi.setLogLevel(newLevel, targetDomain);
      this.toast = t('logs.levelApplied', { domain: targetDomain, level: newLevel });
      this.toastKind = 'ok';
    } catch (err) {
      this.toast = err instanceof Error ? err.message : String(err);
      this.toastKind = 'err';
    }
  }

  private async copyLogs(): Promise<void> {
    try {
      await navigator.clipboard.writeText(formatLogPlainLines(this.entries));
      this.copied = true;
      setTimeout(() => (this.copied = false), 1400);
    } catch {
      // clipboard unavailable
    }
  }

  private exportSnapshot(): void {
    const blob = new Blob([formatLogPlainLines(this.entries) + '\n'], {
      type: 'text/plain;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nexus-logs-${Date.now()}.txt`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  private toggleQuickLevel(lvl: string): void {
    this.level = this.level === lvl ? 'all' : lvl;
    void this.reloadStream();
  }

  render() {
    const activeState: StreamState = appStore.wsLive ? 'live' : this.streamState;
    const streamBadgeClass =
      activeState === 'live'
        ? 'ok'
        : activeState === 'polling' || activeState === 'connecting'
          ? 'warn'
          : 'err';
    const streamLabel =
      activeState === 'live' && appStore.wsLive ? t('stream.liveWs') : t(`stream.${activeState}`);
    const hasFilter = this.level !== 'all' || this.domain !== 'all' || this.search.trim().length > 0;
    const sev = countLogSeverities(this.entries);

    return html`
      <div class="page">
        <div class="page-head">
          <div class="row">
            <h2>${t('logs.title')}</h2>
            <span class="badge ${streamBadgeClass}">
              <span class="dot"></span>${streamLabel}
            </span>
            <span class="muted mono tabular">
              ${t('logs.latest')} #${this.latestSeq} · ${t('logs.evicted')} ${this.evicted}
            </span>
          </div>
          <div class="row">
            <button class="sm" @click=${() => (this.paused = !this.paused)}>
              ${this.paused ? icons.play() : icons.pause()}
              ${this.paused ? t('common.resume') : t('common.pause')}
            </button>
            <button
              class="chip ${this.autoScroll ? 'active' : ''}"
              @click=${() => {
                this.autoScroll = !this.autoScroll;
                if (this.autoScroll) this.scrollToBottom();
              }}
            >
              ${t('logs.autoscroll')}
            </button>
            <button class="sm" ?disabled=${this.entries.length === 0} @click=${() => void this.copyLogs()}>
              ${icons.copy()} ${this.copied ? t('common.copied') : t('common.copy')}
            </button>
            <button class="sm" ?disabled=${this.entries.length === 0} @click=${() => this.exportSnapshot()}>
              ${icons.download()} ${t('common.export')}
            </button>
            <button class="primary sm" @click=${() => void this.reloadStream()}>
              ${icons.refresh()} ${t('common.refresh')}
            </button>
          </div>
        </div>

        ${this.toast
          ? html`
              <div class="toast ${this.toastKind}" role="status" aria-live="polite">
                <span>${this.toast}</span>
                <button class="ghost sm" aria-label=${t('common.dismiss')} @click=${() => (this.toast = '')}>
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
              aria-label=${t('logs.search')}
              spellcheck="false"
              autocapitalize="none"
              autocorrect="off"
              style="flex:1; min-width:200px"
              placeholder=${t('logs.search')}
              .value=${this.search}
              @input=${(e: Event) => {
                this.search = (e.target as HTMLInputElement).value;
                this.scheduleReload();
              }}
              @keydown=${(e: KeyboardEvent) => e.key === 'Enter' && void this.reloadStream()}
            />
            <select
              aria-label=${t('logs.domainLabel')}
              .value=${this.domain}
              @change=${(e: Event) => {
                this.domain = (e.target as HTMLSelectElement).value;
                void this.reloadStream();
              }}
            >
              ${LOG_DOMAINS.map(
                (d) =>
                  html`<option value=${d}>
                    ${t('logs.domainPrefix', { domain: d === 'all' ? t('common.all') : d })}
                  </option>`,
              )}
            </select>
            <select
              aria-label=${t('logs.coreLevelLabel')}
              @change=${(e: Event) => {
                const el = e.target as HTMLSelectElement;
                void this.updateCoreLevel(el.value);
                el.value = '';
              }}
            >
              <option value="" selected disabled>${t('logs.coreLevel')}…</option>
              ${['error', 'warn', 'info', 'debug', 'trace'].map(
                (lvl) => html`<option value=${lvl}>${lvl.toUpperCase()}</option>`,
              )}
            </select>
          </div>

          <div class="row">
            ${LOG_LEVELS.map(
              (lvl) => html`
                <button
                  class="chip ${this.level === lvl ? 'active' : ''}"
                  @click=${() => {
                    this.level = lvl;
                    void this.reloadStream();
                  }}
                >
                  ${lvl === 'all' ? t('common.all') : lvl.toUpperCase()}
                </button>
              `,
            )}
          </div>
        </div>

        <div class="card" style="padding:10px">
          <div class="sev-bar">
            <div class="row" style="gap:6px">
              <button class="chip ${this.level === 'info' ? 'active' : ''}" @click=${() => this.toggleQuickLevel('info')}>
                INFO <span class="tabular">${sev.info}</span>
              </button>
              <button class="chip ${this.level === 'warn' ? 'active' : ''}" @click=${() => this.toggleQuickLevel('warn')}>
                WARN <span class="tabular">${sev.warn}</span>
              </button>
              <button class="chip ${this.level === 'error' ? 'active' : ''}" @click=${() => this.toggleQuickLevel('error')}>
                ERR <span class="tabular">${sev.error}</span>
              </button>
            </div>
            ${!this.autoScroll
              ? html`
                  <button
                    class="primary sm"
                    @click=${() => {
                      this.autoScroll = true;
                      this.scrollToBottom();
                    }}
                  >
                    ${t('logs.jumpLatest')}
                  </button>
                `
              : ''}
          </div>
          <div
            class="log-box mono"
            @scroll=${(ev: Event) => {
              const el = ev.currentTarget as HTMLElement;
              const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight <= 36;
              if (!atBottom && this.autoScroll) this.autoScroll = false;
            }}
          >
            ${this.entries.length === 0
              ? html`
                  <div class="empty-state">
                    <span>${t('logs.empty')}</span>
                    ${hasFilter
                      ? html`<button class="sm" @click=${() => { this.level = 'all'; this.domain = 'all'; this.search = ''; void this.reloadStream(); }}>${t('common.clearFilters')}</button>`
                      : html`<button class="sm" @click=${() => void this.reloadStream()}>${icons.refresh()} ${t('common.refresh')}</button>`}
                  </div>
                `
              : this.entries.map(
                  (e) => html`
                    <div class="log-line lvl-${e.level}">
                      <span class="muted">#${e.seq}</span>
                      <span class="muted hide-sm">${formatTimestampNs(e.timestamp_ns)}</span>
                      <span class="badge ${levelBadgeClass(e.level)}">${e.level}</span>
                      <span class="muted hide-sm">${e.domain}</span>
                      <span class="msg">${e.message}</span>
                    </div>
                  `,
                )}
          </div>
        </div>
      </div>
    `;
  }
}
