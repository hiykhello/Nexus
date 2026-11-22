import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { LogEntry, nexusApi } from '../api.ts';
import { sharedStyles } from '../styles.ts';

@customElement('nexus-logs-page')
export class NexusLogsPage extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .log-box {
        max-height: 58vh;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        gap: 4px;
      }
      .log-line {
        display: grid;
        grid-template-columns: 64px 66px 74px 1fr;
        gap: 8px;
        padding: 4px 6px;
        border-radius: 6px;
      }
      .log-line:hover {
        background: var(--nx-surface-alt);
      }
    `,
  ];

  @state() private entries: LogEntry[] = [];
  @state() private latestSeq = 0;
  @state() private evicted = 0;
  @state() private level = 'trace';
  @state() private domain = 'all';
  @state() private search = '';
  @state() private autoFollow = true;
  @state() private error = '';

  private timer?: number;

  connectedCallback(): void {
    super.connectedCallback();
    void this.refresh();
    this.timer = window.setInterval(() => {
      if (this.autoFollow) void this.refresh();
    }, 2000);
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    if (this.timer !== undefined) window.clearInterval(this.timer);
  }

  private async refresh(): Promise<void> {
    try {
      const resp = await nexusApi.logs({
        level: this.level,
        domain: this.domain,
        search: this.search,
        limit: 250,
      });
      this.entries = resp.entries ?? [];
      this.latestSeq = resp.latest_seq ?? 0;
      this.evicted = resp.evicted ?? 0;
      this.error = '';
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
    }
  }

  private async updateCoreLevel(newLevel: string): Promise<void> {
    try {
      await nexusApi.setLogLevel(newLevel, this.domain === 'all' ? 'global' : this.domain);
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
    }
  }

  private exportSnapshot(): void {
    const lines = this.entries.map(
      (e) => `#${e.seq} [${e.level}] (${e.domain}) ev=${e.event} ${e.message}`,
    );
    const blob = new Blob([lines.join('\n') + '\n'], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nexus-logs-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  render() {
    return html`
      <div class="page">
        <div class="row between">
          <h2>内存环形日志 (最新 #${this.latestSeq} · 已淘汰 ${this.evicted})</h2>
          <div class="row">
            <button @click=${() => (this.autoFollow = !this.autoFollow)}>
              ${this.autoFollow ? '暂停轮询' : '恢复轮询'}
            </button>
            <button @click=${() => this.exportSnapshot()} ?disabled=${this.entries.length === 0}>导出快照</button>
            <button class="primary" @click=${() => void this.refresh()}>立即拉取</button>
          </div>
        </div>

        <div class="card row">
          <input
            style="flex:1; min-width: 180px"
            type="search"
            placeholder="搜索域名 / 规则 / 事件关键字..."
            .value=${this.search}
            @input=${(e: Event) => (this.search = (e.target as HTMLInputElement).value)}
            @keydown=${(e: KeyboardEvent) => e.key === 'Enter' && void this.refresh()}
          />
          <select
            .value=${this.domain}
            @change=${(e: Event) => {
              this.domain = (e.target as HTMLSelectElement).value;
              void this.refresh();
            }}
          >
            ${['all', 'core', 'proxy', 'route', 'dns', 'tun', 'quic', 'control'].map(
              (d) => html`<option value=${d}>域: ${d}</option>`,
            )}
          </select>
          <select
            .value=${this.level}
            @change=${(e: Event) => {
              this.level = (e.target as HTMLSelectElement).value;
              void this.refresh();
            }}
          >
            ${['trace', 'debug', 'info', 'warn', 'error'].map(
              (lvl) => html`<option value=${lvl}>查询级别 ≥ ${lvl}</option>`,
            )}
          </select>
          <select
            @change=${(e: Event) => void this.updateCoreLevel((e.target as HTMLSelectElement).value)}
          >
            <option value="" selected disabled>调整核心输出级别...</option>
            ${['error', 'warn', 'info', 'debug', 'trace'].map(
              (lvl) => html`<option value=${lvl}>核心设为 ${lvl}</option>`,
            )}
          </select>
        </div>

        ${this.error ? html`<div class="error-banner">${this.error}</div>` : ''}

        <div class="card log-box mono">
          ${this.entries.length === 0
            ? html`<div class="muted">暂无匹配日志记录</div>`
            : this.entries.map(
                (e) => html`
                  <div class="log-line">
                    <span class="muted">#${e.seq}</span>
                    <span class="badge ${e.level === 'error' ? 'err' : e.level === 'warn' ? 'warn' : ''}">${e.level}</span>
                    <span class="muted">${e.domain}</span>
                    <span>${e.message}</span>
                  </div>
                `,
              )}
        </div>
      </div>
    `;
  }
}
