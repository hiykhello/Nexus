import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { ConnectionItem, formatBytes, nexusApi } from '../api.ts';
import { sharedStyles } from '../styles.ts';

@customElement('nexus-connections-page')
export class NexusConnectionsPage extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .drawer {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 8px 16px;
        margin-top: 8px;
      }
      .table-wrap {
        overflow-x: auto;
      }
    `,
  ];

  @state() private connections: ConnectionItem[] = [];
  @state() private detail: ConnectionItem | null = null;
  @state() private filter = '';
  @state() private error = '';

  private timer?: number;

  connectedCallback(): void {
    super.connectedCallback();
    void this.refresh();
    this.timer = window.setInterval(() => void this.refresh(), 2500);
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    if (this.timer !== undefined) window.clearInterval(this.timer);
  }

  private async refresh(): Promise<void> {
    try {
      const resp = await nexusApi.connections();
      this.connections = resp.connections ?? [];
      this.error = '';
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
    }
  }

  private async inspect(id: string): Promise<void> {
    try {
      this.detail = await nexusApi.connectionDetail(id);
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
    }
  }

  private async closeOne(id: string, ev: Event): Promise<void> {
    ev.stopPropagation();
    try {
      await nexusApi.closeConnection(id);
      if (this.detail?.id === id) this.detail = null;
      await this.refresh();
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
    }
  }

  private async closeAll(): Promise<void> {
    try {
      await nexusApi.closeAllConnections();
      this.detail = null;
      await this.refresh();
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
    }
  }

  render() {
    const q = this.filter.trim().toLowerCase();
    const list = q
      ? this.connections.filter((c) =>
          `${c.id} ${c.inbound ?? ''} ${c.protocol} ${c.outbound ?? ''} ${c.path} ${c.target ?? ''} ${c.destination_port}`
            .toLowerCase()
            .includes(q),
        )
      : this.connections;

    return html`
      <div class="page">
        <div class="row between">
          <h2>活跃连接 (${list.length})</h2>
          <div class="row">
            <input
              type="search"
              placeholder="按入站 / 出站 / 目标 / 协议过滤..."
              .value=${this.filter}
              @input=${(e: Event) => (this.filter = (e.target as HTMLInputElement).value)}
            />
            <button @click=${() => void this.refresh()}>刷新</button>
            <button class="danger" @click=${() => void this.closeAll()}>断开全部</button>
          </div>
        </div>

        ${this.error ? html`<div class="error-banner">${this.error}</div>` : ''}

        ${this.detail
          ? html`
              <div class="card">
                <div class="row between">
                  <strong>连接详情 #${this.detail.id}</strong>
                  <button @click=${() => (this.detail = null)}>关闭详情</button>
                </div>
                <div class="drawer mono">
                  <div>入站: ${this.detail.inbound || this.detail.protocol}</div>
                  <div>出站: ${this.detail.outbound || this.detail.path}</div>
                  <div>来源: ${this.detail.source || '-'}</div>
                  <div>目标: ${this.detail.target || `:${this.detail.destination_port}`}</div>
                  <div>路由: ${this.detail.route_mode || '-'} · 规则 ${this.detail.route_rule || '-'}</div>
                  <div>耗时: ${this.detail.duration_ms} ms</div>
                  <div>进程: ${this.detail.process_path || '-'}</div>
                  <div>UID: ${this.detail.source_uid ?? '-'}</div>
                </div>
              </div>
            `
          : ''}

        <div class="card table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>入站 / 协议</th>
                <th>目标</th>
                <th>出站</th>
                <th>规则</th>
                <th>流量 (↑ / ↓)</th>
                <th>耗时</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              ${list.length === 0
                ? html`<tr><td colspan="8" class="muted">暂无活跃连接</td></tr>`
                : list.map(
                    (c) => html`
                      <tr class="clickable" @click=${() => void this.inspect(c.id)}>
                        <td class="mono">#${c.id}</td>
                        <td>${c.inbound || '-'} <span class="badge">${c.protocol}</span></td>
                        <td class="mono">${c.target || `:${c.destination_port}`}</td>
                        <td><span class="badge ok">${c.outbound || c.path}</span></td>
                        <td class="mono">${c.route_rule || '-'}</td>
                        <td class="mono">${formatBytes(c.upload_bytes)} / ${formatBytes(c.download_bytes)}</td>
                        <td class="mono">${c.duration_ms} ms</td>
                        <td>
                          <button class="danger" @click=${(e: Event) => void this.closeOne(c.id, e)}>断开</button>
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
