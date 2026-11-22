import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { formatBytes, nexusApi, StatusResponse } from '../api.ts';
import { sharedStyles } from '../styles.ts';

interface RateSample {
  up: number;
  down: number;
}

@customElement('nexus-overview-page')
export class NexusOverviewPage extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .spark {
        width: 100%;
        height: 84px;
        display: block;
      }
      .legend {
        display: flex;
        gap: 16px;
        font-size: 12px;
        color: var(--nx-muted);
      }
    `,
  ];

  @state() private status: StatusResponse | null = null;
  @state() private error = '';
  @state() private feedback = '';
  @state() private upRate = 0;
  @state() private downRate = 0;
  @state() private history: RateSample[] = [];

  private timer?: number;
  private lastUp = 0;
  private lastDown = 0;
  private lastTs = 0;

  connectedCallback(): void {
    super.connectedCallback();
    void this.refresh();
    this.timer = window.setInterval(() => void this.refresh(), 2000);
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    if (this.timer !== undefined) window.clearInterval(this.timer);
  }

  private async refresh(): Promise<void> {
    try {
      const s = await nexusApi.status();
      const now = Date.now();
      const up = Number(s.upload_bytes_total || 0);
      const down = Number(s.download_bytes_total || 0);
      if (this.lastTs > 0 && now > this.lastTs) {
        const dt = (now - this.lastTs) / 1000;
        this.upRate = Math.max(0, (up - this.lastUp) / dt);
        this.downRate = Math.max(0, (down - this.lastDown) / dt);
        this.history = [...this.history.slice(-29), { up: this.upRate, down: this.downRate }];
      }
      this.lastUp = up;
      this.lastDown = down;
      this.lastTs = now;
      this.status = s;
      this.error = '';
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
    }
  }

  private async doReload(): Promise<void> {
    try {
      await nexusApi.reload();
      this.feedback = '已提交配置热重载请求';
      await this.refresh();
    } catch (err) {
      this.feedback = `重载失败: ${err instanceof Error ? err.message : String(err)}`;
    }
  }

  private async doClearCache(): Promise<void> {
    try {
      await nexusApi.clearCache('all');
      this.feedback = 'DNS 与规则集缓存已清空';
      await this.refresh();
    } catch (err) {
      this.feedback = `清空缓存失败: ${err instanceof Error ? err.message : String(err)}`;
    }
  }

  private polyline(key: 'up' | 'down', maxVal: number): string {
    if (this.history.length < 2) return '';
    return this.history
      .map((pt, idx) => {
        const x = (idx / Math.max(1, this.history.length - 1)) * 300;
        const y = 76 - (pt[key] / maxVal) * 68;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ');
  }

  render() {
    const maxVal = Math.max(1024, ...this.history.map((h) => Math.max(h.up, h.down)));
    return html`
      <div class="page">
        <div class="row between">
          <h2>系统概览</h2>
          <div class="row">
            <button @click=${() => void this.refresh()}>刷新</button>
            <button @click=${() => void this.doClearCache()}>清空缓存</button>
            <button class="primary" @click=${() => void this.doReload()}>热重载配置</button>
          </div>
        </div>

        ${this.error ? html`<div class="error-banner">${this.error}（如启用了 Bearer Token，请前往「诊断与鉴权」配置）</div>` : ''}
        ${this.feedback ? html`<div class="card muted">${this.feedback}</div>` : ''}

        <div class="grid">
          <div class="card">
            <h3>运行状态</h3>
            <div class="metric">${this.status ? this.status.state.toUpperCase() : '--'}</div>
            <div class="muted mono">实例: ${this.status?.instance ?? '-'}</div>
          </div>
          <div class="card">
            <h3>活跃会话</h3>
            <div class="metric">${this.status?.active_sessions ?? 0}</div>
            <div class="muted">监听: ${this.status?.listeners ?? 0} · 工作线程: ${this.status?.workers ?? 0}</div>
          </div>
          <div class="card">
            <h3>实时上行 / 累计</h3>
            <div class="metric">${formatBytes(this.upRate)}/s</div>
            <div class="muted">累计 ${formatBytes(this.status?.upload_bytes_total ?? 0)}</div>
          </div>
          <div class="card">
            <h3>实时下行 / 累计</h3>
            <div class="metric">${formatBytes(this.downRate)}/s</div>
            <div class="muted">累计 ${formatBytes(this.status?.download_bytes_total ?? 0)}</div>
          </div>
        </div>

        <div class="card">
          <div class="row between">
            <h3>近 60 秒吞吐趋势（峰值 ${formatBytes(maxVal)}/s）</h3>
            <div class="legend">
              <span style="color:#3b82f6">● 下行</span>
              <span style="color:#10b981">● 上行</span>
              <span>控制代次 #${this.status?.control_generation ?? '0'}</span>
            </div>
          </div>
          <svg class="spark" viewBox="0 0 300 84" preserveAspectRatio="none">
            <polyline fill="none" stroke="#3b82f6" stroke-width="2" points=${this.polyline('down', maxVal)}></polyline>
            <polyline fill="none" stroke="#10b981" stroke-width="2" points=${this.polyline('up', maxVal)}></polyline>
          </svg>
        </div>
      </div>
    `;
  }
}
