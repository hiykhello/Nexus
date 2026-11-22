import { LitElement, html } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { DiagnosticsResponse, getBearerToken, nexusApi, setBearerToken } from '../api.ts';
import { sharedStyles } from '../styles.ts';

@customElement('nexus-diagnostics-page')
export class NexusDiagnosticsPage extends LitElement {
  static styles = [sharedStyles];

  @state() private diag: DiagnosticsResponse | null = null;
  @state() private tokenInput = getBearerToken();
  @state() private statusMsg = '';
  @state() private error = '';

  connectedCallback(): void {
    super.connectedCallback();
    void this.refresh();
  }

  private async refresh(): Promise<void> {
    try {
      this.diag = await nexusApi.diagnostics();
      this.error = '';
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
    }
  }

  private async saveToken(): Promise<void> {
    setBearerToken(this.tokenInput);
    try {
      const h = await nexusApi.health();
      this.statusMsg = `鉴权成功（实例 ${h.instance}，令牌仅存于当前标签页 sessionStorage）`;
      await this.refresh();
    } catch (err) {
      this.statusMsg = `校验失败: ${err instanceof Error ? err.message : String(err)}`;
    }
  }

  render() {
    return html`
      <div class="page">
        <div class="row between">
          <h2>诊断与鉴权</h2>
          <button @click=${() => void this.refresh()}>刷新诊断</button>
        </div>

        <div class="card">
          <h3>控制面 Bearer 令牌（HTTP Authorization 头发送，绝不写入 URL）</h3>
          <div class="row">
            <input
              type="password"
              style="flex:1; min-width:240px"
              placeholder="输入 control bearer-token-file 内容（未启用鉴权可留空）"
              .value=${this.tokenInput}
              @input=${(e: Event) => (this.tokenInput = (e.target as HTMLInputElement).value)}
              @keydown=${(e: KeyboardEvent) => e.key === 'Enter' && void this.saveToken()}
            />
            <button class="primary" @click=${() => void this.saveToken()}>保存并校验</button>
            <button
              @click=${() => {
                this.tokenInput = '';
                setBearerToken('');
                this.statusMsg = '已清除当前会话令牌';
              }}
            >
              清除
            </button>
          </div>
          ${this.statusMsg ? html`<p class="muted" style="margin:8px 0 0">${this.statusMsg}</p>` : ''}
        </div>

        ${this.error ? html`<div class="error-banner">${this.error}</div>` : ''}

        ${this.diag
          ? html`
              <div class="grid">
                <div class="card">
                  <h3>已授权请求</h3>
                  <div class="metric">${this.diag.authorized_requests}</div>
                </div>
                <div class="card">
                  <h3>被拒未授权请求</h3>
                  <div class="metric">${this.diag.unauthorized_requests}</div>
                </div>
                <div class="card">
                  <h3>超时 / 失败应答</h3>
                  <div class="metric">${this.diag.expired_requests} / ${this.diag.reply_failed}</div>
                </div>
                <div class="card">
                  <h3>控制代次</h3>
                  <div class="metric">#${this.diag.control_generation}</div>
                </div>
              </div>
            `
          : ''}
      </div>
    `;
  }
}
