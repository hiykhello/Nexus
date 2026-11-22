import { LitElement, html } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { AcmeCertItem, formatBytes, LogEntry, nexusApi, SsmapiStatsResponse, SsmapiUserItem } from '../api.ts';
import { sharedStyles } from '../styles.ts';

@customElement('nexus-rules-services-page')
export class NexusRulesServicesPage extends LitElement {
  static styles = [sharedStyles];

  @state() private ruleHits: LogEntry[] = [];
  @state() private hitFilter = '';
  @state() private streaming = true;
  @state() private acmeCerts: AcmeCertItem[] = [];
  @state() private acmeNote = '';
  @state() private ssmUsers: SsmapiUserItem[] = [];
  @state() private ssmStats: SsmapiStatsResponse | null = null;
  @state() private ssmNote = '';
  private timerId: number | null = null;

  connectedCallback(): void {
    super.connectedCallback();
    void this.refreshAll();
    this.timerId = window.setInterval(() => {
      if (this.streaming) void this.refreshHits();
    }, 2500);
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    if (this.timerId !== null) window.clearInterval(this.timerId);
    this.timerId = null;
  }

  private async refreshAll(): Promise<void> {
    await Promise.all([this.refreshHits(), this.refreshServices()]);
  }

  private async refreshHits(): Promise<void> {
    try {
      const res = await nexusApi.logs({ domain: 'route', level: 'trace', search: this.hitFilter, limit: 80 });
      this.ruleHits = res.entries;
    } catch {
      // Keep last known rule stream on transient disconnect
    }
  }

  private async refreshServices(): Promise<void> {
    try {
      const acme = await nexusApi.acmeStatus();
      this.acmeCerts = acme.certificates ?? [];
      this.acmeNote = '';
    } catch {
      this.acmeCerts = [];
      this.acmeNote = 'ACME 证书服务未启用或当前实例未导出 /v1/acme/status';
    }
    try {
      const [usersRes, statsRes] = await Promise.all([nexusApi.ssmapiUsers(), nexusApi.ssmapiStats()]);
      this.ssmUsers = usersRes.users ?? [];
      this.ssmStats = statsRes;
      this.ssmNote = '';
    } catch {
      this.ssmUsers = [];
      this.ssmStats = null;
      this.ssmNote = 'SS-2022 多用户管理接口 (ssmapi) 未启用';
    }
  }

  render() {
    return html`
      <div class="page">
        <div class="row between">
          <h2>规则命中流与服务面板 (只读)</h2>
          <div class="row">
            <button @click=${() => (this.streaming = !this.streaming)}>
              ${this.streaming ? '暂停规则流' : '恢复规则流'}
            </button>
            <button class="primary" @click=${() => void this.refreshAll()}>立即刷新</button>
          </div>
        </div>

        <div class="grid">
          <div class="card">
            <h3>ACME 自动证书</h3>
            ${this.acmeNote
              ? html`<p class="muted">${this.acmeNote}</p>`
              : this.acmeCerts.length === 0
                ? html`<p class="muted">暂无已签发证书</p>`
                : this.acmeCerts.map(
                    (c) => html`
                      <div class="row between" style="margin:6px 0">
                        <span>${c.domain} (${c.challenge})</span>
                        <span class="badge">${c.days_remaining} 天有效</span>
                      </div>
                    `,
                  )}
          </div>

          <div class="card">
            <h3>ssmapi 多用户计量</h3>
            ${this.ssmNote
              ? html`<p class="muted">${this.ssmNote}</p>`
              : html`
                  <p class="muted" style="margin:4px 0 8px">
                    用户数: ${this.ssmStats?.userCount ?? this.ssmUsers.length} · 总上行:
                    ${formatBytes(this.ssmStats?.totalUplinkBytes ?? 0)} · 总下行:
                    ${formatBytes(this.ssmStats?.totalDownlinkBytes ?? 0)}
                  </p>
                  ${this.ssmUsers.slice(0, 8).map(
                    (u) => html`
                      <div class="row between" style="margin:4px 0">
                        <span>${u.username} ${u.enabled ? '' : '(已禁用)'}</span>
                        <span class="muted">↑ ${formatBytes(u.uplinkBytes)} / ↓ ${formatBytes(u.downlinkBytes)}</span>
                      </div>
                    `,
                  )}
                `}
          </div>
        </div>

        <div class="card">
          <div class="row between" style="margin-bottom:10px">
            <h3>实时路由规则命中流 (${this.ruleHits.length})</h3>
            <input
              type="text"
              placeholder="按域名 / 出站 / 规则关键字过滤"
              .value=${this.hitFilter}
              @input=${(e: Event) => {
                this.hitFilter = (e.target as HTMLInputElement).value;
                void this.refreshHits();
              }}
            />
          </div>
          <table>
            <thead>
              <tr>
                <th>Seq</th>
                <th>Level</th>
                <th>Event</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              ${this.ruleHits.map(
                (entry) => html`
                  <tr>
                    <td>#${entry.seq}</td>
                    <td>${entry.level}</td>
                    <td>${entry.event}</td>
                    <td>${entry.message}</td>
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
