import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { nexusApi, OutboundGroup } from '../api.ts';
import { sharedStyles } from '../styles.ts';

@customElement('nexus-outbounds-page')
export class NexusOutboundsPage extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .members {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(190px, 1fr));
        gap: 10px;
        margin-top: 10px;
      }
      .member {
        text-align: left;
        padding: 10px 12px;
        border-radius: 10px;
        display: flex;
        flex-direction: column;
        gap: 4px;
      }
      .member.selected {
        border-color: var(--nx-accent);
        background: color-mix(in srgb, var(--nx-accent) 14%, var(--nx-surface-alt));
      }
    `,
  ];

  @state() private groups: OutboundGroup[] = [];
  @state() private error = '';
  @state() private busy = false;

  connectedCallback(): void {
    super.connectedCallback();
    void this.refresh();
  }

  private async refresh(): Promise<void> {
    try {
      const resp = await nexusApi.outbounds();
      this.groups = resp.groups ?? [];
      this.error = '';
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
    }
  }

  private async select(group: string, member: string): Promise<void> {
    this.busy = true;
    try {
      await nexusApi.selectGroup(group, member);
      await this.refresh();
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
    } finally {
      this.busy = false;
    }
  }

  private async probe(group: string): Promise<void> {
    this.busy = true;
    try {
      await nexusApi.probeGroup(group);
      await this.refresh();
    } catch (err) {
      this.error = err instanceof Error ? err.message : String(err);
    } finally {
      this.busy = false;
    }
  }

  render() {
    return html`
      <div class="page">
        <div class="row between">
          <h2>出站策略组</h2>
          <button @click=${() => void this.refresh()} ?disabled=${this.busy}>刷新</button>
        </div>

        ${this.error ? html`<div class="error-banner">${this.error}</div>` : ''}

        ${this.groups.length === 0
          ? html`<div class="card muted">当前配置未声明 selector / url-test / fallback 策略组。</div>`
          : this.groups.map(
              (g) => html`
                <div class="card">
                  <div class="row between">
                    <div class="row">
                      <strong>${g.name}</strong>
                      <span class="badge">${g.mode}</span>
                      <span class="badge ok">当前: ${g.selected}</span>
                      ${g.override ? html`<span class="badge warn">手动覆盖</span>` : ''}
                    </div>
                    <div class="row">
                      ${g.override
                        ? html`<button @click=${() => void this.select(g.name, '--auto')} ?disabled=${this.busy}>恢复自动</button>`
                        : ''}
                      ${g.mode !== 'select'
                        ? html`<button @click=${() => void this.probe(g.name)} ?disabled=${this.busy}>立即测速</button>`
                        : ''}
                    </div>
                  </div>
                  <div class="members">
                    ${g.members.map(
                      (m) => html`
                        <button
                          class="member ${m.name === g.selected ? 'selected' : ''}"
                          ?disabled=${this.busy}
                          @click=${() => void this.select(g.name, m.name)}
                        >
                          <div class="row between" style="width:100%">
                            <strong>${m.name}</strong>
                            <span class="badge ${m.breaker_open ? 'err' : m.state === 'up' ? 'ok' : ''}">
                              ${m.breaker_open ? '熔断' : m.state}
                            </span>
                          </div>
                          <div class="muted mono">
                            ${m.latency_ms !== undefined ? `${m.latency_ms} ms` : '未探测'}
                            ${m.ewma_ms !== undefined ? ` · EWMA ${m.ewma_ms} ms` : ''}
                          </div>
                        </button>
                      `,
                    )}
                  </div>
                </div>
              `,
            )}
      </div>
    `;
  }
}
