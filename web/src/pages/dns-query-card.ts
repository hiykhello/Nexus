import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import {
  nexusApi,
  type CacheClearTarget,
  type DnsQueryResponse,
  type DnsRecordType,
} from '../api.ts';
import { icons } from '../icons.ts';
import { onLocaleChange, t } from '../i18n.ts';
import { sharedStyles } from '../styles.ts';

const RECORD_TYPES: DnsRecordType[] = [
  'A',
  'AAAA',
  'HTTPS',
  'SVCB',
  'CNAME',
  'TXT',
  'MX',
  'SRV',
  'NS',
  'PTR',
  'SOA',
  'CAA',
];

@customElement('nexus-dns-query-card')
export class NexusDnsQueryCard extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .query-form {
        display: grid;
        grid-template-columns: 1fr 110px 160px auto;
        gap: 8px;
        margin-top: 10px;
      }
      @media (max-width: 780px) {
        .query-form {
          grid-template-columns: 1fr 1fr;
        }
      }
      .result-box {
        margin-top: 12px;
        background: var(--nx-well);
        border: 1px solid var(--nx-border);
        border-radius: 10px;
        padding: 12px;
      }
      .data-cell {
        word-break: break-all;
      }
      .cache-bar {
        margin-top: 12px;
        padding-top: 12px;
        border-top: 1px solid var(--nx-border);
      }
    `,
  ];

  @state() private domain = 'example.com';
  @state() private qtype: DnsRecordType = 'A';
  @state() private server = '';
  @state() private querying = false;
  @state() private cacheBusy = false;
  @state() private result: DnsQueryResponse | null = null;
  @state() private recent: Array<{ name: string; type: DnsRecordType }> = [];
  @state() private copiedIdx = -1;
  @state() private toast = '';
  @state() private toastKind: 'ok' | 'err' = 'ok';

  private unsubLocale: (() => void) | null = null;

  connectedCallback(): void {
    super.connectedCallback();
    this.unsubLocale = onLocaleChange(() => this.requestUpdate());
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    this.unsubLocale?.();
    this.unsubLocale = null;
  }

  private async runQuery(): Promise<void> {
    const name = this.domain.trim();
    if (!name || this.querying) return;
    this.querying = true;
    this.toast = '';
    try {
      const resp = await nexusApi.dnsQuery({
        name,
        type: this.qtype,
        server: this.server.trim() || undefined,
      });
      this.result = resp;
      const key = `${name}|${this.qtype}`;
      this.recent = [
        { name, type: this.qtype },
        ...this.recent.filter((r) => `${r.name}|${r.type}` !== key),
      ].slice(0, 5);
    } catch (err) {
      this.toast = err instanceof Error ? err.message : String(err);
      this.toastKind = 'err';
    } finally {
      this.querying = false;
    }
  }

  private async flushFakeip(): Promise<void> {
    this.cacheBusy = true;
    try {
      const res = await nexusApi.flushFakeIp();
      this.toast = t('overview.flushedFakeip', { count: res.flushed });
      this.toastKind = 'ok';
    } catch (err) {
      this.toast = err instanceof Error ? err.message : String(err);
      this.toastKind = 'err';
    } finally {
      this.cacheBusy = false;
    }
  }

  private async clearCache(target: CacheClearTarget): Promise<void> {
    this.cacheBusy = true;
    try {
      const res = await nexusApi.clearCache(target);
      this.toast = `${res.target}: ${res.detail || 'cleared'}`;
      this.toastKind = 'ok';
    } catch (err) {
      this.toast = err instanceof Error ? err.message : String(err);
      this.toastKind = 'err';
    } finally {
      this.cacheBusy = false;
    }
  }

  private async copyAnswer(text: string, idx: number): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      this.copiedIdx = idx;
      setTimeout(() => {
        if (this.copiedIdx === idx) this.copiedIdx = -1;
      }, 1400);
    } catch {
      // clipboard unavailable
    }
  }

  render() {
    const r = this.result;
    const answers = r?.answers ?? [];
    const rcodeClass = !r ? '' : r.rcode === 0 ? 'ok' : r.rcode === 3 ? 'warn' : 'err';

    return html`
      <div class="card">
        <div class="row between">
          <h3>${t('dns.title')}</h3>
        </div>

        <form
          class="query-form"
          @submit=${(e: Event) => {
            e.preventDefault();
            void this.runQuery();
          }}
        >
          <input
            type="text"
            placeholder=${t('dns.domainPlaceholder')}
            .value=${this.domain}
            @input=${(e: Event) => (this.domain = (e.target as HTMLInputElement).value)}
          />
          <select
            aria-label=${t('dns.typeLabel')}
            .value=${this.qtype}
            @change=${(e: Event) =>
              (this.qtype = (e.target as HTMLSelectElement).value as DnsRecordType)}
          >
            ${RECORD_TYPES.map((rt) => html`<option value=${rt}>${rt}</option>`)}
          </select>
          <input
            type="text"
            placeholder=${t('dns.serverPlaceholder')}
            .value=${this.server}
            @input=${(e: Event) => (this.server = (e.target as HTMLInputElement).value)}
          />
          <button class="primary" type="submit" ?disabled=${this.querying || !this.domain.trim()}>
            ${icons.search()} ${this.querying ? t('dns.querying') : t('dns.query')}
          </button>
        </form>

        ${this.recent.length > 0
          ? html`
              <div class="row" style="margin-top:8px">
                <span class="muted" style="font-size:11.5px">${t('dns.recent')}:</span>
                ${this.recent.map(
                  (item) => html`
                    <button
                      class="chip"
                      @click=${() => {
                        this.domain = item.name;
                        this.qtype = item.type;
                        void this.runQuery();
                      }}
                    >
                      <span class="mono">${item.name}</span>
                      <span>${item.type}</span>
                    </button>
                  `,
                )}
              </div>
            `
          : ''}

        ${this.toast
          ? html`
              <div class="toast ${this.toastKind}" role="status" aria-live="polite" style="margin-top:10px">
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

        ${r
          ? html`
              <div class="result-box">
                <div class="row between" style="margin-bottom:8px">
                  <div class="row">
                    <strong class="mono">${r.name}</strong>
                    <span class="badge accent">${r.type}</span>
                    <span class="badge ${rcodeClass}">${r.rcode_name} (${r.rcode})</span>
                  </div>
                  <div class="row mono">
                    <span class="badge">${t('dns.col.ttl')} ${r.ttl}s</span>
                    <span class="badge ok">${r.elapsed_ms} ms</span>
                  </div>
                </div>
                ${answers.length === 0
                  ? html`<div class="muted">${t('dns.noAnswers')}</div>`
                  : html`
                      <div class="table-wrap">
                        <table>
                          <thead>
                            <tr>
                              <th>${t('dns.col.name')}</th>
                              <th>${t('dns.col.type')}</th>
                              <th>${t('dns.col.ttl')}</th>
                              <th>${t('dns.col.data')}</th>
                              <th></th>
                            </tr>
                          </thead>
                          <tbody>
                            ${answers.map(
                              (ans, idx) => html`
                                <tr>
                                  <td class="mono">${ans.name}</td>
                                  <td><span class="badge">${ans.type}</span></td>
                                  <td class="mono muted">${ans.ttl}s</td>
                                  <td class="mono data-cell">${ans.data}</td>
                                  <td style="text-align:right">
                                    <button
                                      class="ghost sm"
                                      @click=${() => void this.copyAnswer(ans.data, idx)}
                                    >
                                      ${icons.copy()}
                                      ${this.copiedIdx === idx ? t('common.copied') : t('common.copy')}
                                    </button>
                                  </td>
                                </tr>
                              `,
                            )}
                          </tbody>
                        </table>
                      </div>
                    `}
              </div>
            `
          : ''}

        <div class="row cache-bar">
          <button class="sm" ?disabled=${this.cacheBusy} @click=${() => void this.flushFakeip()}>
            ${t('dns.flushFakeip')}
          </button>
          <button class="sm" ?disabled=${this.cacheBusy} @click=${() => void this.clearCache('dns')}>
            ${t('dns.cacheDns')}
          </button>
          <button class="sm" ?disabled=${this.cacheBusy} @click=${() => void this.clearCache('rulesets')}>
            ${t('dns.cacheRules')}
          </button>
          <button class="danger sm" ?disabled=${this.cacheBusy} @click=${() => void this.clearCache('all')}>
            ${icons.trash()} ${t('dns.cacheAll')}
          </button>
        </div>
      </div>
    `;
  }
}
