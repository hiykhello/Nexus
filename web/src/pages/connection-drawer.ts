import { css, html } from 'lit';
import { formatBytes, formatDuration, type ConnectionItem } from '../api.ts';
import { normalizeHostQuery } from '../components/palette-logic.ts';
import { icons } from '../icons.ts';
import { t } from '../i18n.ts';
import { appStore } from '../store.ts';

export const connectionDrawerStyles = css`
  .drawer {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 10px 16px;
    margin-top: 10px;
  }
  .kv {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .kv-label {
    font-size: 11px;
    color: var(--nx-muted);
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }
`;

export function renderConnectionDrawer(
  d: ConnectionItem | null,
  handlers: { onCloseConn: (id: string, ev: Event) => void; onDismiss: () => void },
) {
  if (!d) return html``;
  const host = normalizeHostQuery(d.target ?? '');

  return html`
    <div class="card">
      <div class="row between">
        <div class="row">
          <strong>${t('connections.detail')}</strong>
          <span class="badge accent mono">#${d.id}</span>
        </div>
        <div class="row">
          ${host
            ? html`<button type="button" class="sm" @click=${() => appStore.requestOpenPalette(host)}>
                ${icons.search()} ${t('connections.inspectDomain')}
              </button>`
            : ''}
          ${d.route_rule
            ? html`<button type="button" class="sm" @click=${() => appStore.requestRuleFilter(d.route_rule!)}>
                ${icons.rules()} ${t('connections.filterRule')}
              </button>`
            : ''}
          ${d.can_close
            ? html`<button type="button" class="danger sm" @click=${(e: Event) => handlers.onCloseConn(d.id, e)}>
                ${t('connections.closeOne')}
              </button>`
            : ''}
          <button type="button" class="sm" @click=${handlers.onDismiss}>
            ${icons.close()} ${t('common.close')}
          </button>
        </div>
      </div>
      <div class="drawer mono">
        <div class="kv">
          <span class="kv-label">${t('connections.col.inbound')}</span>
          <span>${d.inbound || '-'} (${d.protocol})</span>
        </div>
        <div class="kv">
          <span class="kv-label">${t('connections.col.outbound')}</span>
          <span>${d.outbound || d.path}</span>
        </div>
        <div class="kv">
          <span class="kv-label">${t('connections.detail.source')}</span>
          <span>${d.source || '-'}</span>
        </div>
        <div class="kv">
          <span class="kv-label">${t('connections.col.target')}</span>
          <span>${d.target || `:${d.destination_port}`}</span>
        </div>
        <div class="kv">
          <span class="kv-label">${t('connections.col.rule')}</span>
          <span>${d.route_mode || '-'} · ${d.route_rule || '-'}</span>
        </div>
        <div class="kv">
          <span class="kv-label">${t('connections.col.traffic')}</span>
          <span>↑ ${formatBytes(d.upload_bytes)} / ↓ ${formatBytes(d.download_bytes)}</span>
        </div>
        <div class="kv">
          <span class="kv-label">${t('connections.detail.process')}</span>
          <span class="truncate" title=${d.process_path || '-'}>${d.process_path || '-'}</span>
        </div>
        <div class="kv">
          <span class="kv-label">${t('connections.detail.uidDuration')}</span>
          <span>${d.source_uid ?? '-'} · ${formatDuration(d.duration_ms)}</span>
        </div>
      </div>
    </div>
  `;
}
