import { css, html } from 'lit';
import {
  getLatencyTier,
  latencyBars,
  type OutboundMember,
  type OutboundProbeResult,
} from '../api.ts';
import { computeRelativeMeterScale } from '../components/telemetry-math.ts';
import { icons } from '../icons.ts';
import { t } from '../i18n.ts';

export const nodeCardStyles = css`
  .node-card {
    position: relative;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 12px;
    border-radius: 8px;
    background: var(--nx-well);
    border: 1px solid transparent;
    transition:
      border-color 120ms ease-out,
      background 120ms ease-out,
      transform 120ms cubic-bezier(0.23, 1, 0.32, 1);
  }
  .node-card > .row {
    position: relative;
    z-index: 1;
  }
  .lat-meter {
    position: absolute;
    inset: 0;
    transform-origin: left;
    opacity: var(--nx-meter-opacity, 0.08);
    pointer-events: none;
  }
  .node-card.switchable {
    cursor: pointer;
  }
  .node-card.switchable:active {
    transform: scale(0.98);
  }
  .node-card.selected {
    border-color: var(--nx-accent);
    background: var(--nx-accent-soft);
  }
  .node-select-btn {
    flex: 1;
    min-width: 0;
    border: none;
    background: transparent;
    padding: 0;
    color: var(--nx-text);
    font-size: 13.5px;
    font-weight: 700;
    text-align: left;
    justify-content: flex-start;
  }
  .node-select-btn:disabled {
    opacity: 1;
    cursor: default;
  }
  @media (hover: hover) and (pointer: fine) {
    .node-card.switchable:hover {
      border-color: var(--nx-accent-border);
      background: var(--nx-row-hover);
    }
    .node-select-btn:hover:not(:disabled) {
      background: transparent;
      color: var(--nx-accent-text, var(--nx-accent));
    }
  }
  .bars {
    display: inline-flex;
    align-items: flex-end;
    gap: 2px;
    height: 12px;
  }
  .bars span {
    width: 3px;
    border-radius: 1px;
    background: currentColor;
    opacity: 0.24;
  }
  .bars span.on {
    opacity: 1;
  }
`;

export function renderOutboundNodeCard(p: {
  member: OutboundMember;
  liveProbe?: OutboundProbeResult;
  maxHealthy: number;
  selected: boolean;
  canSwitch: boolean;
  busy: boolean;
  probing: boolean;
  onSelect: () => void;
  onProbe: (ev: Event) => void;
}) {
  const m = p.member;
  const ms =
    p.liveProbe && p.liveProbe.latency_ms !== undefined && p.liveProbe.latency_ms !== null
      ? p.liveProbe.latency_ms
      : (m.latency_ms ?? null);
  const st = p.liveProbe?.state ?? m.state;
  const tier = m.breaker_open ? 'down' : getLatencyTier(ms, st);
  const bars = latencyBars(ms);
  const statusCode = p.liveProbe?.status_code ?? m.last_status;
  const meter = computeRelativeMeterScale(
    ms,
    p.maxHealthy,
    !m.breaker_open && tier !== 'down' && tier !== 'unprobed',
  );

  return html`
    <div
      class="node-card ${p.selected ? 'selected' : ''} ${p.canSwitch ? 'switchable' : ''}"
      @click=${() => p.canSwitch && !p.busy && p.onSelect()}
    >
      ${meter > 0
        ? html`<span
            class="lat-meter"
            aria-hidden="true"
            style="transform:scaleX(${meter.toFixed(3)});background:var(--nx-lat-${tier}-fg)"
          ></span>`
        : ''}
      <div class="row between">
        <button
          type="button"
          class="node-select-btn truncate"
          title=${m.name}
          aria-pressed=${p.selected ? 'true' : 'false'}
          ?disabled=${!p.canSwitch || p.busy}
          @click=${(ev: Event) => {
            ev.stopPropagation();
            if (p.canSwitch && !p.busy) p.onSelect();
          }}
        >
          ${m.name}
        </button>
        <span class="badge lat-${tier}">
          <span class="bars" aria-hidden="true">
            ${[4, 7, 10, 12].map(
              (h, idx) => html`<span class=${idx < bars ? 'on' : ''} style="height:${h}px"></span>`,
            )}
          </span>
          ${m.breaker_open
            ? t('outbounds.breaker')
            : ms !== null
              ? `${ms} ms`
              : st === 'down'
                ? t('outbounds.down')
                : t('outbounds.unprobed')}
        </span>
      </div>
      <div class="row between">
        <div class="muted mono" style="font-size:11.5px">
          ${m.ewma_ms !== undefined ? `EWMA ${m.ewma_ms}ms` : st}
          ${statusCode !== undefined ? ` · HTTP ${statusCode}` : ''}
        </div>
        <button type="button" class="sm" ?disabled=${p.probing} @click=${p.onProbe}>
          ${icons.bolt()} ${p.probing ? t('outbounds.probing') : t('outbounds.probeNode')}
        </button>
      </div>
    </div>
  `;
}
