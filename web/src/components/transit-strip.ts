import { css, html } from 'lit';
import {
  formatRate,
  type ModeResponse,
  type OutboundGroup,
  type RouteMode,
  type StatusResponse,
  type StreamState,
} from '../api.ts';
import { t } from '../i18n.ts';
import { appStore } from '../store.ts';
import { resolveTransitExit } from './telemetry-math.ts';

export const transitStripStyles = css`
  .transit-strip {
    padding: 8px;
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr) auto minmax(0, 1fr) auto minmax(0, 1fr);
    align-items: center;
    gap: 6px;
  }
  .transit-stage {
    width: 100%;
    min-width: 0;
    min-height: 48px;
    padding: 7px 10px;
    border: 1px solid transparent;
    border-radius: 8px;
    background: var(--nx-well);
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    justify-content: center;
    gap: 3px;
    text-align: left;
  }
  .transit-k {
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--nx-muted);
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }
  .transit-v {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    font-size: 13px;
    font-weight: 700;
    color: var(--nx-text);
    min-width: 0;
  }
  .transit-sub {
    width: 100%;
    font-size: 11px;
    color: var(--nx-muted);
  }
  .transit-sep {
    color: var(--nx-muted);
    font-size: 13px;
    font-weight: 700;
    padding: 0 2px;
    user-select: none;
  }
  .transit-sep.live {
    color: var(--nx-signal);
  }
  .sig-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--nx-muted);
    flex-shrink: 0;
  }
  .sig-dot.live {
    background: var(--nx-signal);
  }
  @media (hover: hover) and (pointer: fine) {
    .transit-stage:hover {
      background: var(--nx-row-hover);
      border-color: var(--nx-border-strong);
    }
  }
  @media (max-width: 860px) {
    .transit-strip {
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
    }
    .transit-sep {
      display: none;
    }
  }
`;

export interface TransitStripProps {
  status: StatusResponse | null;
  mode: ModeResponse | null;
  groups: OutboundGroup[];
  ruleCount: number;
  downRate: number;
  upRate: number;
  streamState: StreamState;
}

export function renderTransitStrip(p: TransitStripProps) {
  const live = p.streamState === 'live' && p.status !== null;
  const activeMode = (p.mode?.mode ?? 'rule') as RouteMode;
  const exit = resolveTransitExit(p.mode, p.groups, {
    direct: t('overview.mode.direct'),
    global: t('overview.mode.global'),
    noGroup: t('transit.noGroup'),
    fallbackSub: t('outbounds.title'),
  });

  return html`
    <div class="card transit-strip" role="region" aria-label=${t('transit.label')}>
      <button type="button" class="transit-stage" @click=${() => appStore.requestNavigate('/diagnostics')}>
        <span class="transit-k">${t('transit.inbound')}</span>
        <span class="transit-v tabular">${p.status?.listeners ?? 0} ${t('overview.listeners')}</span>
        <span class="transit-sub mono truncate">${p.status?.instance ?? 'nexus'}</span>
      </button>
      <span class="transit-sep ${live ? 'live' : ''}" aria-hidden="true">→</span>
      <button type="button" class="transit-stage" @click=${() => appStore.requestNavigate('/services')}>
        <span class="transit-k">${t('transit.route')}</span>
        <span class="transit-v">${t(`overview.mode.${activeMode}`)}</span>
        <span class="transit-sub tabular">${t('transit.rules', { count: p.ruleCount })}</span>
      </button>
      <span class="transit-sep ${live ? 'live' : ''}" aria-hidden="true">→</span>
      <button
        type="button"
        class="transit-stage"
        title=${exit.label}
        @click=${() =>
          p.groups.length > 0 ? appStore.requestOpenPalette('') : appStore.requestNavigate('/outbounds')}
      >
        <span class="transit-k">
          <span class="sig-dot ${live ? 'live' : ''}" aria-hidden="true"></span>
          ${t('transit.exit')}
        </span>
        <span class="transit-v">
          <span class="truncate">${exit.label}</span>
          ${exit.rttMs !== undefined && exit.tier
            ? html`<span class="badge lat-${exit.tier}">${exit.rttMs} ms</span>`
            : ''}
        </span>
        <span class="transit-sub truncate">${exit.subtitle}</span>
      </button>
      <span class="transit-sep ${live ? 'live' : ''}" aria-hidden="true">→</span>
      <button type="button" class="transit-stage" @click=${() => appStore.requestNavigate('/connections')}>
        <span class="transit-k">${t('transit.rate')}</span>
        <span class="transit-v mono">
          <span class="rate-slot" style="color:var(--nx-down)">↓ ${formatRate(p.downRate)}</span>
        </span>
        <span class="transit-sub mono tabular">
          <span style="color:var(--nx-up)">↑ ${formatRate(p.upRate)}</span> ·
          ${t('transit.sessions', { count: p.status?.active_sessions ?? 0 })}
        </span>
      </button>
    </div>
  `;
}
