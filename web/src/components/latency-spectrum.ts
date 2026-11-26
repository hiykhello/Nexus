import { css, html } from 'lit';
import { t } from '../i18n.ts';
import { SPECTRUM_TIERS, type SpectrumStats } from './telemetry-math.ts';

export {
  SPECTRUM_TIERS,
  computeGroupSpectrum,
  computeRelativeMeterScale,
  type SpectrumStats,
} from './telemetry-math.ts';

export const latencySpectrumStyles = css`
  .spec-wrap {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
  }
  .spec-bar {
    flex: 1;
    min-width: 48px;
    height: 3px;
    border-radius: 2px;
    background: var(--nx-inset);
    overflow: hidden;
    display: flex;
  }
  .spec-bar.compact {
    height: 2px;
  }
  .spec-seg {
    height: 100%;
    flex-shrink: 0;
  }
  .spec-seg.fast { background: var(--nx-lat-fast-fg); }
  .spec-seg.good { background: var(--nx-lat-good-fg); }
  .spec-seg.mid { background: var(--nx-lat-mid-fg); }
  .spec-seg.slow { background: var(--nx-lat-slow-fg); }
  .spec-seg.down { background: var(--nx-lat-down-fg); }
  .spec-seg.unprobed { background: var(--nx-border-strong); }
  .spec-p50 {
    font-size: 11.5px;
    color: var(--nx-muted);
    white-space: nowrap;
  }
`;

export function renderLatencySpectrum(
  stats: SpectrumStats | null,
  opts: { compact?: boolean; showP50?: boolean } = {},
) {
  if (!stats || stats.total <= 0) return html``;
  const ariaLabel = t('outbounds.spectrum', {
    fast: stats.counts.fast,
    good: stats.counts.good,
    mid: stats.counts.mid,
    slow: stats.counts.slow,
    down: stats.counts.down,
    unprobed: stats.counts.unprobed,
  });

  return html`
    <div class="spec-wrap">
      <div class="spec-bar ${opts.compact ? 'compact' : ''}" role="img" aria-label=${ariaLabel}>
        ${SPECTRUM_TIERS.map((tier) => {
          const count = stats.counts[tier];
          if (count <= 0) return '';
          return html`<span class="spec-seg ${tier}" style="width:${((count / stats.total) * 100).toFixed(2)}%"></span>`;
        })}
      </div>
      ${opts.showP50 && stats.p50 !== null
        ? html`<span class="spec-p50 mono tabular">${t('outbounds.p50', { ms: stats.p50 })}</span>`
        : ''}
    </div>
  `;
}
