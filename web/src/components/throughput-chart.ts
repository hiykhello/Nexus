import { css, html } from 'lit';
import { formatRate, type OnsetMarker, type RateSample } from '../api.ts';
import { t } from '../i18n.ts';
import { mapOnsetMarkersToX } from './telemetry-math.ts';

export { mapOnsetMarkersToX, type MappedOnsetMarker } from './telemetry-math.ts';

export const throughputChartStyles = css`
  .spark-wrap {
    position: relative;
    margin-top: 10px;
    background: var(--nx-well);
    border-radius: 8px;
    padding: 10px 8px 4px;
  }
  .spark {
    width: 100%;
    height: 118px;
    display: block;
  }
  .peak-tag {
    position: absolute;
    top: 6px;
    right: 10px;
    font-size: 11px;
    color: var(--nx-muted);
    pointer-events: none;
  }
  .mid-tag {
    position: absolute;
    top: 54px;
    right: 10px;
    font-size: 10px;
    color: var(--nx-muted);
    opacity: 0.72;
    pointer-events: none;
  }
  .legend {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 14px;
    font-size: 12px;
    color: var(--nx-text-secondary);
  }
  .legend-item {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .swatch-solid {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: var(--nx-down);
  }
  .swatch-dash {
    width: 14px;
    height: 0;
    border-top: 2px dashed var(--nx-up);
  }
`;

export function renderThroughputChart(p: {
  history: RateSample[];
  onsetMarkers: OnsetMarker[];
  downRate: number;
  upRate: number;
}) {
  const maxVal = Math.max(1024, ...p.history.map((h) => Math.max(h.up, h.down)));
  const ptsOf = (key: 'up' | 'down') =>
    p.history.length < 2
      ? ''
      : p.history
          .map((pt, idx) => {
            const x = (idx / Math.max(1, p.history.length - 1)) * 400;
            const y = 104 - (pt[key] / maxVal) * 80;
            return `${x.toFixed(1)},${y.toFixed(1)}`;
          })
          .join(' ');

  const downPts = ptsOf('down');
  const upPts = ptsOf('up');
  const markers = mapOnsetMarkersToX(p.onsetMarkers, p.history, 400);
  const aria = t('chart.aria', { peak: formatRate(maxVal), markers: markers.length });

  return html`
    <div class="card">
      <div class="row between">
        <h3>${t('overview.throughput')}</h3>
        <div class="legend tabular">
          <span class="legend-item">
            <span class="swatch-solid" aria-hidden="true"></span>
            ${t('overview.download')}
            <span class="rate-slot">${formatRate(p.downRate)}</span>
          </span>
          <span class="legend-item">
            <span class="swatch-dash" aria-hidden="true"></span>
            ${t('overview.upload')}
            <span class="rate-slot">${formatRate(p.upRate)}</span>
          </span>
        </div>
      </div>
      <div class="spark-wrap">
        <span class="peak-tag mono tabular">${t('overview.peak')}: ${formatRate(maxVal)}</span>
        <span class="mid-tag mono tabular">${t('chart.mid')}</span>
        <svg class="spark" role="img" aria-label=${aria} viewBox="0 0 400 112" preserveAspectRatio="none">
          <line x1="0" y1="64" x2="400" y2="64" stroke="var(--nx-border)" stroke-dasharray="3 4" />
          ${downPts
            ? html`
                <polygon fill="var(--nx-down)" fill-opacity="0.14" points="0,110 ${downPts} 400,110"></polygon>
                <polyline fill="none" stroke="var(--nx-down)" stroke-width="2" points=${downPts}></polyline>
              `
            : ''}
          ${upPts
            ? html`
                <polyline
                  fill="none"
                  stroke="var(--nx-up)"
                  stroke-width="1.75"
                  stroke-dasharray="4 3"
                  points=${upPts}
                ></polyline>
              `
            : ''}
          ${markers.map(
            (m) => html`
              <line
                x1=${m.x.toFixed(1)}
                y1="14"
                x2=${m.x.toFixed(1)}
                y2="110"
                stroke="var(--nx-accent-text)"
                stroke-width="1"
                stroke-dasharray="2 2"
              />
              <text
                x=${m.labelX.toFixed(1)}
                y="11"
                text-anchor="middle"
                fill="var(--nx-accent-text)"
                font-size="9"
                font-family="ui-monospace, SFMono-Regular, Menlo, monospace"
              >
                ${m.label}
              </text>
            `,
          )}
        </svg>
      </div>
    </div>
  `;
}
