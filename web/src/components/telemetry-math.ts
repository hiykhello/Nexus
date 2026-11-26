import {
  getLatencyTier,
  type LatencyTier,
  type ModeResponse,
  type OnsetKind,
  type OnsetMarker,
  type OutboundGroup,
  type OutboundMember,
  type RateSample,
} from '../api.ts';

export interface TransitExitInfo {
  label: string;
  subtitle: string;
  rttMs?: number;
  tier?: LatencyTier;
}

export function resolveTransitExit(
  mode: ModeResponse | null,
  groups: OutboundGroup[],
  labels: { direct: string; global: string; noGroup: string; fallbackSub: string },
): TransitExitInfo {
  const activeMode = mode?.mode ?? 'rule';
  if (activeMode === 'direct') {
    return { label: labels.direct, subtitle: labels.direct };
  }

  const primary = groups[0] ?? null;
  if (activeMode === 'global') {
    const target = mode?.outbound?.trim() ?? '';
    if (target) {
      const asGroup = groups.find((g) => g.name === target);
      if (asGroup) {
        const active = asGroup.members.find((m) => m.name === asGroup.selected);
        return {
          label: asGroup.selected || asGroup.name,
          subtitle: asGroup.name,
          rttMs: active?.latency_ms,
          tier: active ? (active.breaker_open ? 'down' : getLatencyTier(active.latency_ms, active.state)) : undefined,
        };
      }
      for (const g of groups) {
        const mem = g.members.find((m) => m.name === target);
        if (mem) {
          return {
            label: mem.name,
            subtitle: g.name,
            rttMs: mem.latency_ms,
            tier: mem.breaker_open ? 'down' : getLatencyTier(mem.latency_ms, mem.state),
          };
        }
      }
      return { label: target, subtitle: labels.global };
    }
  }

  if (!primary) return { label: labels.noGroup, subtitle: labels.fallbackSub };
  const active = primary.members.find((m) => m.name === primary.selected);
  return {
    label: primary.selected || labels.noGroup,
    subtitle: primary.name,
    rttMs: active?.latency_ms,
    tier: active ? (active.breaker_open ? 'down' : getLatencyTier(active.latency_ms, active.state)) : undefined,
  };
}

export const SPECTRUM_TIERS: readonly LatencyTier[] = [
  'fast',
  'good',
  'mid',
  'slow',
  'down',
  'unprobed',
];

export interface SpectrumStats {
  total: number;
  probed: number;
  p50: number | null;
  maxHealthy: number;
  counts: Record<LatencyTier, number>;
}

export interface MappedOnsetMarker {
  x: number;
  labelX: number;
  label: string;
  kind: OnsetKind;
}

export function computeGroupSpectrum(
  members: OutboundMember[],
  getLatency: (m: OutboundMember) => number | null = (m) => m.latency_ms ?? null,
  getState: (m: OutboundMember) => string = (m) => m.state,
): SpectrumStats {
  const counts: Record<LatencyTier, number> = {
    fast: 0,
    good: 0,
    mid: 0,
    slow: 0,
    down: 0,
    unprobed: 0,
  };
  const healthy: number[] = [];

  for (const m of members) {
    const ms = getLatency(m);
    const st = getState(m);
    const tier: LatencyTier = m.breaker_open ? 'down' : getLatencyTier(ms, st);
    counts[tier]++;
    if (!m.breaker_open && tier !== 'down' && tier !== 'unprobed' && ms !== null && ms > 0) {
      healthy.push(ms);
    }
  }

  healthy.sort((a, b) => a - b);
  let p50: number | null = null;
  if (healthy.length > 0) {
    const mid = Math.floor(healthy.length / 2);
    p50 =
      healthy.length % 2 === 1
        ? Math.round(healthy[mid])
        : Math.round((healthy[mid - 1] + healthy[mid]) / 2);
  }

  return {
    total: members.length,
    probed: healthy.length,
    p50,
    maxHealthy: healthy.length > 0 ? healthy[healthy.length - 1] : 0,
    counts,
  };
}

export function computeRelativeMeterScale(
  ms: number | null | undefined,
  maxHealthy: number,
  isHealthy: boolean,
): number {
  if (!isHealthy || ms === null || ms === undefined || ms <= 0) return 0;
  const denom = Math.max(maxHealthy, 250);
  return Math.min(1, Math.max(0.06, ms / denom));
}

export function mapOnsetMarkersToX(
  markers: OnsetMarker[],
  history: RateSample[],
  width = 400,
): MappedOnsetMarker[] {
  if (markers.length === 0 || history.length < 2) return [];
  const startTs = history[0].ts;
  const endTs = history[history.length - 1].ts;
  const span = Math.max(1, endTs - startTs);
  const mapped: MappedOnsetMarker[] = [];

  for (const m of markers) {
    if (m.ts < startTs) continue;
    const ratio = Math.min(1, Math.max(0, (m.ts - startTs) / span));
    const x = ratio * width;
    const labelX = Math.min(width - 34, Math.max(34, x));
    mapped.push({ x, labelX, label: m.label, kind: m.kind });
  }
  return mapped;
}
