import { svg } from 'lit';

function icon(paths: ReturnType<typeof svg>, size = 16) {
  return svg`<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
}

export const icons = {
  overview: () =>
    icon(svg`<rect x="3" y="3" width="7" height="9" rx="2"/><rect x="14" y="3" width="7" height="5" rx="2"/><rect x="14" y="12" width="7" height="9" rx="2"/><rect x="3" y="16" width="7" height="5" rx="2"/>`),
  outbounds: () =>
    icon(svg`<circle cx="6" cy="6" r="3"/><circle cx="18" cy="6" r="3"/><circle cx="12" cy="18" r="3"/><path d="M8.5 7.5 11 15M15.5 7.5 13 15"/>`),
  connections: () =>
    icon(svg`<path d="M7 16V4m0 0-3 3m3-3 3 3M17 8v12m0 0 3-3m-3 3-3-3"/>`),
  rules: () =>
    icon(svg`<path d="M4 6h16M4 12h10M4 18h7"/><circle cx="18" cy="15" r="3"/><path d="m20.5 17.5 1.5 1.5"/>`),
  logs: () =>
    icon(svg`<path d="M4 5h16a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1Z"/><path d="m7 9 3 3-3 3m5 0h5"/>`),
  diagnostics: () =>
    icon(svg`<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/>`),
  refresh: () =>
    icon(svg`<path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/>`, 15),
  bolt: () =>
    icon(svg`<path d="M13 2 3 14h9l-1 8 10-12h-9l1-8Z"/>`, 14),
  sun: () =>
    icon(svg`<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32 1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41m11.32-11.32 1.41-1.41"/>`, 15),
  moon: () =>
    icon(svg`<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79Z"/>`, 15),
  globe: () =>
    icon(svg`<circle cx="12" cy="12" r="9"/><path d="M3.6 9h16.8M3.6 15h16.8M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>`, 15),
  lock: () =>
    icon(svg`<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>`, 15),
  search: () =>
    icon(svg`<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>`, 15),
  copy: () =>
    icon(svg`<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>`, 14),
  download: () =>
    icon(svg`<path d="M12 3v12m0 0-4-4m4 4 4-4M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/>`, 14),
  trash: () =>
    icon(svg`<path d="M3 6h18M8 6V4h8v2m-9 0 1 14h8l1-14"/>`, 14),
  pause: () =>
    icon(svg`<rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/>`, 14),
  play: () =>
    icon(svg`<polygon points="6 4 20 12 6 20 6 4"/>`, 14),
  close: () =>
    icon(svg`<path d="M18 6 6 18M6 6l12 12"/>`, 15),
};
