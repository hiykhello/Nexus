import { LitElement, html, css } from 'lit';
import { customElement } from 'lit/decorators.js';
import { Router, routerLink } from '@elelcode/lit-router';
import './pages/overview-page.ts';
import './pages/outbounds-page.ts';
import './pages/connections-page.ts';
import './pages/logs-page.ts';
import './pages/rules-services-page.ts';
import './pages/diagnostics-page.ts';

const routes = [
  { path: '/', title: '概览 · Nexus', component: 'nexus-overview-page' },
  { path: '/outbounds', title: '策略组 · Nexus', component: 'nexus-outbounds-page' },
  { path: '/connections', title: '活跃连接 · Nexus', component: 'nexus-connections-page' },
  { path: '/logs', title: '运行日志 · Nexus', component: 'nexus-logs-page' },
  { path: '/services', title: '规则与服务 · Nexus', component: 'nexus-rules-services-page' },
  { path: '/diagnostics', title: '诊断与鉴权 · Nexus', component: 'nexus-diagnostics-page' },
];

@customElement('nexus-app')
export class NexusApp extends LitElement {
  static styles = css`
    :host {
      --nx-bg: #f4f6f9;
      --nx-surface: #ffffff;
      --nx-surface-alt: #f8fafc;
      --nx-border: #e2e8f0;
      --nx-text: #0f172a;
      --nx-muted: #64748b;
      --nx-accent: #2563eb;
      --nx-danger: #dc2626;
      display: block;
      min-height: 100vh;
      background: var(--nx-bg);
      color: var(--nx-text);
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }
    @media (prefers-color-scheme: dark) {
      :host {
        --nx-bg: #0b1120;
        --nx-surface: #111827;
        --nx-surface-alt: #1f2937;
        --nx-border: #334155;
        --nx-text: #f1f5f9;
        --nx-muted: #94a3b8;
        --nx-accent: #3b82f6;
        --nx-danger: #f87171;
      }
    }
    .shell {
      display: grid;
      grid-template-columns: 210px 1fr;
      min-height: 100vh;
    }
    aside {
      background: var(--nx-surface);
      border-right: 1px solid var(--nx-border);
      padding: 20px 14px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .brand {
      font-size: 20px;
      font-weight: 800;
      letter-spacing: 2px;
      padding: 6px 10px 16px;
    }
    nav {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    nav a {
      text-decoration: none;
      color: var(--nx-text);
      padding: 9px 12px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 500;
    }
    nav a:hover {
      background: var(--nx-surface-alt);
    }
    nav a.active {
      background: var(--nx-accent);
      color: #fff;
    }
    main {
      padding: 24px;
      max-width: 1200px;
      width: 100%;
      box-sizing: border-box;
    }
    .foot {
      margin-top: auto;
      padding: 10px;
      font-size: 12px;
      color: var(--nx-muted);
    }
    @media (max-width: 760px) {
      .shell {
        grid-template-columns: 1fr;
      }
      aside {
        border-right: none;
        border-bottom: 1px solid var(--nx-border);
      }
      nav {
        flex-direction: row;
        flex-wrap: wrap;
      }
      .foot {
        display: none;
      }
    }
  `;

  private readonly router = new Router({ routes, autoStart: true });

  disconnectedCallback(): void {
    super.disconnectedCallback();
    this.router.stop();
  }

  render() {
    return html`
      <div class="shell">
        <aside>
          <div class="brand">NEXUS</div>
          <nav>
            <a ${routerLink(this.router, '/', { exact: true, activeClass: 'active' })}>概览</a>
            <a ${routerLink(this.router, '/outbounds', { activeClass: 'active' })}>策略组</a>
            <a ${routerLink(this.router, '/connections', { activeClass: 'active' })}>活跃连接</a>
            <a ${routerLink(this.router, '/logs', { activeClass: 'active' })}>运行日志</a>
            <a ${routerLink(this.router, '/services', { activeClass: 'active' })}>规则与服务</a>
            <a ${routerLink(this.router, '/diagnostics', { activeClass: 'active' })}>诊断与鉴权</a>
          </nav>
          <div class="foot">控制面只读 Web 控制台 · Vite 8 + Lit</div>
        </aside>
        <main>
          <router-view .router=${this.router}></router-view>
        </main>
      </div>
    `;
  }
}
