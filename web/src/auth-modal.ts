import { LitElement, html, css } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { getBearerToken, nexusApi, setBearerToken } from './api.ts';
import { icons } from './icons.ts';
import { onLocaleChange, t } from './i18n.ts';
import { sharedStyles } from './styles.ts';

@customElement('nexus-auth-modal')
export class NexusAuthModal extends LitElement {
  static styles = [
    sharedStyles,
    css`
      .backdrop {
        position: fixed;
        inset: 0;
        background: var(--nx-scrim);
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 16px;
        z-index: 100;
        transition: opacity 160ms ease-out;
      }
      @media (prefers-reduced-transparency: no-preference) {
        .backdrop {
          backdrop-filter: blur(4px);
        }
      }
      .modal {
        width: min(460px, 100%);
        max-height: 90dvh;
        overflow-y: auto;
        overscroll-behavior: contain;
        background: var(--nx-overlay);
        border: 1px solid var(--nx-border-strong);
        border-radius: 16px;
        padding: 18px;
        box-shadow: var(--nx-modal-shadow);
        display: flex;
        flex-direction: column;
        gap: 12px;
        transition:
          opacity 180ms cubic-bezier(0.23, 1, 0.32, 1),
          transform 180ms cubic-bezier(0.23, 1, 0.32, 1);
      }
      @starting-style {
        .backdrop {
          opacity: 0;
        }
        .modal {
          opacity: 0;
          transform: scale(0.96);
        }
      }
    `,
  ];

  @property({ type: Boolean }) open = false;
  @state() private tokenInput = '';
  @state() private feedback = '';
  @state() private feedbackKind: 'ok' | 'err' = 'ok';

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

  protected updated(changed: Map<string, unknown>): void {
    if (changed.has('open') && this.open) {
      this.tokenInput = getBearerToken();
      this.feedback = '';
      void this.updateComplete.then(() => {
        this.shadowRoot?.querySelector<HTMLInputElement>('input[type="password"]')?.focus();
      });
    }
  }

  private close(): void {
    this.dispatchEvent(new CustomEvent('close', { bubbles: true, composed: true }));
  }

  private async verifyAndSave(): Promise<void> {
    setBearerToken(this.tokenInput);
    try {
      const h = await nexusApi.health();
      this.feedback = t('auth.verified', { instance: h.instance });
      this.feedbackKind = 'ok';
      setTimeout(() => this.close(), 450);
    } catch (err) {
      this.feedback = t('auth.failed', {
        error: err instanceof Error ? err.message : String(err),
      });
      this.feedbackKind = 'err';
    }
  }

  render() {
    if (!this.open) return null;
    return html`
      <div
        class="backdrop"
        @click=${(e: Event) => {
          if (e.target === e.currentTarget) this.close();
        }}
      >
        <div class="modal" role="dialog" aria-modal="true" aria-label=${t('auth.title')}>
          <div class="row between">
            <strong style="font-size:16px">${t('auth.title')}</strong>
            <button class="ghost sm" aria-label=${t('common.close')} @click=${() => this.close()}>
              ${icons.close()}
            </button>
          </div>
          <p class="muted" style="margin:0">${t('auth.desc')}</p>
          <input
            type="password"
            aria-label=${t('auth.tokenLabel')}
            autocomplete="off"
            spellcheck="false"
            autocapitalize="none"
            autocorrect="off"
            placeholder=${t('auth.placeholder')}
            .value=${this.tokenInput}
            @input=${(e: Event) => (this.tokenInput = (e.target as HTMLInputElement).value)}
            @keydown=${(e: KeyboardEvent) => e.key === 'Enter' && void this.verifyAndSave()}
          />
          ${this.feedback
            ? html`<div class="toast ${this.feedbackKind}" role="status" aria-live="polite">${this.feedback}</div>`
            : ''}
          <div class="row between">
            <button
              class="sm"
              @click=${() => {
                this.tokenInput = '';
                setBearerToken('');
                this.feedback = t('auth.cleared');
                this.feedbackKind = 'ok';
              }}
            >
              ${t('auth.clear')}
            </button>
            <div class="row">
              <button class="sm" @click=${() => this.close()}>${t('auth.close')}</button>
              <button class="primary sm" @click=${() => void this.verifyAndSave()}>
                ${icons.lock()} ${t('auth.save')}
              </button>
            </div>
          </div>
        </div>
      </div>
    `;
  }
}
