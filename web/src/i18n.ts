import { EN, type I18nKey } from './i18n-en.ts';
import { ZH } from './i18n-zh.ts';

export type { I18nKey } from './i18n-en.ts';
export type Locale = 'en' | 'zh';

const LOCALE_KEY = 'nexus_web_lang';
const localeBus = new EventTarget();
const DICTS: Record<Locale, Record<I18nKey, string>> = { en: EN, zh: ZH };

function detectLocale(): Locale {
  if (typeof window !== 'undefined') {
    try {
      const saved = window.localStorage.getItem(LOCALE_KEY);
      if (saved === 'en' || saved === 'zh') return saved;
    } catch {
      // ignore
    }
  }
  if (typeof navigator !== 'undefined' && navigator.language?.toLowerCase().startsWith('zh')) {
    return 'zh';
  }
  return 'en';
}

let currentLocale: Locale = detectLocale();

function syncDocumentLang(): void {
  if (typeof document !== 'undefined') {
    document.documentElement.lang = currentLocale === 'zh' ? 'zh-CN' : 'en';
  }
}

syncDocumentLang();

export function getLocale(): Locale {
  return currentLocale;
}

export function setLocale(locale: Locale): void {
  if (currentLocale === locale) return;
  currentLocale = locale;
  if (typeof window !== 'undefined') {
    try {
      window.localStorage.setItem(LOCALE_KEY, locale);
    } catch {
      // ignore
    }
  }
  syncDocumentLang();
  localeBus.dispatchEvent(new CustomEvent('locale-changed', { detail: locale }));
}

export function toggleLocale(): Locale {
  const next: Locale = currentLocale === 'zh' ? 'en' : 'zh';
  setLocale(next);
  return next;
}

export function onLocaleChange(cb: (locale: Locale) => void): () => void {
  const handler = () => cb(currentLocale);
  localeBus.addEventListener('locale-changed', handler);
  return () => localeBus.removeEventListener('locale-changed', handler);
}

export function t(key: I18nKey, params?: Record<string, string | number>): string {
  const template = DICTS[currentLocale][key] ?? EN[key] ?? key;
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (_, k: string) =>
    params[k] !== undefined ? String(params[k]) : `{${k}}`,
  );
}
