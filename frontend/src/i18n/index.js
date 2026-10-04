/**
 * Locale handling for the SPA.
 *
 * The catalogs live one namespace per file under `messages/<locale>/`, and the
 * file's name becomes the namespace, so `messages/en/leaf.json` provides
 * `leaf.*` and adding a namespace means adding a file — no index to edit, and
 * no risk of two features fighting over one JSON file.
 */
import { createI18n } from 'vue-i18n'

/** Locales the interface is translated into. `en` is the source language. */
export const SUPPORTED_LOCALES = [
  { code: 'en', label: 'English', htmlLang: 'en', acceptLanguage: 'en' },
  { code: 'zh', label: '简体中文', htmlLang: 'zh-Hans', acceptLanguage: 'zh-hans,zh;q=0.9' },
]

export const FALLBACK_LOCALE = 'en'

const STORAGE_KEY = 'localca.locale'

function isSupported(code) {
  return SUPPORTED_LOCALES.some((locale) => locale.code === code)
}

/**
 * The locale to start in: the visitor's last explicit choice, otherwise the
 * browser's preference, otherwise English.
 *
 * Deliberately not a server setting. The choice is about the person reading the
 * page, not about the deployment, and it has to be available before the first
 * paint to avoid a flash of the wrong language.
 */
export function detectLocale() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored && isSupported(stored)) {
      return stored
    }
  } catch (err) {
    /* storage disabled: fall through to the browser's preference */
  }
  const preferred = (navigator.languages || [navigator.language || ''])
    .map((tag) => String(tag).toLowerCase())
  for (const tag of preferred) {
    if (tag.startsWith('zh')) {
      return 'zh'
    }
    if (tag.startsWith('en')) {
      return 'en'
    }
  }
  return FALLBACK_LOCALE
}

/** The metadata block for a locale code. */
export function localeMeta(code) {
  return SUPPORTED_LOCALES.find((locale) => locale.code === code) || SUPPORTED_LOCALES[0]
}

/**
 * Deep-merge `source` into `target`, returning `target`.
 *
 * Merging rather than assigning is what lets the catalogs be split by feature:
 * one file per namespace, and no file has to know about the others.
 */
function merge(target, source) {
  for (const [key, value] of Object.entries(source)) {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      target[key] = merge(target[key] || {}, value)
    } else {
      target[key] = value
    }
  }
  return target
}

/**
 * Every `messages/<locale>/<file>.json`, merged into per-locale trees.
 *
 * The namespace is the *top-level key inside the file* (`auth.json` declares
 * `{"auth": {...}}`), not the file name: the name only groups files for a human
 * reading the directory, while the key is what `t('auth.login.title')` looks up.
 * Two files claiming the same namespace is therefore a mistake, and dev builds
 * say so instead of silently letting the last one win.
 */
function loadMessages() {
  const messages = {}
  const files = import.meta.glob('./messages/*/*.json', { eager: true })
  for (const [path, module] of Object.entries(files)) {
    const match = path.match(/\.\/messages\/([^/]+)\/[^/]+\.json$/)
    if (!match) {
      continue
    }
    const locale = match[1]
    const contents = module.default || module
    messages[locale] = messages[locale] || {}
    for (const namespace of Object.keys(contents)) {
      if (import.meta.env.DEV && namespace in messages[locale]) {
        console.warn(`[i18n] namespace "${namespace}" is declared by more than one file in "${locale}"`)
      }
    }
    merge(messages[locale], contents)
  }
  return messages
}

export const i18n = createI18n({
  // Composition API mode: `useI18n()` in components, `$t` in templates.
  legacy: false,
  globalInjection: true,
  locale: detectLocale(),
  fallbackLocale: FALLBACK_LOCALE,
  messages: loadMessages(),
  // A certificate expiry is written with `d(value, 'short')` so it follows the
  // reader's locale instead of the browser's default layout.
  datetimeFormats: {
    en: { short: { year: 'numeric', month: 'short', day: 'numeric' } },
    zh: { short: { year: 'numeric', month: 'long', day: 'numeric' } },
  },
  // A missing key is a bug, and silently rendering the key makes it look like a
  // layout problem. Keep it visible in development, quiet in production.
  missingWarn: import.meta.env.DEV,
  fallbackWarn: import.meta.env.DEV,
})

/**
 * Switch language and record the choice.
 *
 * Also updates `<html lang>` (screen readers and hyphenation depend on it) and
 * the `Accept-Language` header the API client sends, so server-authored
 * messages — validation errors, rate limits — come back in the same language
 * the interface is drawn in.
 */
export function setLocale(code) {
  const locale = isSupported(code) ? code : FALLBACK_LOCALE
  i18n.global.locale.value = locale

  const meta = localeMeta(locale)
  document.documentElement.lang = meta.htmlLang
  try {
    localStorage.setItem(STORAGE_KEY, locale)
  } catch (err) {
    /* storage disabled: the choice just does not survive a reload */
  }
  return locale
}

/** The `Accept-Language` value matching the active locale. */
export function acceptLanguage() {
  return localeMeta(i18n.global.locale.value).acceptLanguage
}
