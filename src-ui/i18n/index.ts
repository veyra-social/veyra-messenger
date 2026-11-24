import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "./locales/en.json";
import {
  detectInitialUiLocale,
  SUPPORTED_UI_LOCALES,
  type UiLocale,
  uiLocaleDirection,
} from "./locale";

// English ships in the main bundle as the synchronous fallback; every other
// dictionary is its own lazy chunk, loaded from the local app bundle the
// first time its language is applied. The 20 statically-imported
// dictionaries used to be the bulk of the oversized main chunk.
const localeLoaders = import.meta.glob<Record<string, unknown>>("./locales/*.json", {
  import: "default",
});

const pendingLocaleLoads = new Map<UiLocale, Promise<void>>();

function ensureLocaleLoaded(locale: UiLocale): Promise<void> {
  if (locale === "en" || i18n.hasResourceBundle(locale, "translation")) {
    return Promise.resolve();
  }
  const existing = pendingLocaleLoads.get(locale);
  if (existing) return existing;
  const loader = localeLoaders[`./locales/${locale}.json`];
  if (!loader) return Promise.resolve();
  const task = loader()
    .then((bundle) => {
      i18n.addResourceBundle(locale, "translation", bundle, true, true);
    })
    .catch(() => {
      /* chunk failed to load — keep rendering the English fallback */
    })
    .finally(() => {
      pendingLocaleLoads.delete(locale);
    });
  pendingLocaleLoads.set(locale, task);
  return task;
}

const initialLocale = detectInitialUiLocale();

void i18n.use(initReactI18next).init({
  resources: {
    en: { translation: en },
  },
  lng: initialLocale,
  fallbackLng: "en",
  supportedLngs: SUPPORTED_UI_LOCALES,
  interpolation: { escapeValue: false },
});

// Warm the initial dictionary at module-import time, before React first
// paints — LocaleProvider's mount effect then applies it via the same
// (deduplicated) promise, so any English flash stays within milliseconds.
void ensureLocaleLoaded(initialLocale);

export function applyUiLocale(locale: UiLocale) {
  document.documentElement.lang = locale;
  document.documentElement.dir = uiLocaleDirection(locale);
  return ensureLocaleLoaded(locale).then(() => i18n.changeLanguage(locale));
}

export default i18n;
