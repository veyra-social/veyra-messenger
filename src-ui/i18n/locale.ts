export const SUPPORTED_UI_LOCALES = [
  "zh-CN",
  "es",
  "en",
  "hi",
  "bn",
  "pt",
  "ru",
  "ja",
  "ar",
  "id",
  "tr",
  "ko",
  "de",
  "vi",
  "uz",
  "el",
  "be",
  "cs",
  "nl",
  "pl",
] as const;

export type UiLocale = (typeof SUPPORTED_UI_LOCALES)[number];

export const UI_LOCALE_STORAGE_KEY = "veyra.ui_locale";

export function isUiLocale(value: string): value is UiLocale {
  return (SUPPORTED_UI_LOCALES as readonly string[]).includes(value);
}

export function normalizeUiLocale(value?: string | null): UiLocale {
  const raw = (value ?? "").trim().toLowerCase();
  if (raw === "zh-cn" || raw === "zh" || raw.startsWith("zh-")) return "zh-CN";
  const base = raw.split(/[-_]/, 1)[0];
  if (base && isUiLocale(base)) return base;
  return "en";
}

export function uiLocaleDirection(locale: UiLocale): "ltr" | "rtl" {
  return locale === "ar" ? "rtl" : "ltr";
}

export function readStoredUiLocale(): UiLocale | null {
  try {
    const stored = localStorage.getItem(UI_LOCALE_STORAGE_KEY);
    if (!stored) return null;
    return normalizeUiLocale(stored);
  } catch {
    return null;
  }
}

export function writeStoredUiLocale(locale: UiLocale) {
  try {
    localStorage.setItem(UI_LOCALE_STORAGE_KEY, locale);
  } catch {
    /* ignore storage failures */
  }
}

export function detectInitialUiLocale(): UiLocale {
  return readStoredUiLocale() ?? normalizeUiLocale(navigator.language);
}
