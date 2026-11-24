import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api } from "../lib/tauriApi";
import i18n, { applyUiLocale } from "./index";
import {
  detectInitialUiLocale,
  normalizeUiLocale,
  uiLocaleDirection,
  writeStoredUiLocale,
  type UiLocale,
} from "./locale";

type LocaleContextValue = {
  locale: UiLocale;
  setLocale: (locale: UiLocale, options?: { persistToBackend?: boolean }) => Promise<void>;
  syncFromBackend: () => Promise<void>;
};

const LocaleContext = createContext<LocaleContextValue | null>(null);

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<UiLocale>(() => detectInitialUiLocale());

  const setLocale = useCallback(
    async (next: UiLocale, options?: { persistToBackend?: boolean }) => {
      const normalized = normalizeUiLocale(next);
      setLocaleState(normalized);
      writeStoredUiLocale(normalized);
      await applyUiLocale(normalized);
      if (options?.persistToBackend) {
        await api.setUiLocale(normalized);
      }
    },
    [],
  );

  const syncFromBackend = useCallback(async () => {
    try {
      const fromDb = normalizeUiLocale(await api.getUiLocale());
      if (fromDb !== locale) {
        setLocaleState(fromDb);
        writeStoredUiLocale(fromDb);
        await applyUiLocale(fromDb);
      }
    } catch {
      /* keep local preference when DB is unavailable */
    }
  }, [locale]);

  useEffect(() => {
    void applyUiLocale(locale);
  }, [locale]);

  useEffect(() => {
    const onLanguageChanged = (next: string) => {
      const normalized = normalizeUiLocale(next);
      setLocaleState(normalized);
      document.documentElement.lang = normalized;
      document.documentElement.dir = uiLocaleDirection(normalized);
    };
    i18n.on("languageChanged", onLanguageChanged);
    return () => {
      i18n.off("languageChanged", onLanguageChanged);
    };
  }, []);

  const value = useMemo(
    () => ({ locale, setLocale, syncFromBackend }),
    [locale, setLocale, syncFromBackend],
  );

  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>;
}

export function useLocale() {
  const ctx = useContext(LocaleContext);
  if (!ctx) {
    throw new Error("useLocale must be used within LocaleProvider");
  }
  return ctx;
}
