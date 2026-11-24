import { describe, expect, it } from "vitest";
import { normalizeUiLocale, SUPPORTED_UI_LOCALES, uiLocaleDirection } from "./locale";

const localeModules = import.meta.glob<Record<string, unknown>>("./locales/*.json", {
  eager: true,
  import: "default",
});

function leafEntries(value: unknown, prefix = ""): Array<[string, string]> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    return typeof child === "string" ? [[path, child]] : leafEntries(child, path);
  });
}

function placeholders(value: string) {
  return [...value.matchAll(/{{[^{}]+}}/g)].map((match) => match[0]).sort();
}

describe("UI locales", () => {
  it("registers exactly the 20 shipped locale bundles", () => {
    const files = Object.keys(localeModules)
      .map((file) => file.match(/\/([^/]+)\.json$/)?.[1])
      .sort();
    expect(files).toEqual([...SUPPORTED_UI_LOCALES].sort());
  });

  it("keeps complete key and placeholder parity with English", () => {
    const english = new Map(leafEntries(localeModules["./locales/en.json"]));
    for (const [file, resource] of Object.entries(localeModules)) {
      const entries = leafEntries(resource);
      expect(entries.map(([key]) => key).sort(), file).toEqual([...english.keys()].sort());
      for (const [key, value] of entries) {
        expect(placeholders(value), `${file}:${key}`).toEqual(
          placeholders(english.get(key) ?? ""),
        );
      }
    }
  });

  it("normalizes regional browser tags and falls back to English", () => {
    expect(normalizeUiLocale("es-MX")).toBe("es");
    expect(normalizeUiLocale("pt_BR")).toBe("pt");
    expect(normalizeUiLocale("zh-Hant")).toBe("zh-CN");
    expect(normalizeUiLocale("ar-EG")).toBe("ar");
    expect(normalizeUiLocale("fr-FR")).toBe("en");
  });

  it("uses RTL only for Arabic", () => {
    expect(uiLocaleDirection("ar")).toBe("rtl");
    for (const locale of SUPPORTED_UI_LOCALES.filter((value) => value !== "ar")) {
      expect(uiLocaleDirection(locale)).toBe("ltr");
    }
  });
});
