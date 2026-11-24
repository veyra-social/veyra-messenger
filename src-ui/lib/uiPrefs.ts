import { invoke } from "@tauri-apps/api/core";
import { isIosUserAgent } from "./usePlatform";

export type UiTheme = "auto" | "light" | "dark";
export type UiFontScale = "sm" | "md" | "lg" | "xl";
export type UiSkin =
  | "veyra"
  | "classic-imessage"
  | "imessage"
  | "viber"
  | "telegram"
  | "whatsapp";

export const UI_SKINS: UiSkin[] = [
  "veyra",
  "classic-imessage",
  "imessage",
  "viber",
  "telegram",
  "whatsapp",
];

export type UiPrefs = {
  theme: UiTheme;
  uiFontScale: UiFontScale;
  chatFontScale: UiFontScale;
  skin: UiSkin;
  videoAutoplayMuted: boolean;
  keepScreenOn: boolean;
};

export const DEFAULT_UI_PREFS: UiPrefs = {
  theme: "light",
  uiFontScale: "md",
  chatFontScale: "md",
  skin: "veyra",
  videoAutoplayMuted: true,
  keepScreenOn: defaultKeepScreenOn(),
};

const THEME_STORAGE_KEY = "veyra.ui_theme";
const UI_FONT_STORAGE_KEY = "veyra.ui_font_scale";
const CHAT_FONT_STORAGE_KEY = "veyra.chat_font_scale";
const SKIN_STORAGE_KEY = "veyra.ui_skin";
const VIDEO_AUTOPLAY_MUTED_STORAGE_KEY = "veyra.video_autoplay_muted";
const KEEP_SCREEN_ON_STORAGE_KEY = "veyra.keep_screen_on";

/**
 * iOS has held the screen awake in the foreground unconditionally since that
 * rule was ratified, so its default keeps doing exactly that and the toggle
 * only gives the user a way to switch it OFF. Everywhere else the display
 * sleeps as the system decides until the toggle is switched on. Mirrors
 * `db::default_keep_screen_on` on the Rust side.
 */
function defaultKeepScreenOn(): boolean {
  return typeof navigator !== "undefined" && isIosUserAgent(navigator.userAgent);
}

function normalizeBoolean(value: unknown, defaultValue: boolean): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value !== "string") return defaultValue;
  switch (value.trim().toLowerCase()) {
    case "true":
    case "1":
    case "yes":
    case "on":
      return true;
    case "false":
    case "0":
    case "no":
    case "off":
      return false;
    default:
      return defaultValue;
  }
}

export function normalizeVideoAutoplayMuted(value: unknown): boolean {
  return normalizeBoolean(value, true);
}

export function readVideoAutoplayMutedFromStorage(): boolean {
  try {
    return normalizeVideoAutoplayMuted(window.localStorage.getItem(VIDEO_AUTOPLAY_MUTED_STORAGE_KEY));
  } catch {
    return true;
  }
}

export function writeVideoAutoplayMutedToStorage(enabled: boolean): void {
  try {
    window.localStorage.setItem(VIDEO_AUTOPLAY_MUTED_STORAGE_KEY, enabled ? "true" : "false");
  } catch {
    /* ignore */
  }
}

export function normalizeKeepScreenOn(value: unknown): boolean {
  return normalizeBoolean(value, defaultKeepScreenOn());
}

export function readKeepScreenOnFromStorage(): boolean {
  try {
    return normalizeKeepScreenOn(window.localStorage.getItem(KEEP_SCREEN_ON_STORAGE_KEY));
  } catch {
    return defaultKeepScreenOn();
  }
}

export function writeKeepScreenOnToStorage(enabled: boolean): void {
  try {
    window.localStorage.setItem(KEEP_SCREEN_ON_STORAGE_KEY, enabled ? "true" : "false");
  } catch {
    /* ignore */
  }
}

// Collapsible settings blocks (Network page: proxy, nodes, and the debug-only
// ones) remember their last state per device. Local UI state only — it is not
// part of UiPrefs and never travels to the backend or to another device.
// Everything starts collapsed, so a first visit shows a short page.
const SECTION_OPEN_STORAGE_PREFIX = "veyra.section_open.";

export function readSectionOpenFromStorage(sectionId: string): boolean {
  try {
    return window.localStorage.getItem(`${SECTION_OPEN_STORAGE_PREFIX}${sectionId}`) === "true";
  } catch {
    return false;
  }
}

export function writeSectionOpenToStorage(sectionId: string, open: boolean): void {
  try {
    window.localStorage.setItem(
      `${SECTION_OPEN_STORAGE_PREFIX}${sectionId}`,
      open ? "true" : "false",
    );
  } catch {
    /* ignore */
  }
}

export function normalizeSkin(value: unknown): UiSkin {
  return UI_SKINS.includes(value as UiSkin) ? (value as UiSkin) : "veyra";
}

export function readSkinFromStorage(): UiSkin {
  try {
    return normalizeSkin(window.localStorage.getItem(SKIN_STORAGE_KEY));
  } catch {
    return "veyra";
  }
}

export function writeSkinToStorage(skin: UiSkin): void {
  try {
    window.localStorage.setItem(SKIN_STORAGE_KEY, skin);
  } catch {
    /* ignore */
  }
}

export function applySkin(skin: UiSkin): void {
  document.documentElement.dataset.skin = skin;
}

const UI_FONT_PX: Record<UiFontScale, string> = {
  sm: "13px",
  md: "14px",
  lg: "16px",
  xl: "18px",
};

const CHAT_FONT_PX: Record<UiFontScale, string> = {
  sm: "13px",
  md: "14px",
  lg: "16px",
  xl: "18px",
};

// Multiplier twins of the tables above (base 14px). Explicit font-size
// declarations in styles.css are calc(Npx * var(--ui-scale|--chat-scale)),
// so the pickers scale everything, not just sizes inherited from :root.
const FONT_SCALE_FACTOR: Record<UiFontScale, string> = {
  sm: "0.9286",
  md: "1",
  lg: "1.1429",
  xl: "1.2857",
};

export function normalizeFontScale(value: unknown): UiFontScale {
  return value === "sm" || value === "lg" || value === "xl" ? value : "md";
}

export function readUiFontScaleFromStorage(): UiFontScale {
  try {
    return normalizeFontScale(window.localStorage.getItem(UI_FONT_STORAGE_KEY));
  } catch {
    return "md";
  }
}

export function readChatFontScaleFromStorage(): UiFontScale {
  try {
    return normalizeFontScale(window.localStorage.getItem(CHAT_FONT_STORAGE_KEY));
  } catch {
    return "md";
  }
}

export function writeUiFontScaleToStorage(scale: UiFontScale): void {
  try {
    window.localStorage.setItem(UI_FONT_STORAGE_KEY, scale);
  } catch {
    /* ignore */
  }
}

export function writeChatFontScaleToStorage(scale: UiFontScale): void {
  try {
    window.localStorage.setItem(CHAT_FONT_STORAGE_KEY, scale);
  } catch {
    /* ignore */
  }
}

export function applyUiFontScale(scale: UiFontScale): void {
  document.documentElement.style.setProperty("--ui-font-base", UI_FONT_PX[scale]);
  document.documentElement.style.setProperty("--ui-scale", FONT_SCALE_FACTOR[scale]);
  document.documentElement.dataset.uiFontScale = scale;
}

export function applyChatFontScale(scale: UiFontScale): void {
  document.documentElement.style.setProperty("--chat-font-base", CHAT_FONT_PX[scale]);
  document.documentElement.style.setProperty("--chat-scale", FONT_SCALE_FACTOR[scale]);
  document.documentElement.dataset.chatFontScale = scale;
}

export function normalizeTheme(value: unknown): UiTheme {
  return value === "auto" || value === "dark" ? value : "light";
}

export function readThemeFromStorage(): UiTheme {
  try {
    return normalizeTheme(window.localStorage.getItem(THEME_STORAGE_KEY));
  } catch {
    return "light";
  }
}

export function writeThemeToStorage(theme: UiTheme): void {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    /* private mode / disabled storage */
  }
}

function systemPrefersDark(): boolean {
  try {
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  } catch {
    return false;
  }
}

export function resolveEffectiveTheme(theme: UiTheme): "light" | "dark" {
  if (theme === "auto") return systemPrefersDark() ? "dark" : "light";
  return theme;
}

// Native Android bridge injected by MainActivity via
// `WebView.addJavascriptInterface(VeyraNativeBridge, "VeyraNative")`. Only
// present inside the Android WebView; absent on desktop / browser builds.
type VeyraNativeBridge = {
  setStatusBarLight?: (light: boolean) => void;
};

export function applyTheme(theme: UiTheme): void {
  const effective = resolveEffectiveTheme(theme);
  document.documentElement.dataset.theme = effective;
  document.documentElement.dataset.themeMode = theme;
  syncAndroidStatusBar(effective);
  syncIosPrivacyShield(effective);
}

// Sync the Android system status-bar icon appearance with the live Veyra
// theme so the clock/SIM/battery glyphs stay readable in both light and dark
// themes regardless of the host device's system UI mode. No-op outside the
// Android WebView (and silently tolerant if the bridge is missing on an
// older APK).
function syncAndroidStatusBar(effective: "light" | "dark"): void {
  try {
    const bridge = (window as unknown as { VeyraNative?: VeyraNativeBridge })
      .VeyraNative;
    bridge?.setStatusBarLight?.(effective === "light");
  } catch {
    /* bridge missing or threw — ignore. */
  }
}

// iOS mirror of syncAndroidStatusBar: the native app-switcher privacy shield
// paints itself with the entry-screen palette of the resolved theme, and this
// command stores which one that is (see `ios_privacy_shield` in
// src-core/src/lib.rs). Fire-and-forget; the command is a no-op everywhere
// but iOS, and the catch swallows environments without Tauri IPC (browser
// dev, tests).
function syncIosPrivacyShield(effective: "light" | "dark"): void {
  if (typeof navigator === "undefined" || !isIosUserAgent(navigator.userAgent)) return;
  void invoke("set_privacy_shield_light", { light: effective === "light" }).catch(
    () => {
      /* IPC unavailable — ignore. */
    },
  );
}

let autoMediaCleanup: (() => void) | null = null;

export function watchAutoTheme(getTheme: () => UiTheme): () => void {
  if (autoMediaCleanup) autoMediaCleanup();
  try {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = () => {
      if (getTheme() === "auto") applyTheme("auto");
    };
    media.addEventListener("change", handler);
    autoMediaCleanup = () => media.removeEventListener("change", handler);
    return autoMediaCleanup;
  } catch {
    return () => undefined;
  }
}
