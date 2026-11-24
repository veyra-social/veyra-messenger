import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import {
  DEFAULT_UI_PREFS,
  applyChatFontScale,
  applySkin,
  applyTheme,
  applyUiFontScale,
  normalizeFontScale,
  normalizeSkin,
  normalizeTheme,
  normalizeKeepScreenOn,
  normalizeVideoAutoplayMuted,
  readChatFontScaleFromStorage,
  readKeepScreenOnFromStorage,
  readSkinFromStorage,
  readThemeFromStorage,
  readUiFontScaleFromStorage,
  readVideoAutoplayMutedFromStorage,
  watchAutoTheme,
  writeChatFontScaleToStorage,
  writeKeepScreenOnToStorage,
  writeSkinToStorage,
  writeThemeToStorage,
  writeUiFontScaleToStorage,
  writeVideoAutoplayMutedToStorage,
  type UiFontScale,
  type UiPrefs,
  type UiSkin,
  type UiTheme,
} from "./uiPrefs";
import { setKeepScreenOn as applyNativeKeepScreenOn } from "./nativeBridge";
import { api } from "./tauriApi";

type Ctx = {
  prefs: UiPrefs;
  setTheme: (theme: UiTheme) => Promise<void>;
  setUiFontScale: (scale: UiFontScale) => Promise<void>;
  setChatFontScale: (scale: UiFontScale) => Promise<void>;
  setSkin: (skin: UiSkin) => Promise<void>;
  setVideoAutoplayMuted: (enabled: boolean) => Promise<void>;
  setKeepScreenOn: (enabled: boolean) => Promise<void>;
  syncFromBackend: () => Promise<void>;
};

const UiPrefsContext = createContext<Ctx | null>(null);

function applyAll(prefs: UiPrefs) {
  applyTheme(prefs.theme);
  applyUiFontScale(prefs.uiFontScale);
  applyChatFontScale(prefs.chatFontScale);
  applySkin(prefs.skin);
}

export function UiPrefsProvider({ children }: { children: React.ReactNode }) {
  const initial: UiPrefs = useMemo(
    () => ({
      theme: readThemeFromStorage(),
      uiFontScale: readUiFontScaleFromStorage(),
      chatFontScale: readChatFontScaleFromStorage(),
      skin: readSkinFromStorage(),
      videoAutoplayMuted: readVideoAutoplayMutedFromStorage(),
      keepScreenOn: readKeepScreenOnFromStorage(),
    }),
    [],
  );
  const [prefs, setPrefs] = useState<UiPrefs>(initial);
  const prefsRef = useRef(prefs);
  prefsRef.current = prefs;

  useEffect(() => {
    applyAll(initial);
  }, [initial]);

  useEffect(() => {
    return watchAutoTheme(() => prefsRef.current.theme);
  }, []);

  const syncFromBackend = useCallback(async () => {
    try {
      const backend = await api.getUiPrefs();
      const next: UiPrefs = {
        theme: normalizeTheme(backend.theme),
        uiFontScale: normalizeFontScale(backend.ui_font_scale),
        chatFontScale: normalizeFontScale(backend.chat_font_scale),
        skin: normalizeSkin(backend.skin),
        videoAutoplayMuted: normalizeVideoAutoplayMuted(backend.video_autoplay_muted),
        keepScreenOn: normalizeKeepScreenOn(backend.keep_screen_on),
      };
      setPrefs((current) => {
        if (
          current.theme === next.theme &&
          current.uiFontScale === next.uiFontScale &&
          current.chatFontScale === next.chatFontScale &&
          current.skin === next.skin &&
          current.videoAutoplayMuted === next.videoAutoplayMuted &&
          current.keepScreenOn === next.keepScreenOn
        ) {
          return current;
        }
        applyAll(next);
        writeThemeToStorage(next.theme);
        writeUiFontScaleToStorage(next.uiFontScale);
        writeChatFontScaleToStorage(next.chatFontScale);
        writeSkinToStorage(next.skin);
        writeVideoAutoplayMutedToStorage(next.videoAutoplayMuted);
        writeKeepScreenOnToStorage(next.keepScreenOn);
        return next;
      });
    } catch {
      /* backend may not be reachable pre-startup; localStorage already applied */
    }
  }, []);

  useEffect(() => {
    void syncFromBackend();
  }, [syncFromBackend]);

  // The Android Activity starts every launch with the flag released and knows
  // nothing about the stored preference, so push the resolved value at it.
  useEffect(() => {
    applyNativeKeepScreenOn(prefs.keepScreenOn);
  }, [prefs.keepScreenOn]);

  const persistBackend = useCallback(async (next: UiPrefs) => {
    try {
      await api.setUiPrefs({
        theme: next.theme,
        ui_font_scale: next.uiFontScale,
        chat_font_scale: next.chatFontScale,
        skin: next.skin,
        video_autoplay_muted: next.videoAutoplayMuted,
        keep_screen_on: next.keepScreenOn,
      });
    } catch {
      /* persistence is best-effort */
    }
  }, []);

  const setTheme = useCallback(
    async (theme: UiTheme) => {
      const next: UiPrefs = { ...prefsRef.current, theme };
      setPrefs(next);
      applyTheme(theme);
      writeThemeToStorage(theme);
      await persistBackend(next);
    },
    [persistBackend],
  );

  const setUiFontScale = useCallback(
    async (scale: UiFontScale) => {
      const next: UiPrefs = { ...prefsRef.current, uiFontScale: scale };
      setPrefs(next);
      applyUiFontScale(scale);
      writeUiFontScaleToStorage(scale);
      await persistBackend(next);
    },
    [persistBackend],
  );

  const setChatFontScale = useCallback(
    async (scale: UiFontScale) => {
      const next: UiPrefs = { ...prefsRef.current, chatFontScale: scale };
      setPrefs(next);
      applyChatFontScale(scale);
      writeChatFontScaleToStorage(scale);
      await persistBackend(next);
    },
    [persistBackend],
  );

  const setSkin = useCallback(
    async (skin: UiSkin) => {
      const next: UiPrefs = { ...prefsRef.current, skin };
      setPrefs(next);
      applySkin(skin);
      writeSkinToStorage(skin);
      await persistBackend(next);
    },
    [persistBackend],
  );

  const setVideoAutoplayMuted = useCallback(
    async (enabled: boolean) => {
      const next: UiPrefs = { ...prefsRef.current, videoAutoplayMuted: enabled };
      setPrefs(next);
      writeVideoAutoplayMutedToStorage(enabled);
      await persistBackend(next);
    },
    [persistBackend],
  );

  const setKeepScreenOn = useCallback(
    async (enabled: boolean) => {
      const next: UiPrefs = { ...prefsRef.current, keepScreenOn: enabled };
      setPrefs(next);
      writeKeepScreenOnToStorage(enabled);
      // Android owns the window flag natively; iOS is driven from the Rust
      // side inside set_ui_prefs, so persisting is what applies it there.
      applyNativeKeepScreenOn(enabled);
      await persistBackend(next);
    },
    [persistBackend],
  );

  const value = useMemo<Ctx>(
    () => ({
      prefs,
      setTheme,
      setUiFontScale,
      setChatFontScale,
      setSkin,
      setVideoAutoplayMuted,
      setKeepScreenOn,
      syncFromBackend,
    }),
    [
      prefs,
      setTheme,
      setUiFontScale,
      setChatFontScale,
      setSkin,
      setVideoAutoplayMuted,
      setKeepScreenOn,
      syncFromBackend,
    ],
  );

  return <UiPrefsContext.Provider value={value}>{children}</UiPrefsContext.Provider>;
}

export function useUiPrefs(): Ctx {
  const ctx = useContext(UiPrefsContext);
  if (!ctx) throw new Error("useUiPrefs must be used inside <UiPrefsProvider>");
  return ctx;
}
