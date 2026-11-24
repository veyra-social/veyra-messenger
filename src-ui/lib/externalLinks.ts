import { openUrl } from "@tauri-apps/plugin-opener";

// Tauri v2 webviews do not honor `<a target="_blank">`: external navigation
// is blocked by the shell, so every outbound link in the app silently did
// nothing (field bug 2026-07-20, all platforms). Links must go through the
// opener plugin, which hands the URL to the OS default handler.

const EXTERNAL_SCHEMES = ["http:", "https:", "mailto:", "tel:"];

/** Opens a URL in the OS default application (browser, mail, dialer). */
export function openExternal(url: string): void {
  const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
  if (inTauri) {
    void openUrl(url).catch((err) => {
      console.error("[externalLinks] failed to open url:", url, err);
    });
  } else {
    // Vite dev in a plain browser: the browser can navigate itself.
    window.open(url, "_blank", "noopener,noreferrer");
  }
}

/**
 * Global click interceptor: routes every `<a>` pointing at an external
 * scheme through {@link openExternal}. One capture-phase listener covers
 * the About link, profile mailto/tel/links and any future anchor without
 * per-component wiring.
 */
export function installExternalLinkInterceptor(): void {
  document.addEventListener(
    "click",
    (event) => {
      if (event.defaultPrevented || event.button !== 0) {
        return;
      }
      const anchor = (event.target as HTMLElement | null)?.closest?.("a[href]");
      if (!(anchor instanceof HTMLAnchorElement)) {
        return;
      }
      const href = anchor.href;
      let scheme: string;
      try {
        scheme = new URL(href).protocol;
      } catch {
        return;
      }
      if (!EXTERNAL_SCHEMES.includes(scheme)) {
        return;
      }
      event.preventDefault();
      openExternal(href);
    },
    { capture: true },
  );
}
