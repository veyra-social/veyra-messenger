import React from "react";
import ReactDOM from "react-dom/client";
import { getCurrentWindow } from "@tauri-apps/api/window";
import App from "./App";
import { LocaleProvider } from "./i18n/LocaleProvider";
import { UiPrefsProvider } from "./lib/UiPrefsProvider";
import { api } from "./lib/tauriApi";
import { installExternalLinkInterceptor } from "./lib/externalLinks";
import "./i18n";
import "./styles.css";

installExternalLinkInterceptor();

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <UiPrefsProvider>
      <LocaleProvider>
        <App />
      </LocaleProvider>
    </UiPrefsProvider>
  </React.StrictMode>,
);

// Show the window after React's first paint unless this is a background
// autostart launch that should stay in the tray.
requestAnimationFrame(() => {
  try {
    void api
      .shouldShowMainWindowOnStartup()
      .then((shouldShow) => {
        if (shouldShow) {
          void getCurrentWindow().show();
        }
      })
      .catch((err) => {
        const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
        if (inTauri) {
          console.error("[main.tsx] failed to resolve startup window mode:", err);
        }
      });
  } catch (err) {
    // Running outside Tauri (Vite dev in browser) is the only expected branch.
    const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
    if (inTauri) {
      console.error("[main.tsx] failed to show Tauri window:", err);
    }
  }
});
