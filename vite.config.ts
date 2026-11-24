import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// UI branch baked in at build time. Debug UI is the full developer-facing
// look; release UI is the simplified end-user look. Resolution order:
// explicit VEYRA_UI_MODE always wins (buildall -DebugUi sets it), otherwise
// dev server and Tauri debug builds get the debug UI, release builds the
// release UI.
function resolveUiMode(command: string): "debug" | "release" {
  const explicit = process.env.VEYRA_UI_MODE;
  if (explicit === "debug" || explicit === "release") {
    return explicit;
  }
  if (command === "serve" || process.env.TAURI_ENV_DEBUG === "true") {
    return "debug";
  }
  return "release";
}

export default defineConfig(({ command }) => ({
  plugins: [react()],
  clearScreen: false,
  define: {
    __VEYRA_UI_MODE__: JSON.stringify(resolveUiMode(command)),
  },
  server: {
    port: 1420,
    strictPort: true,
  },
  envPrefix: ["VITE_", "TAURI_"],
  build: {
    // Without an explicit CSS target, esbuild minification rewrites media
    // queries into Media Queries L4 range syntax — `(max-width: 800px)`
    // becomes `(width<=800px)`, which Chromium < 104 silently drops. Huawei
    // (no-GMS) devices ship their own aged WebView, so every narrow-layout
    // override died there and phones rendered the two-pane desktop shell
    // (2026-07-06 field bug). JS `matchMedia` strings are untouched by the
    // minifier, which is why only the CSS half broke. chrome61 is Vite's
    // recommended floor for legacy Android WebViews; it only tames
    // minification output, costing nothing on modern engines.
    cssTarget: "chrome61",
  },
}));
