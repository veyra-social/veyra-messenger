// Build-time UI branch (vite.config.ts injects __VEYRA_UI_MODE__):
// "debug" is the full developer-facing look (today's UI), "release" is the
// simplified end-user look. The flag is a compile-time constant so release
// bundles can drop debug-only branches entirely.
declare const __VEYRA_UI_MODE__: "debug" | "release" | undefined;

export type UiMode = "debug" | "release";

export const UI_MODE: UiMode =
  typeof __VEYRA_UI_MODE__ === "string" && __VEYRA_UI_MODE__ === "release"
    ? "release"
    : "debug";

export const isDebugUi = UI_MODE === "debug";
