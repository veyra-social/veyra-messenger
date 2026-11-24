import { readText as readNativeText, writeText as writeNativeText } from "@tauri-apps/plugin-clipboard-manager";

function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

async function writeWebText(value: string): Promise<void> {
  if (!navigator.clipboard?.writeText) {
    throw new Error("web clipboard unavailable");
  }
  await navigator.clipboard.writeText(value);
}

export async function copyTextToClipboard(value: string): Promise<void> {
  if (isTauriRuntime()) {
    await writeNativeText(value);
    return;
  }

  try {
    await writeWebText(value);
  } catch {
    await writeNativeText(value);
  }
}

async function readWebText(): Promise<string> {
  if (!navigator.clipboard?.readText) {
    throw new Error("web clipboard unavailable");
  }
  return await navigator.clipboard.readText();
}

export async function readTextFromClipboard(): Promise<string> {
  if (isTauriRuntime()) {
    return await readNativeText();
  }

  try {
    return await readWebText();
  } catch {
    return await readNativeText();
  }
}
