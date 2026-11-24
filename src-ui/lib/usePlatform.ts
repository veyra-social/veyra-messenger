import { useMemo } from "react";

export function isAndroidUserAgent(userAgent: string): boolean {
  return /Android/i.test(userAgent);
}

export function isIosUserAgent(userAgent: string): boolean {
  return /\b(iPhone|iPad|iPod)\b/i.test(userAgent);
}

export function useIsAndroid(): boolean {
  return useMemo(
    () => typeof navigator !== "undefined" && isAndroidUserAgent(navigator.userAgent),
    [],
  );
}

export function useIsIOS(): boolean {
  return useMemo(
    () => typeof navigator !== "undefined" && isIosUserAgent(navigator.userAgent),
    [],
  );
}
