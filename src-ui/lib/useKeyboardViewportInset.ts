import { useEffect } from "react";

const KEYBOARD_OPEN_THRESHOLD_PX = 48;
const DEFAULT_KEYBOARD_INSET_PX = 336;
const MIN_FALLBACK_KEYBOARD_INSET_PX = 240;
const isIOS = typeof navigator !== "undefined" && /iPad|iPhone|iPod/.test(navigator.userAgent);
const isAndroid = typeof navigator !== "undefined" && /Android/i.test(navigator.userAgent);

function readViewportOverlapPx(): number {
  const viewport = window.visualViewport;
  if (!viewport) return 0;
  const overlap = window.innerHeight - (viewport.height + viewport.offsetTop);
  return Math.max(0, Math.round(overlap));
}

function applyKeyboardInset(insetPx: number) {
  document.documentElement.style.setProperty("--keyboard-inset", `${insetPx}px`);
  document.documentElement.classList.toggle("keyboard-open", insetPx > 0);
}

// Only inputs that summon the soft keyboard count. A focused checkbox is
// still an HTMLInputElement, and treating it as text entry applied the
// stored keyboard inset (~337px) with no keyboard on screen — every
// checkbox tap on mobile crushed the page to a strip (field bug
// 2026-07-20: «Разрешить работу в фоне» seemed to break the
// notifications page; the battery dialog merely kept the focus alive).
const NON_TEXT_INPUT_TYPES = new Set([
  "checkbox",
  "radio",
  "button",
  "submit",
  "reset",
  "range",
  "color",
  "file",
]);

function isTextEntryElement(element: unknown): boolean {
  if (element instanceof HTMLTextAreaElement) return true;
  if (element instanceof HTMLInputElement) {
    return !NON_TEXT_INPUT_TYPES.has(element.type);
  }
  return false;
}

function isTextEntryFocused(): boolean {
  return isTextEntryElement(document.activeElement);
}

function readStoredKeyboardInset(): number {
  const stored = parseInt(
    localStorage.getItem("veyra.last_keyboard_height") || `${DEFAULT_KEYBOARD_INSET_PX}`,
    10,
  );
  const fallback = Number.isFinite(stored) ? stored : DEFAULT_KEYBOARD_INSET_PX;
  const maxInset = Math.max(
    MIN_FALLBACK_KEYBOARD_INSET_PX,
    Math.round(window.innerHeight * 0.55),
  );
  return Math.min(Math.max(fallback, MIN_FALLBACK_KEYBOARD_INSET_PX), maxInset);
}

function resetOuterScroll() {
  if (window.scrollX !== 0 || window.scrollY !== 0) {
    window.scrollTo(0, 0);
  }
}

export function useKeyboardViewportInset(enabled: boolean) {
  useEffect(() => {
    if (!enabled) {
      applyKeyboardInset(0);
      return;
    }

    const sync = () => {
      const overlapPx = readViewportOverlapPx();
      const textEntryFocused = isTextEntryFocused();

      const isCurrentlyOpen = overlapPx >= KEYBOARD_OPEN_THRESHOLD_PX;

      if (isCurrentlyOpen) {
        applyKeyboardInset(overlapPx);
        localStorage.setItem("veyra.last_keyboard_height", overlapPx.toString());
      } else if (textEntryFocused && (isIOS || isAndroid)) {
        applyKeyboardInset(readStoredKeyboardInset());
      } else if (textEntryFocused) {
        applyKeyboardInset(0);
      } else {
        applyKeyboardInset(0);
      }

      resetOuterScroll();
      window.requestAnimationFrame(resetOuterScroll);
    };

    const handleFocusIn = (e: FocusEvent) => {
      if (!isIOS && !isAndroid) return;
      if (isTextEntryElement(e.target)) {
        applyKeyboardInset(readStoredKeyboardInset());
        resetOuterScroll();
        window.requestAnimationFrame(resetOuterScroll);
        window.requestAnimationFrame(sync);
        // Old Android WebViews may not fire visualViewport resize when the
        // keyboard opens; repeat syncs keep the composer above the keyboard.
        setTimeout(resetOuterScroll, 30);
        setTimeout(resetOuterScroll, 80);
        setTimeout(sync, 80);
        setTimeout(sync, 220);
      }
    };

    const handleFocusOut = () => {
      if (!isIOS && !isAndroid) return;
      setTimeout(() => {
        if (!isTextEntryFocused()) {
          applyKeyboardInset(0);
          resetOuterScroll();
        } else {
          sync();
        }
      }, 40);
    };

    // Returning from a system Activity (battery dialog, share sheet) can
    // leave a stale inset: the resize that would undo it fires while the
    // page is hidden. Re-sync on visibility restore.
    const handleVisibility = () => {
      if (!document.hidden) sync();
    };

    sync();

    const viewport = window.visualViewport;
    viewport?.addEventListener("resize", sync);
    viewport?.addEventListener("scroll", sync);
    window.addEventListener("resize", sync);
    window.addEventListener("orientationchange", sync);
    document.addEventListener("visibilitychange", handleVisibility);

    if (isIOS || isAndroid) {
      window.addEventListener("focusin", handleFocusIn);
      window.addEventListener("focusout", handleFocusOut);
    }

    return () => {
      viewport?.removeEventListener("resize", sync);
      viewport?.removeEventListener("scroll", sync);
      window.removeEventListener("resize", sync);
      window.removeEventListener("orientationchange", sync);
      document.removeEventListener("visibilitychange", handleVisibility);
      if (isIOS || isAndroid) {
        window.removeEventListener("focusin", handleFocusIn);
        window.removeEventListener("focusout", handleFocusOut);
      }
      applyKeyboardInset(0);
    };
  }, [enabled]);
}
