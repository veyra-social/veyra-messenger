import { useEffect, useRef, useState, type MouseEvent, type TouchEvent } from "react";

const LONG_PRESS_MS = 550;
const MOVE_CANCEL_DISTANCE_SQUARED = 64;

export function useInputContextMenu() {
  const [menuPosition, setMenuPosition] = useState<{ x: number; y: number } | null>(null);
  const longPressTimer = useRef<number | undefined>(undefined);
  const touchOrigin = useRef<{ x: number; y: number } | null>(null);

  const clearLongPressTimer = () => {
    if (longPressTimer.current !== undefined) {
      window.clearTimeout(longPressTimer.current);
      longPressTimer.current = undefined;
    }
  };

  const closeMenu = () => {
    setMenuPosition(null);
  };

  useEffect(() => clearLongPressTimer, []);

  useEffect(() => {
    if (!menuPosition) return;

    const close = () => closeMenu();
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        closeMenu();
      }
    };

    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    document.addEventListener("keydown", handleKeyDown);

    return () => {
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [menuPosition]);

  const handleContextMenu = (event: MouseEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    event.preventDefault();
    event.stopPropagation();
    clearLongPressTimer();
    setMenuPosition({ x: event.clientX, y: event.clientY });
  };

  const handleTouchStart = (event: TouchEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    if (event.touches.length === 0) return;
    const touch = event.touches[0];
    const origin = { x: touch.clientX, y: touch.clientY };
    touchOrigin.current = origin;
    clearLongPressTimer();

    longPressTimer.current = window.setTimeout(() => {
      setMenuPosition(origin);
      longPressTimer.current = undefined;
    }, LONG_PRESS_MS);
  };

  const handleTouchMove = (event: TouchEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    if (!touchOrigin.current || event.touches.length === 0) return;
    const touch = event.touches[0];
    const dx = touch.clientX - touchOrigin.current.x;
    const dy = touch.clientY - touchOrigin.current.y;

    if (dx * dx + dy * dy > MOVE_CANCEL_DISTANCE_SQUARED) {
      clearLongPressTimer();
    }
  };

  const handleTouchEnd = () => {
    clearLongPressTimer();
    touchOrigin.current = null;
  };

  return {
    menuPosition,
    closeMenu,
    bind: {
      className: "input-context-menu-enabled",
      onContextMenu: handleContextMenu,
      onTouchStart: handleTouchStart,
      onTouchMove: handleTouchMove,
      onTouchEnd: handleTouchEnd,
      onTouchCancel: handleTouchEnd,
    },
  };
}
