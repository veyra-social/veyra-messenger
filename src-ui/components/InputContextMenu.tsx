import { useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";
import { Clipboard, ClipboardPaste, Scissors, Trash2 } from "lucide-react";
import { copyTextToClipboard, readTextFromClipboard } from "../lib/clipboard";
import {
  applyInputValue,
  cutText,
  getInputMenuState,
  normalizeRange,
  pasteText,
  selectedOrAllText,
} from "../lib/inputContextActions";

type Props = {
  position: { x: number; y: number } | null;
  onClose: () => void;
  inputRef: React.RefObject<HTMLInputElement | HTMLTextAreaElement>;
  isPassword?: boolean;
};

export function InputContextMenu({ position, onClose, inputRef, isPassword }: Props) {
  const { t } = useTranslation();
  const menuRef = useRef<HTMLDivElement>(null);

  const el = inputRef.current;
  const isReadOnly = el?.readOnly || el?.disabled || false;
  const menuState = el
    ? getInputMenuState(el, isPassword)
    : { canPaste: false, canCopy: false, canCut: false, canClear: false, showCopyCut: !isPassword };

  useEffect(() => {
    if (!position) return;

    const handleOutsidePress = (event: Event) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        onClose();
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };

    const handleViewportChange = () => {
      onClose();
    };

    document.addEventListener("pointerdown", handleOutsidePress, true);
    document.addEventListener("mousedown", handleOutsidePress, true);
    document.addEventListener("touchstart", handleOutsidePress, true);
    document.addEventListener("keydown", handleKeyDown);
    window.addEventListener("scroll", handleViewportChange, true);
    window.addEventListener("resize", handleViewportChange);

    return () => {
      document.removeEventListener("pointerdown", handleOutsidePress, true);
      document.removeEventListener("mousedown", handleOutsidePress, true);
      document.removeEventListener("touchstart", handleOutsidePress, true);
      document.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("scroll", handleViewportChange, true);
      window.removeEventListener("resize", handleViewportChange);
    };
  }, [position, onClose]);

  if (!position) return null;

  const handleCopy = async () => {
    if (!el || !menuState.showCopyCut) return;
    const range = normalizeRange(el.value, el.selectionStart, el.selectionEnd);
    const selectedText = selectedOrAllText(el.value, range);
    if (selectedText) {
      try {
        await copyTextToClipboard(selectedText);
      } catch (err) {
        console.error("Copy failed", err);
      }
    }
    onClose();
  };

  const handleCut = async () => {
    if (!el || isReadOnly || !menuState.showCopyCut) return;
    const range = normalizeRange(el.value, el.selectionStart, el.selectionEnd);
    const selectedText = selectedOrAllText(el.value, range);
    if (selectedText) {
      try {
        await copyTextToClipboard(selectedText);
        const next = cutText(el.value, range);
        applyInputValue(el, next.value, next.caret);
      } catch (err) {
        console.error("Cut failed", err);
      }
    }
    onClose();
  };

  const handlePaste = async () => {
    if (!el || isReadOnly) return;
    try {
      const pasted = await readTextFromClipboard();
      if (pasted) {
        const range = normalizeRange(el.value, el.selectionStart, el.selectionEnd);
        const next = pasteText(el.value, range, pasted);
        applyInputValue(el, next.value, next.caret);
      }
    } catch (err) {
      console.error("Paste failed", err);
    }
    onClose();
  };

  const handleClear = () => {
    if (!el || isReadOnly) return;
    applyInputValue(el, "", 0);
    onClose();
  };

  const menuWidth = 196;
  const itemsCount = menuState.showCopyCut ? 4 : 2;
  const menuHeight = itemsCount * 36 + 12 + (itemsCount - 1) * 2;

  const viewportWidth = window.visualViewport ? window.visualViewport.width : window.innerWidth;
  const viewportHeight = window.visualViewport ? window.visualViewport.height : window.innerHeight;

  let x = position.x;
  let y = position.y > viewportHeight / 2 ? position.y - menuHeight - 10 : position.y + 10;

  x = Math.max(10, Math.min(x, viewportWidth - menuWidth - 10));
  y = Math.max(10, Math.min(y, viewportHeight - menuHeight - 10));

  return createPortal(
    <div
      ref={menuRef}
      className="chat-context-menu"
      style={{
        left: x,
        top: y,
        position: "fixed",
      }}
      role="menu"
    >
      <button
        type="button"
        className="chat-context-menu-item"
        onClick={handlePaste}
        disabled={!menuState.canPaste}
        role="menuitem"
      >
        <ClipboardPaste size={16} style={{ color: "var(--brand-emerald, #08a95f)" }} />
        <span>{t("common.paste")}</span>
      </button>

      {menuState.showCopyCut && (
        <button
          type="button"
          className="chat-context-menu-item"
          onClick={handleCopy}
          disabled={!menuState.canCopy}
          role="menuitem"
        >
          <Clipboard size={16} />
          <span>{t("common.copy")}</span>
        </button>
      )}

      {menuState.showCopyCut && (
        <button
          type="button"
          className="chat-context-menu-item"
          onClick={handleCut}
          disabled={!menuState.canCut}
          role="menuitem"
        >
          <Scissors size={16} />
          <span>{t("common.cut")}</span>
        </button>
      )}

      <button
        type="button"
        className="chat-context-menu-item destructive"
        onClick={handleClear}
        disabled={!menuState.canClear}
        role="menuitem"
      >
        <Trash2 size={16} />
        <span>{t("common.clear")}</span>
      </button>
    </div>,
    document.body,
  );
}
