import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";

type Props = {
  onSelect: (emoji: string) => void;
  onClose: () => void;
};

// Hand-picked Unicode emoji set: faces (smiles/expressions/emotions/face
// actions), hearts, hand gestures, common symbols. No npm dep — emoji are
// just Unicode characters and travel over the existing text message wire
// envelope as-is, so this stays a pure UI feature with no protocol or
// schema implication. Reactions on messages (separate from inline insert)
// remain a future protocol-v2 capability.
const EMOJI: ReadonlyArray<string> = [
  // Smiles
  "😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣",
  "😊", "😇", "🙂", "🙃", "😉", "😌", "😍", "🥰",
  "😘", "😗", "😙", "😚", "😋", "😛", "😝", "😜",
  // Expressions
  "🤪", "🤨", "🧐", "🤓", "😎", "🤩", "🥳", "😏",
  "😒", "😞", "😔", "😟", "😕", "🙁", "☹️", "😣",
  "😖", "😫", "😩", "🥺", "😢", "😭", "😤", "😠",
  // Emotions / states
  "😡", "🤬", "🤯", "😳", "🥵", "🥶", "😱", "😨",
  "😰", "😥", "😓", "🤗", "🤔", "🤭", "🤫", "🤥",
  "😶", "😐", "😑", "😬", "🙄", "😯", "😦", "😧",
  "😮", "😲", "🥱", "😴", "🤤", "😪", "😵", "🤐",
  "🤧", "🤒", "🤕", "🤑", "🤠", "😈", "👿", "💀",
  "👻", "🤖", "🎃", "💩",
  // Hearts
  "❤️", "🧡", "💛", "💚", "💙", "💜", "🖤", "🤍",
  "🤎", "💔", "💕", "💞", "💓", "💗", "💖", "💘",
  "💝", "💟",
  // Hand gestures
  "👍", "👎", "👌", "✌️", "🤞", "🤟", "🤘", "🤙",
  "👈", "👉", "👆", "👇", "☝️", "✋", "🤚", "🖐️",
  "🖖", "👋", "🤝", "🙏", "💪", "👏",
  // Common symbols
  "🎉", "🎊", "🔥", "⭐", "🌟", "✨", "⚡", "💯",
  "✅", "❌", "❓", "❗", "⚠️", "💡", "🎁", "🌹",
  "🌸", "🌈", "☀️", "🌙", "☕", "🍕", "🍻", "🎵",
];

export function EmojiPicker({ onSelect, onClose }: Props) {
  const { t } = useTranslation();
  const popoverRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onKeydown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.stopPropagation();
        onClose();
      }
    }
    function onPointerDown(event: PointerEvent) {
      const popover = popoverRef.current;
      if (!popover) return;
      const target = event.target as Node | null;
      if (target && popover.contains(target)) return;
      // Also ignore clicks on the toggle button itself — the parent
      // component handles re-toggling and we don't want a double-close.
      if (target instanceof HTMLElement && target.closest(".emoji-toggle-btn")) {
        return;
      }
      onClose();
    }
    document.addEventListener("keydown", onKeydown);
    document.addEventListener("pointerdown", onPointerDown);
    return () => {
      document.removeEventListener("keydown", onKeydown);
      document.removeEventListener("pointerdown", onPointerDown);
    };
  }, [onClose]);

  return (
    <div
      ref={popoverRef}
      className="emoji-picker-popover"
      role="dialog"
      aria-label={t("chat.emoji")}
    >
      <div className="emoji-picker-grid">
        {EMOJI.map((emoji) => (
          <button
            key={emoji}
            type="button"
            className="emoji-picker-item"
            onClick={() => onSelect(emoji)}
            // Prevent the input from losing focus when an emoji is
            // tapped — without this the next paint moves the caret to
            // the end of the input on some platforms and the click also
            // dismisses the on-screen keyboard on Android.
            onPointerDown={(event) => event.preventDefault()}
            onMouseDown={(event) => event.preventDefault()}
            aria-label={emoji}
          >
            {emoji}
          </button>
        ))}
      </div>
    </div>
  );
}
