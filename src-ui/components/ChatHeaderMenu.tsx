import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Eraser,
  IdCard,
  Phone,
  RotateCcw,
  BarChart3,
} from "lucide-react";

export type ChatHeaderAction =
  | "profile"
  | "call"
  | "stats"
  | "restore"
  | "clear";

type Props = {
  anchorRect: DOMRect;
  onAction: (action: ChatHeaderAction) => void;
  onClose: () => void;
};

export function ChatHeaderMenu({ anchorRect, onAction, onClose }: Props) {
  const { t } = useTranslation();
  const ref = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState<{ left: number; top: number }>({
    left: anchorRect.right,
    top: anchorRect.bottom + 6,
  });

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const margin = 8;
    const desiredLeft = anchorRect.right - rect.width;
    const desiredTop = anchorRect.bottom + 6;
    const maxLeft = window.innerWidth - rect.width - margin;
    const maxTop = window.innerHeight - rect.height - margin;
    setPosition({
      left: Math.max(margin, Math.min(desiredLeft, maxLeft)),
      top: Math.max(margin, Math.min(desiredTop, maxTop)),
    });
  }, [anchorRect.right, anchorRect.bottom]);

  useEffect(() => {
    function onDocMouseDown(event: MouseEvent) {
      if (!ref.current) return;
      if (!ref.current.contains(event.target as Node)) onClose();
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    document.addEventListener("mousedown", onDocMouseDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocMouseDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  const items: Array<{ action: ChatHeaderAction; label: string; Icon: typeof Phone }> = [
    { action: "profile", label: t("chatHeaderMenu.profile"), Icon: IdCard },
    { action: "call", label: t("chatHeaderMenu.call"), Icon: Phone },
    { action: "stats", label: t("chatHeaderMenu.stats"), Icon: BarChart3 },
    { action: "restore", label: t("chatHeaderMenu.restore"), Icon: RotateCcw },
    { action: "clear", label: t("chatHeaderMenu.clear"), Icon: Eraser },
  ];

  return (
    <div
      ref={ref}
      className="chat-context-menu chat-header-menu"
      role="menu"
      style={{ left: position.left, top: position.top }}
      onContextMenu={(event) => event.preventDefault()}
    >
      {items.map(({ action, label, Icon }) => (
        <button
          key={action}
          type="button"
          role="menuitem"
          className="chat-context-menu-item"
          onClick={() => onAction(action)}
        >
          <Icon size={15} />
          <span>{label}</span>
        </button>
      ))}
    </div>
  );
}
