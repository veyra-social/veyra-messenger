import { Paperclip, Send, Smile, X } from "lucide-react";
import { useCallback, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { EmojiPicker } from "./EmojiPicker";
import { useInputContextMenu } from "../lib/useInputContextMenu";
import { InputContextMenu } from "./InputContextMenu";
import { MAX_ATTACHMENT_BYTES } from "../lib/attachmentUpload";

export type ComposerQuotePreview = {
  authorName: string;
  excerpt: string;
};

type Props = {
  onSend: (text: string) => Promise<void>;
  onSendAttachment?: (file: File, caption: string) => Promise<void>;
  onAttach: () => void;
  onAttachmentTooLarge?: (limitBytes: number) => void;
  onComposerFocus?: () => void;
  quotePreview?: ComposerQuotePreview | null;
  onClearQuote?: () => void;
};

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GiB`;
}

export function MessageInput({
  onSend,
  onSendAttachment,
  onAttach,
  onAttachmentTooLarge,
  onComposerFocus,
  quotePreview,
  onClearQuote,
}: Props) {
  const { t } = useTranslation();
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [showEmoji, setShowEmoji] = useState(false);
  const [attachment, setAttachment] = useState<File | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const textMenu = useInputContextMenu();

  function focusComposer() {
    requestAnimationFrame(() => inputRef.current?.focus());
  }

  async function commitSend() {
    const trimmed = text.trim();
    if ((!trimmed && !attachment) || busy) return;
    setBusy(true);
    setShowEmoji(false);
    inputRef.current?.focus();
    try {
      if (attachment) {
        const file = attachment;
        setAttachment(null);
        setText("");
        await onSendAttachment?.(file, trimmed);
      } else {
        setText("");
        await onSend(trimmed);
      }
      inputRef.current?.focus();
    } finally {
      setBusy(false);
    }
  }

  function chooseAttachment(file: File | null) {
    if (!file) return;
    if (file.size > MAX_ATTACHMENT_BYTES) {
      onAttachmentTooLarge?.(MAX_ATTACHMENT_BYTES);
      return;
    }
    setAttachment(file);
    inputRef.current?.focus();
  }

  const insertEmoji = useCallback((emoji: string) => {
    const el = inputRef.current;
    const start = el?.selectionStart ?? text.length;
    const end = el?.selectionEnd ?? text.length;
    const next = text.slice(0, start) + emoji + text.slice(end);
    setText(next);
    // Restore focus + place the caret right after the inserted emoji on
    // the next paint, once React has flushed the new value into the DOM.
    // setSelectionRange uses UTF-16 code-unit indexes, so `emoji.length`
    // is the right offset for both BMP and surrogate-pair emoji.
    requestAnimationFrame(() => {
      const target = inputRef.current;
      if (!target) return;
      target.focus();
      const pos = start + emoji.length;
      try {
        target.setSelectionRange(pos, pos);
      } catch {
        /* setSelectionRange isn't supported on every input type; ignore. */
      }
    });
  }, [text]);

  const hasComposerPreview = Boolean(quotePreview || attachment);

  return (
    <form
      className="message-input"
      onSubmit={(event) => {
        event.preventDefault();
        void commitSend();
      }}
    >
      {hasComposerPreview && (
        <div className="composer-preview-stack">
          {quotePreview && (
            <div className="composer-quote-chip" role="status" aria-live="polite">
              <div className="composer-quote-chip-body">
                <small className="composer-quote-chip-author">{quotePreview.authorName}</small>
                <span className="composer-quote-chip-text">{quotePreview.excerpt}</span>
              </div>
              {onClearQuote && (
                <button
                  type="button"
                  className="composer-quote-chip-clear"
                  onPointerDown={(event) => event.preventDefault()}
                  onClick={() => {
                    onClearQuote();
                    focusComposer();
                  }}
                  aria-label={t("messageMenu.clearQuote")}
                  title={t("messageMenu.clearQuote")}
                >
                  <X size={16} />
                </button>
              )}
            </div>
          )}
          {attachment && (
            <div className="composer-attachment-chip" role="status" aria-live="polite">
              <div className="composer-attachment-chip-body">
                <small>{t("attachments.selected")}</small>
                <span>{attachment.name}</span>
                <small>{formatFileSize(attachment.size)}</small>
              </div>
              <button
                type="button"
                className="composer-quote-chip-clear"
                onPointerDown={(event) => event.preventDefault()}
                onClick={() => {
                  setAttachment(null);
                  focusComposer();
                }}
                aria-label={t("attachments.remove")}
                title={t("attachments.remove")}
              >
                <X size={16} />
              </button>
            </div>
          )}
        </div>
      )}
      <div className="composer-controls">
        <div className="composer-pill">
          <div className="emoji-toggle-wrap">
            <button
              type="button"
              className="input-tool-btn emoji-toggle-btn"
              onClick={() => setShowEmoji((v) => !v)}
              title={t("chat.emoji")}
              aria-expanded={showEmoji}
              aria-haspopup="dialog"
            >
              <Smile size={18} />
            </button>
            {showEmoji && (
              <EmojiPicker
                onSelect={insertEmoji}
                onClose={() => setShowEmoji(false)}
              />
            )}
          </div>
          <button
            type="button"
            className="input-tool-btn"
            onClick={() => {
              if (!onSendAttachment) {
                onAttach();
                return;
              }
              fileInputRef.current?.click();
            }}
            title={t("chat.attach")}
            disabled={busy}
          >
            <Paperclip size={18} />
          </button>
          <input
            ref={fileInputRef}
            type="file"
            className="composer-file-input"
            onChange={(event) => {
              chooseAttachment(event.target.files?.[0] ?? null);
              event.currentTarget.value = "";
            }}
          />
          <input
            ref={inputRef}
            value={text}
            onChange={(event) => setText(event.target.value)}
            onFocus={() => onComposerFocus?.()}
            placeholder={t("chat.messagePlaceholder")}
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="sentences"
            spellCheck={false}
            enterKeyHint="send"
            {...textMenu.bind}
          />
          <InputContextMenu
            position={textMenu.menuPosition}
            onClose={textMenu.closeMenu}
            inputRef={inputRef}
          />
        </div>
        <button
          type="submit"
          className="send-btn"
          disabled={busy || (!text.trim() && !attachment)}
          title={t("chat.send")}
          onPointerDown={(event) => event.preventDefault()}
        >
          <Send size={18} />
        </button>
      </div>
    </form>
  );
}
