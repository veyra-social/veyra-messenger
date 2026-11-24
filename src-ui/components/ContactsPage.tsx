import { memo, useCallback, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ArrowLeft, Check, MoreVertical, Plus, ShieldCheck, X } from "lucide-react";
import type { Contact } from "../lib/types";
import { api } from "../lib/tauriApi";
import { presenceLabel } from "../lib/format";
import { ContactRequests } from "./ContactRequests";
import { ContactContextMenu, type ContactMenuAction } from "./ContactContextMenu";
import { ConfirmDeleteContactDialog } from "./ConfirmDeleteContactDialog";

type Props = {
  contacts: Contact[];
  pendingRequests: Contact[];
  onAddContact: () => void;
  onOpenChat: (contactId: string) => void;
  onRefresh: () => Promise<void>;
  showMobileBack?: boolean;
  onMobileBack?: () => void;
};

// Mirrors ChatList.tsx long-press constants so contacts and chats feel
// identical: 8px move tolerance lets the user scroll without triggering
// the menu by accident; 550ms matches Android system long-press feel.
const LONG_PRESS_MOVE_TOLERANCE = 8;
const LONG_PRESS_DELAY_MS = 550;

type ContactRowProps = {
  contact: Contact;
  isEditing: boolean;
  editName: string;
  onEditNameChange: (value: string) => void;
  onSaveRename: () => void;
  onCancelRename: () => void;
  onOpenChat: (contactId: string) => void;
  onOpenMenu: (event: { clientX: number; clientY: number }, contactId: string) => void;
};

const ContactRow = memo(function ContactRow({
  contact,
  isEditing,
  editName,
  onEditNameChange,
  onSaveRename,
  onCancelRename,
  onOpenChat,
  onOpenMenu,
}: ContactRowProps) {
  const { t } = useTranslation();
  const online = contact.presence_status === "online";
  const verified = contact.trust_status === "verified";
  const blocked = contact.trust_status === "blocked";
  // The account's own row (it exists because the user added their own
  // invite, and it is what the Notes chat hangs on). It opens Notes and
  // nothing else: renaming, verifying, blocking or deleting yourself are all
  // nonsense, so this row carries no menu at all.
  const isSelf = !!contact.is_self;

  const longPressTimer = useRef<number | undefined>(undefined);
  const longPressFired = useRef(false);
  const pressOrigin = useRef<{ x: number; y: number } | null>(null);

  const cancelLongPress = useCallback(() => {
    if (longPressTimer.current !== undefined) {
      window.clearTimeout(longPressTimer.current);
      longPressTimer.current = undefined;
    }
    pressOrigin.current = null;
  }, []);

  const handlePointerDown = useCallback(
    (event: React.PointerEvent<HTMLButtonElement>) => {
      if (event.pointerType === "mouse" || isSelf) return;
      longPressFired.current = false;
      pressOrigin.current = { x: event.clientX, y: event.clientY };
      const clientX = event.clientX;
      const clientY = event.clientY;
      longPressTimer.current = window.setTimeout(() => {
        longPressFired.current = true;
        onOpenMenu({ clientX, clientY }, contact.local_id);
      }, LONG_PRESS_DELAY_MS);
    },
    [contact.local_id, isSelf, onOpenMenu],
  );

  const handlePointerMove = useCallback(
    (event: React.PointerEvent<HTMLButtonElement>) => {
      const origin = pressOrigin.current;
      if (!origin) return;
      const dx = event.clientX - origin.x;
      const dy = event.clientY - origin.y;
      if (dx * dx + dy * dy > LONG_PRESS_MOVE_TOLERANCE * LONG_PRESS_MOVE_TOLERANCE) {
        cancelLongPress();
      }
    },
    [cancelLongPress],
  );

  const handlePointerEnd = useCallback(() => {
    cancelLongPress();
  }, [cancelLongPress]);

  const handleClick = useCallback(() => {
    if (longPressFired.current) {
      longPressFired.current = false;
      return;
    }
    if (blocked) return;
    onOpenChat(contact.local_id);
  }, [blocked, contact.local_id, onOpenChat]);

  const handleContextMenu = useCallback(
    (event: React.MouseEvent<HTMLButtonElement>) => {
      event.preventDefault();
      event.stopPropagation();
      if (isSelf) return;
      onOpenMenu({ clientX: event.clientX, clientY: event.clientY }, contact.local_id);
    },
    [contact.local_id, isSelf, onOpenMenu],
  );

  const handleOverflowClick = useCallback(
    (event: React.MouseEvent<HTMLButtonElement>) => {
      event.stopPropagation();
      const rect = (event.currentTarget as HTMLButtonElement).getBoundingClientRect();
      onOpenMenu({ clientX: rect.right, clientY: rect.bottom }, contact.local_id);
    },
    [contact.local_id, onOpenMenu],
  );

  if (isEditing) {
    return (
      <div className={`contact-row editing ${blocked ? "blocked" : ""}`}>
        <input
          className="contact-row-rename-input"
          value={editName}
          onChange={(event) => onEditNameChange(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && editName.trim()) {
              event.preventDefault();
              onSaveRename();
            } else if (event.key === "Escape") {
              event.preventDefault();
              onCancelRename();
            }
          }}
          autoFocus
        />
        <button
          type="button"
          className="contact-row-edit-btn"
          title={t("common.save")}
          onClick={onSaveRename}
          disabled={!editName.trim()}
        >
          <Check size={16} />
        </button>
        <button
          type="button"
          className="contact-row-edit-btn"
          title={t("common.cancel")}
          onClick={onCancelRename}
        >
          <X size={16} />
        </button>
      </div>
    );
  }

  return (
    <div className={`contact-row ${blocked ? "blocked" : ""}`}>
      <button
        type="button"
        className="contact-row-body"
        onClick={handleClick}
        onContextMenu={handleContextMenu}
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerEnd}
        onPointerCancel={handlePointerEnd}
        onPointerLeave={handlePointerEnd}
      >
        {/* The self row keeps the same lamp slot so the name column stays
            aligned; it is lit because this device is the "peer". */}
        <span
          className={`presence-dot ${isSelf || online ? "online" : "offline"}`}
          aria-hidden="true"
        />
        <span className="contact-row-text">
          <span className="contact-row-title">
            <strong>{isSelf ? t("chat.notes") : contact.display_name}</strong>
            {!isSelf && verified && (
              <ShieldCheck size={14} className="verified-tick" aria-label={t("common.verified")} />
            )}
            {!isSelf && blocked && (
              <span className="badge badge-blocked">{t("contacts.blocked")}</span>
            )}
          </span>
          <small className="contact-row-presence">
            {isSelf
              ? t("contacts.selfHint")
              : presenceLabel(contact.presence_status, contact.last_seen_at)}
          </small>
        </span>
      </button>
      {!isSelf && (
        <button
          type="button"
          className="contact-row-overflow"
          onClick={handleOverflowClick}
          aria-label={t("contactMenu.openMenu")}
        >
          <MoreVertical size={18} />
        </button>
      )}
    </div>
  );
});

export function ContactsPage({
  contacts,
  pendingRequests,
  onAddContact,
  onOpenChat,
  onRefresh,
  showMobileBack,
  onMobileBack,
}: Props) {
  const { t } = useTranslation();
  const [editing, setEditing] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [error, setError] = useState("");
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [menuFor, setMenuFor] = useState<{ contactId: string; x: number; y: number } | null>(null);

  const closeMenu = useCallback(() => setMenuFor(null), []);

  const handleOpenMenu = useCallback(
    (event: { clientX: number; clientY: number }, contactId: string) => {
      // Don't open a menu over a row that is currently being renamed inline;
      // the inline editor owns the focus and Save/Cancel buttons.
      if (editing === contactId) return;
      setMenuFor({ contactId, x: event.clientX, y: event.clientY });
    },
    [editing],
  );

  const startEdit = useCallback((contact: Contact) => {
    setEditing(contact.local_id);
    setEditName(contact.display_name);
    setError("");
  }, []);

  async function run(action: () => Promise<unknown>) {
    setError("");
    try {
      await action();
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("common.actionFailed"));
    }
  }

  async function saveRename(contactId: string) {
    const value = editName.trim();
    if (!value) {
      setError(t("contacts.emptyDisplayName"));
      return;
    }
    await run(async () => {
      await api.renameContact(contactId, value);
      setEditing(null);
    });
  }

  const sorted = [...contacts].sort((a, b) => {
    // Notes sits on top, the way the self chat is pinned above every other
    // chat in the list.
    if (!!a.is_self !== !!b.is_self) return a.is_self ? -1 : 1;
    if (a.trust_status === "blocked" && b.trust_status !== "blocked") return 1;
    if (b.trust_status === "blocked" && a.trust_status !== "blocked") return -1;
    return a.display_name.localeCompare(b.display_name);
  });
  // Notes is not a contact: a list holding nothing else is still empty, and
  // the "add your first contact" prompt has to stay visible.
  const hasOtherContacts = contacts.some((contact) => !contact.is_self);

  const menuContact = menuFor
    ? contacts.find((c) => c.local_id === menuFor.contactId) ?? null
    : null;
  const confirmContact = confirmDelete
    ? contacts.find((c) => c.local_id === confirmDelete) ?? null
    : null;

  function handleMenuAction(contact: Contact, action: ContactMenuAction) {
    closeMenu();
    if (action === "rename") {
      startEdit(contact);
      return;
    }
    if (action === "block") {
      void run(() => api.blockContact(contact.local_id));
      return;
    }
    if (action === "unblock") {
      void run(() => api.unblockContact(contact.local_id));
      return;
    }
    if (action === "delete") {
      setConfirmDelete(contact.local_id);
      return;
    }
  }

  return (
    <div className="contacts-page">
      <header className="settings-header contacts-page-header">
        <div className="settings-header-row contacts-header-row">
          {showMobileBack && onMobileBack && (
            <button
              type="button"
              className="mobile-back-btn"
              onClick={onMobileBack}
              aria-label={t("common.backToChatList")}
            >
              <ArrowLeft size={22} strokeWidth={2} />
            </button>
          )}
          <h1>{t("contacts.title")}</h1>
          <button className="primary" onClick={onAddContact}>
            <Plus size={16} /> {t("contacts.addContact")}
          </button>
        </div>
      </header>

      <div className="settings-content">
        <ContactRequests requests={pendingRequests} onChanged={onRefresh} />

      {error && <p className="error">{error}</p>}

      {sorted.length > 0 && (
        <div className="contacts-list">
          {sorted.map((contact) => (
            <ContactRow
              key={contact.local_id}
              contact={contact}
              isEditing={editing === contact.local_id}
              editName={editName}
              onEditNameChange={setEditName}
              onSaveRename={() => saveRename(contact.local_id)}
              onCancelRename={() => setEditing(null)}
              onOpenChat={onOpenChat}
              onOpenMenu={handleOpenMenu}
            />
          ))}
        </div>
      )}

      {!hasOtherContacts && (
        <div className="contacts-empty">
          <p>{t("contacts.emptyTitle")}</p>
          <p className="hint">{t("contacts.emptyHint")}</p>
        </div>
      )}

      </div>

      {menuFor && menuContact && (
        <ContactContextMenu
          contact={menuContact}
          x={menuFor.x}
          y={menuFor.y}
          onAction={(action) => handleMenuAction(menuContact, action)}
          onClose={closeMenu}
        />
      )}

      {confirmDelete && confirmContact && (
        <ConfirmDeleteContactDialog
          contact={confirmContact}
          onCancel={() => setConfirmDelete(null)}
          onConfirm={async () => {
            await run(async () => {
              await api.deleteContact(confirmContact.local_id);
              setConfirmDelete(null);
            });
          }}
        />
      )}
    </div>
  );
}
