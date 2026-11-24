import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { save } from "@tauri-apps/plugin-dialog";
import { ArrowLeft, Check, Copy, Edit3, ImagePlus, Loader2, Plus, QrCode, Save, Trash2, X } from "lucide-react";
import type { LocalProfileSummary, MyProfile, ProfileExtensions, ProfileField, ProfileLink, ProfileLinkType } from "../lib/types";
import { api } from "../lib/tauriApi";
import { isDebugUi } from "../uiMode";
import { copyTextToClipboard } from "../lib/clipboard";
import { setBackupKeepScreenOn } from "../lib/nativeBridge";
import { useIsAndroid, useIsIOS } from "../lib/usePlatform";
import {
  base64ToBytes,
  hasNativeBackupPickers,
  pickBackupExportPath,
  safeFileStem,
  timestampForFilename,
  writeTempFileToPath,
  writeBytesToPath,
} from "../lib/backupIO";
import { InviteQrView } from "./InviteQrView";
import { UserAvatar } from "./UserAvatar";

const MAX_INPUT_BYTES = 256 * 1024;
const PROFILE_LINK_TYPES: ProfileLinkType[] = [
  "website",
  "telegram",
  "whatsapp",
  "vk",
  "instagram",
  "facebook",
  "youtube",
  "tiktok",
  "other",
];
const PROFILE_LINK_SCHEMES = new Set(["http", "https", "tg", "tel", "mailto"]);
const textInputProps = {
  autoCapitalize: "none",
  autoCorrect: "off",
  spellCheck: false,
} as const;

type ProfileCardFieldName = Exclude<keyof ProfileExtensions, "links">;
type ProfileCardLinkErrors = Partial<Record<"type" | "label" | "url", string>>;
type ProfileCardErrors = Partial<Record<ProfileCardFieldName, string>> & {
  links: Record<number, ProfileCardLinkErrors>;
};

function emptyCardErrors(): ProfileCardErrors {
  return { links: {} };
}

function hasCardErrors(errors: ProfileCardErrors): boolean {
  return (
    !!errors.about ||
    !!errors.status ||
    !!errors.mood ||
    !!errors.email ||
    !!errors.phone ||
    Object.values(errors.links).some((linkErrors) => Object.keys(linkErrors).length > 0)
  );
}

function charCount(value: string): number {
  return Array.from(value).length;
}

function withContactsField(field: ProfileField, value: string): ProfileField {
  return { ...field, value, visibility: "contacts" };
}

function validateEmailValue(value: string): boolean {
  if (!value) return true;
  if (/\s/.test(value)) return false;
  const parts = value.split("@");
  return parts.length === 2 && parts[0].length > 0 && parts[1].includes(".");
}

function validatePhoneValue(value: string): boolean {
  return /^[0-9+\- ().]*$/.test(value);
}

function validateProfileUrl(value: string): boolean {
  const separator = value.indexOf(":");
  if (separator <= 0 || separator === value.length - 1) return false;
  return PROFILE_LINK_SCHEMES.has(value.slice(0, separator).toLowerCase());
}

function emptyProfileField(): ProfileField {
  return { value: "", visibility: "contacts" };
}

function defaultProfileExtensions(): ProfileExtensions {
  return {
    about: emptyProfileField(),
    status: emptyProfileField(),
    mood: emptyProfileField(),
    email: emptyProfileField(),
    phone: emptyProfileField(),
    links: [],
  };
}

function withProfileDefaults(value?: ProfileExtensions | null): ProfileExtensions {
  const base = defaultProfileExtensions();
  if (!value) return base;
  return {
    about: { ...base.about, ...value.about },
    status: { ...base.status, ...value.status },
    mood: { ...base.mood, ...value.mood },
    email: { ...base.email, ...value.email },
    phone: { ...base.phone, ...value.phone },
    links: Array.isArray(value.links) ? value.links.map((link) => ({ ...link })) : [],
  };
}

type Props = {
  profile: MyProfile;
  showMobileBack?: boolean;
  onMobileBack?: () => void;
  onProfileChanged?: () => Promise<void>;
};

function blobToBase64(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const r = reader.result as string;
      const i = r.indexOf(",");
      resolve(i >= 0 ? r.slice(i + 1) : r);
    };
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(blob);
  });
}

function loadImage(src: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error("decode"));
    img.src = src;
  });
}

/** Downscale in-browser so uploads stay under the Rust input cap; server still normalizes. */
async function prepareAvatarForUpload(file: File): Promise<string> {
  const url = URL.createObjectURL(file);
  try {
    const img = await loadImage(url);
    const maxEdge = 512;
    let w = img.naturalWidth;
    let h = img.naturalHeight;
    if (!w || !h) {
      throw new Error("bad image");
    }
    const scale = Math.min(1, maxEdge / Math.max(w, h));
    w = Math.round(w * scale);
    h = Math.round(h * scale);
    const canvas = document.createElement("canvas");
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext("2d");
    if (!ctx) {
      throw new Error("no canvas");
    }
    ctx.drawImage(img, 0, 0, w, h);
    let b64: string | null = null;
    for (const q of [0.88, 0.82, 0.75, 0.68, 0.62]) {
      const blob = await new Promise<Blob | null>((res) =>
        canvas.toBlob(res, "image/jpeg", q),
      );
      if (!blob) continue;
      if (blob.size <= MAX_INPUT_BYTES || q === 0.62) {
        b64 = await blobToBase64(blob);
        break;
      }
    }
    if (!b64) {
      throw new Error("encode");
    }
    return b64;
  } finally {
    URL.revokeObjectURL(url);
  }
}

export function ProfilePage({ profile, showMobileBack, onMobileBack, onProfileChanged }: Props) {
  const { t } = useTranslation();
  const isAndroid = useIsAndroid();
  const isIOS = useIsIOS();
  const [toast, setToast] = useState<string | null>(null);
  const [otherProfiles, setOtherProfiles] = useState<LocalProfileSummary[]>([]);
  const [deleteTarget, setDeleteTarget] = useState<LocalProfileSummary | null>(null);
  const [deleteKeepBackup, setDeleteKeepBackup] = useState(true);
  const [deletePassword, setDeletePassword] = useState("");
  const [deleteBusy, setDeleteBusy] = useState<"backup" | "delete" | null>(null);
  const [deleteError, setDeleteError] = useState("");
  const [qrInviteValue, setQrInviteValue] = useState("");
  const [qrBusy, setQrBusy] = useState(false);
  const [photoBusy, setPhotoBusy] = useState(false);
  const [photoError, setPhotoError] = useState("");
  const [nameEditing, setNameEditing] = useState(false);
  const [nameDraft, setNameDraft] = useState(profile.display_name);
  const [nameBusy, setNameBusy] = useState(false);
  const [nameError, setNameError] = useState("");
  const [card, setCard] = useState<ProfileExtensions>(() => withProfileDefaults(profile.profile_extensions));
  const [cardBusy, setCardBusy] = useState(false);
  const [cardMessage, setCardMessage] = useState("");
  const [cardError, setCardError] = useState("");
  const [cardErrors, setCardErrors] = useState<ProfileCardErrors>(() => emptyCardErrors());
  const keepCardDraftOnProfileRefresh = useRef(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (keepCardDraftOnProfileRefresh.current) {
      keepCardDraftOnProfileRefresh.current = false;
      return;
    }
    setCard(withProfileDefaults(profile.profile_extensions));
    setCardMessage("");
    setCardError("");
    setCardErrors(emptyCardErrors());
  }, [profile.profile_extensions]);

  useEffect(() => {
    if (!nameEditing) setNameDraft(profile.display_name);
  }, [nameEditing, profile.display_name]);

  function showToast(message: string) {
    setToast(message);
    window.setTimeout(() => setToast(null), 1500);
  }

  const reloadOtherProfiles = useCallback(async () => {
    try {
      const profiles = await api.listLocalProfiles();
      setOtherProfiles(profiles.filter((entry) => !entry.active));
    } catch {
      // The registry is UI sugar; a failed read just hides the block.
      setOtherProfiles([]);
    }
  }, []);

  useEffect(() => {
    void reloadOtherProfiles();
  }, [reloadOtherProfiles]);

  function requestDeleteProfile(target: LocalProfileSummary) {
    setDeleteTarget(target);
    setDeleteKeepBackup(true);
    setDeletePassword("");
    setDeleteError("");
  }

  function closeDeleteModal() {
    if (deleteBusy) return;
    setDeleteTarget(null);
  }

  // Pre-delete backup: a standard full `.vmb` of the LOCKED profile, opened
  // and encrypted with its own master password (one field, one secret — the
  // password that opens the vault is the password that opens the backup).
  // Returns false when the user cancels the save dialog.
  async function saveBackupForDelete(target: LocalProfileSummary): Promise<boolean> {
    const defaultFilename = `${safeFileStem(target.display_name || "veyra-profile")}-${timestampForFilename()}.vmb`;
    let path: string | null = null;
    if (isAndroid && hasNativeBackupPickers()) {
      path = await pickBackupExportPath(defaultFilename);
    } else {
      const chosen = await save({
        title: t("backup.saveDialogTitle"),
        defaultPath: defaultFilename,
        filters: [{ name: t("backup.vmbFiles"), extensions: ["vmb"] }],
      });
      if (!chosen) return false;
      path =
        chosen.toLowerCase().endsWith(".vmb") || chosen.startsWith("content://")
          ? chosen
          : `${chosen}.vmb`;
    }
    if (!path) return false;
    setDeleteBusy("backup");
    setBackupKeepScreenOn(true);
    try {
      if (isAndroid) {
        let tempPath: string | null = null;
        try {
          tempPath = await api.exportLocalProfileBackupTempFile(target.id, deletePassword);
          const copiedFromTemp = await writeTempFileToPath(path, tempPath);
          if (!copiedFromTemp) {
            const b64 = await api.serializeLocalProfileBackup(target.id, deletePassword);
            await writeBytesToPath(path, base64ToBytes(b64));
          }
        } finally {
          if (tempPath) {
            void api.deleteBackupTempFile(tempPath).catch(() => {});
          }
        }
      } else if (isIOS) {
        const b64 = await api.serializeLocalProfileBackup(target.id, deletePassword);
        await writeBytesToPath(path, base64ToBytes(b64));
      } else {
        await api.exportLocalProfileBackup(target.id, deletePassword, path);
      }
    } finally {
      setBackupKeepScreenOn(false);
    }
    return true;
  }

  async function confirmDeleteProfile() {
    const target = deleteTarget;
    if (!target || deleteBusy) return;
    setDeleteError("");
    try {
      if (deleteKeepBackup) {
        if (!deletePassword) return;
        const saved = await saveBackupForDelete(target);
        if (!saved) {
          // Save dialog cancelled: stay in the confirmation, delete nothing.
          setDeleteBusy(null);
          return;
        }
      }
      setDeleteBusy("delete");
      await api.deleteLocalProfile(target.id);
      setDeleteBusy(null);
      setDeleteTarget(null);
      showToast(t("profile.others.deleted"));
      await reloadOtherProfiles();
    } catch (err) {
      setDeleteBusy(null);
      const code =
        err && typeof err === "object" && "code" in err
          ? String((err as { code: unknown }).code)
          : "";
      if (code === "wrong_password") {
        setDeleteError(t("auth.wrongPassword"));
        return;
      }
      const message =
        err instanceof Error
          ? err.message
          : err && typeof err === "object" && "message" in err &&
              typeof (err as { message?: unknown }).message === "string"
            ? (err as { message: string }).message
            : "";
      setDeleteError(message || t("profile.others.deleteFailed"));
    }
  }

  async function copy(value: string, message: string) {
    await copyTextToClipboard(value);
    showToast(message);
  }

  async function copyInvite() {
    try {
      const invite = await api.generateInviteString();
      await copy(invite, t("profile.inviteCopied"));
    } catch {
      await copy(profile.invite_string, t("profile.inviteCopied"));
    }
  }

  async function copyProfileId() {
    await copy(profile.fingerprint, t("profile.idCopied"));
  }

  async function showInviteQr() {
    if (qrBusy) return;
    setQrBusy(true);
    try {
      const invite = await api.generateInviteString();
      setQrInviteValue(invite);
    } catch {
      setQrInviteValue(profile.invite_string);
    } finally {
      setQrBusy(false);
    }
  }

  const closeInviteQr = useCallback(() => {
    setQrInviteValue("");
  }, []);

  async function onAvatarFileChange(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || !onProfileChanged) return;

    setPhotoError("");
    setPhotoBusy(true);
    try {
      await new Promise<void>((resolve) => window.requestAnimationFrame(() => resolve()));
      const jpegBase64 = await prepareAvatarForUpload(file);
      await api.setMyAvatarJpeg(jpegBase64);
      await onProfileChanged();
    } catch (err) {
      const code =
        err && typeof err === "object" && "code" in err
          ? String((err as { code: unknown }).code)
          : "";
      const msg = err instanceof Error ? err.message : "";
      const invalid =
        code === "invalid_avatar_image" || /invalid.?avatar/i.test(msg) || /invalid_avatar/i.test(msg);
      setPhotoError(invalid ? t("profile.photoInvalid") : t("profile.photoFailed"));
    } finally {
      setPhotoBusy(false);
    }
  }

  async function clearAvatar() {
    if (!onProfileChanged) return;
    setPhotoError("");
    setPhotoBusy(true);
    try {
      await api.clearMyAvatar();
      await onProfileChanged();
    } catch {
      setPhotoError(t("profile.photoFailed"));
    } finally {
      setPhotoBusy(false);
    }
  }

  async function saveDisplayName() {
    const nextName = nameDraft.trim();
    if (!nextName) {
      setNameError(t("profile.nameEmpty"));
      return;
    }
    if (nextName === profile.display_name) {
      setNameEditing(false);
      setNameError("");
      return;
    }
    setNameBusy(true);
    setNameError("");
    try {
      await api.renameProfile(nextName);
      await onProfileChanged?.();
      setNameEditing(false);
      showToast(t("profile.nameSaved"));
    } catch {
      setNameError(t("profile.nameFailed"));
    } finally {
      setNameBusy(false);
    }
  }

  function updateField(name: keyof Omit<ProfileExtensions, "links">, patch: Partial<ProfileField>) {
    setCardMessage("");
    setCardError("");
    setCardErrors((current) => ({ ...current, [name]: undefined }));
    setCard((current) => ({
      ...current,
      [name]: { ...current[name], ...patch },
    }));
  }

  function updateLink(index: number, patch: Partial<ProfileLink>) {
    setCardMessage("");
    setCardError("");
    setCardErrors((current) => {
      const nextLinkErrors = { ...current.links };
      const currentLinkErrors = { ...nextLinkErrors[index] };
      if ("type" in patch) delete currentLinkErrors.type;
      if ("label" in patch) delete currentLinkErrors.label;
      if ("url" in patch) delete currentLinkErrors.url;
      if (Object.keys(currentLinkErrors).length) {
        nextLinkErrors[index] = currentLinkErrors;
      } else {
        delete nextLinkErrors[index];
      }
      return { ...current, links: nextLinkErrors };
    });
    setCard((current) => ({
      ...current,
      links: current.links.map((link, i) => (i === index ? { ...link, ...patch } : link)),
    }));
  }

  function addLink() {
    setCardError("");
    setCardMessage("");
    if (card.links.length >= 10) {
      setCardError(t("profile.card.linkLimit"));
      return;
    }
    setCard((current) => ({
      ...current,
      links: [
        ...current.links,
        { type: "website", label: "", url: "", visibility: "contacts" },
      ],
    }));
  }

  function removeLink(index: number) {
    setCardMessage("");
    setCardError("");
    setCardErrors((current) => {
      const links: Record<number, ProfileCardLinkErrors> = {};
      Object.entries(current.links).forEach(([key, value]) => {
        const linkIndex = Number(key);
        if (Number.isNaN(linkIndex) || linkIndex === index) return;
        links[linkIndex > index ? linkIndex - 1 : linkIndex] = value;
      });
      return { ...current, links };
    });
    setCard((current) => ({
      ...current,
      links: current.links.filter((_, i) => i !== index),
    }));
  }

  function validateProfileCardDraft(): { publicCard: ProfileExtensions; errors: ProfileCardErrors } {
    const previous = withProfileDefaults(profile.profile_extensions);
    const errors = emptyCardErrors();
    const publicCard: ProfileExtensions = {
      about: { ...previous.about, visibility: "contacts" },
      status: { ...previous.status, visibility: "contacts" },
      mood: { ...previous.mood, visibility: "contacts" },
      email: { ...previous.email, visibility: "contacts" },
      phone: { ...previous.phone, visibility: "contacts" },
      links: [],
    };

    const copyField = (name: ProfileCardFieldName, maxChars: number) => {
      const value = card[name].value.trim();
      if (charCount(value) > maxChars) {
        errors[name] = t("profile.card.errors.tooLong", { max: maxChars });
        return;
      }
      publicCard[name] = withContactsField(card[name], value);
    };

    copyField("about", 2000);
    copyField("status", 140);
    copyField("mood", 64);

    const email = card.email.value.trim();
    if (charCount(email) > 254) {
      errors.email = t("profile.card.errors.tooLong", { max: 254 });
    } else if (!validateEmailValue(email)) {
      errors.email = t("profile.card.errors.email");
    } else {
      publicCard.email = withContactsField(card.email, email);
    }

    const phone = card.phone.value.trim();
    if (charCount(phone) > 40) {
      errors.phone = t("profile.card.errors.tooLong", { max: 40 });
    } else if (!validatePhoneValue(phone)) {
      errors.phone = t("profile.card.errors.phone");
    } else {
      publicCard.phone = withContactsField(card.phone, phone);
    }

    card.links.slice(0, 10).forEach((link, index) => {
      const linkErrors: ProfileCardLinkErrors = {};
      const type = PROFILE_LINK_TYPES.includes(link.type as ProfileLinkType)
        ? (link.type as ProfileLinkType)
        : "website";
      const label = (link.label ?? "").trim();
      const url = link.url.trim();

      if (!PROFILE_LINK_TYPES.includes(link.type as ProfileLinkType)) {
        linkErrors.type = t("profile.card.errors.linkType");
      }
      if (charCount(label) > 80) {
        linkErrors.label = t("profile.card.errors.tooLong", { max: 80 });
      }
      if (!url) {
        if (label) linkErrors.url = t("profile.card.errors.linkUrlRequired");
      } else if (charCount(url) > 2048) {
        linkErrors.url = t("profile.card.errors.tooLong", { max: 2048 });
      } else if (!validateProfileUrl(url)) {
        linkErrors.url = t("profile.card.errors.linkUrl");
      }

      if (Object.keys(linkErrors).length) {
        errors.links[index] = linkErrors;
        const previousLink = previous.links[index];
        if (previousLink) {
          publicCard.links.push({ ...previousLink, visibility: "contacts" });
        }
        return;
      }
      if (!url) return;
      publicCard.links.push({
        type,
        label: label || undefined,
        url,
        visibility: "contacts",
      });
    });

    if (card.links.length > 10) {
      card.links.slice(10).forEach((_, index) => {
        errors.links[index + 10] = { url: t("profile.card.linkLimit") };
      });
    }

    return { publicCard, errors };
  }

  function invalidProfileCardLabels(errors: ProfileCardErrors): string {
    const labels: string[] = [];
    if (errors.about) labels.push(t("profile.card.about"));
    if (errors.status) labels.push(t("profile.card.status"));
    if (errors.mood) labels.push(t("profile.card.mood"));
    if (errors.email) labels.push(t("profile.card.email"));
    if (errors.phone) labels.push(t("profile.card.phone"));
    Object.keys(errors.links).forEach((index) => {
      labels.push(t("profile.card.linkNumber", { number: Number(index) + 1 }));
    });
    return labels.join(", ");
  }

  async function saveProfileCard() {
    setCardBusy(true);
    setCardError("");
    setCardMessage("");
    const { publicCard, errors } = validateProfileCardDraft();
    const hasErrors = hasCardErrors(errors);
    setCardErrors(errors);
    try {
      const updated = await api.setMyProfileExtensions(publicCard);
      if (hasErrors) {
        keepCardDraftOnProfileRefresh.current = true;
      } else {
        setCard(withProfileDefaults(updated.profile_extensions));
      }
      await onProfileChanged?.();
      setCardMessage(
        hasErrors
          ? t("profile.card.partialSaved", { fields: invalidProfileCardLabels(errors) })
          : t("profile.card.saved"),
      );
    } catch (err) {
      const code =
        err && typeof err === "object" && "code" in err
          ? String((err as { code: unknown }).code)
          : "";
      setCardError(code === "invalid_profile_extensions" ? t("profile.card.invalid") : t("profile.card.failed"));
    } finally {
      setCardBusy(false);
    }
  }

  return (
    <div className="profile-page">
      <header className="settings-header">
        <div className="settings-header-row">
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
          <div className="settings-header-text">
            <h1>{t("profile.title")}</h1>
            <small className="hint">{t("profile.subtitle")}</small>
          </div>
        </div>
      </header>

      <div className="settings-content">
        <section className="settings-section profile-overview-section">
          <div className="profile-name-row">
            {nameEditing ? (
              <div className="profile-name-edit">
                <input
                  {...textInputProps}
                  value={nameDraft}
                  maxLength={80}
                  autoFocus
                  disabled={nameBusy}
                  aria-label={t("profile.displayName")}
                  onChange={(event) => setNameDraft(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") void saveDisplayName();
                    if (event.key === "Escape") {
                      setNameDraft(profile.display_name);
                      setNameError("");
                      setNameEditing(false);
                    }
                  }}
                />
                <button
                  type="button"
                  className="primary"
                  disabled={nameBusy}
                  onClick={() => void saveDisplayName()}
                >
                  <Check size={16} aria-hidden="true" />
                  {nameBusy ? t("profile.nameSaving") : t("common.save")}
                </button>
                <button
                  type="button"
                  disabled={nameBusy}
                  onClick={() => {
                    setNameDraft(profile.display_name);
                    setNameError("");
                    setNameEditing(false);
                  }}
                >
                  <X size={16} aria-hidden="true" />
                  {t("common.cancel")}
                </button>
              </div>
            ) : (
              <>
                <strong className="profile-display-name">{profile.display_name}</strong>
                {/* Phones (<=800px) show the icon only; the short label
                    appears on desktop widths. Full action name stays on
                    aria-label/title for accessibility. */}
                <button
                  type="button"
                  onClick={() => setNameEditing(true)}
                  aria-label={t("profile.editName")}
                  title={t("profile.editName")}
                >
                  <Edit3 size={16} aria-hidden="true" />
                  <span className="mobile-hidden-label">{t("profile.editNameShort")}</span>
                </button>
              </>
            )}
          </div>
          {nameError && <div className="error inline">{nameError}</div>}

          <div className="profile-photo-block">
            <p className="profile-photo-heading">{t("profile.photoTitle")}</p>
            <p className="hint">{t("profile.photoHint")}</p>
            <div className="profile-photo-row">
              <button
                type="button"
                className="profile-photo-button"
                disabled={photoBusy || !onProfileChanged}
                onClick={() => fileInputRef.current?.click()}
                aria-label={t("profile.uploadPhoto")}
              >
                <UserAvatar
                  className="profile-photo-preview"
                  displayName={profile.display_name}
                  avatarJpegBase64={profile.avatar_jpeg_base64}
                />
                <ImagePlus size={18} aria-hidden="true" />
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                style={{ display: "none" }}
                onChange={(e) => void onAvatarFileChange(e)}
              />
              <div className="profile-photo-actions">
                <button
                  type="button"
                  className="profile-remove-photo-btn"
                  disabled={photoBusy || !profile.avatar_jpeg_base64 || !onProfileChanged}
                  onClick={() => void clearAvatar()}
                  aria-label={t("profile.removePhoto")}
                  title={t("profile.removePhoto")}
                >
                  <Trash2 size={14} aria-hidden="true" />
                  <span className="mobile-hidden-label">{t("profile.removePhotoShort")}</span>
                </button>
              </div>
            </div>
            {photoBusy && (
              <div className="profile-photo-progress" role="status" aria-live="polite">
                <div className="auth-progress-track" aria-hidden="true">
                  <span />
                </div>
                <p>{t("profile.photoUpdating")}</p>
              </div>
            )}
            {photoError && <div className="error inline">{photoError}</div>}
          </div>

          <label className="profile-field profile-id-field">
            <span>{t("profile.profileId")}</span>
            <input
              readOnly
              value={profile.fingerprint}
              onClick={() => void copyProfileId()}
              onFocus={(event) => event.currentTarget.select()}
              aria-label={t("profile.profileId")}
            />
          </label>
        </section>

        <section className="settings-section profile-invite-section">
          <h2>{t("profile.invite")}</h2>
          <p className="hint">{t("profile.inviteHint")}</p>
          {/* The raw veyra:v3… string is a debug-UI diagnostic; release
              users act through copy / QR only. */}
          {isDebugUi && <textarea readOnly value={profile.invite_string} rows={4} />}
          <div className="button-row profile-invite-actions">
            <button
              type="button"
              className="primary profile-copy-invite-btn"
              onClick={() => void copyInvite()}
            >
              <Copy size={16} aria-hidden="true" />
              {t("profile.copyInvite")}
            </button>
            <button type="button" className="primary" disabled={qrBusy} onClick={() => void showInviteQr()}>
              <QrCode size={16} aria-hidden="true" />
              {qrBusy ? t("profile.generatingQr") : t("profile.showQr")}
            </button>
          </div>
        </section>

        <section className="settings-section profile-card-editor">
          <div className="profile-card-heading">
            <h2>{t("profile.card.title")}</h2>
            <p className="hint">{t("profile.card.hint")}</p>
          </div>

          <div className="profile-card-grid">
            <label className="profile-card-control profile-card-control-wide">
              <span>{t("profile.card.about")}</span>
              <textarea
                {...textInputProps}
                className={cardErrors.about ? "is-invalid" : undefined}
                value={card.about.value}
                maxLength={2000}
                rows={4}
                aria-invalid={!!cardErrors.about}
                onChange={(event) => updateField("about", { value: event.target.value, visibility: "contacts" })}
              />
              {cardErrors.about && <small className="profile-card-validation-error">{cardErrors.about}</small>}
            </label>
            <label className="profile-card-control">
              <span>{t("profile.card.status")}</span>
              <input
                {...textInputProps}
                className={cardErrors.status ? "is-invalid" : undefined}
                value={card.status.value}
                maxLength={140}
                aria-invalid={!!cardErrors.status}
                onChange={(event) => updateField("status", { value: event.target.value, visibility: "contacts" })}
              />
              {cardErrors.status && <small className="profile-card-validation-error">{cardErrors.status}</small>}
            </label>
            <label className="profile-card-control">
              <span>{t("profile.card.mood")}</span>
              <input
                {...textInputProps}
                className={cardErrors.mood ? "is-invalid" : undefined}
                value={card.mood.value}
                maxLength={64}
                aria-invalid={!!cardErrors.mood}
                onChange={(event) => updateField("mood", { value: event.target.value, visibility: "contacts" })}
              />
              {cardErrors.mood && <small className="profile-card-validation-error">{cardErrors.mood}</small>}
            </label>
            <label className="profile-card-control">
              <span>{t("profile.card.email")}</span>
              <input
                {...textInputProps}
                className={cardErrors.email ? "is-invalid" : undefined}
                type="email"
                autoComplete="off"
                value={card.email.value}
                maxLength={254}
                aria-invalid={!!cardErrors.email}
                onChange={(event) => updateField("email", { value: event.target.value, visibility: "contacts" })}
              />
              {cardErrors.email && <small className="profile-card-validation-error">{cardErrors.email}</small>}
            </label>
            <label className="profile-card-control">
              <span>{t("profile.card.phone")}</span>
              <input
                {...textInputProps}
                className={cardErrors.phone ? "is-invalid" : undefined}
                autoComplete="off"
                inputMode="tel"
                value={card.phone.value}
                maxLength={40}
                aria-invalid={!!cardErrors.phone}
                onChange={(event) => updateField("phone", { value: event.target.value, visibility: "contacts" })}
              />
              {cardErrors.phone && <small className="profile-card-validation-error">{cardErrors.phone}</small>}
            </label>
          </div>

          <div className="profile-card-links-heading">
            <h3>{t("profile.card.links")}</h3>
            <button type="button" onClick={addLink} disabled={cardBusy || card.links.length >= 10}>
              <Plus size={16} aria-hidden="true" />
              {t("profile.card.addLink")}
            </button>
          </div>
          <div className="profile-card-links">
            {card.links.map((link, index) => {
              const linkErrors = cardErrors.links[index];
              const linkErrorText = linkErrors ? Object.values(linkErrors).filter(Boolean).join(" ") : "";
              return (
                <div className="profile-card-link-item" key={index}>
                  <div className="profile-card-link-row">
                    <select
                      className={linkErrors?.type ? "is-invalid" : undefined}
                      value={link.type || "website"}
                      onChange={(event) => updateLink(index, { type: event.target.value as ProfileLinkType })}
                      aria-label={t("profile.card.linkType")}
                      aria-invalid={!!linkErrors?.type}
                    >
                      {PROFILE_LINK_TYPES.map((type) => (
                        <option key={type} value={type}>
                          {t(`profile.card.types.${type}`)}
                        </option>
                      ))}
                    </select>
                    <input
                      {...textInputProps}
                      className={linkErrors?.label ? "is-invalid" : undefined}
                      value={link.label ?? ""}
                      maxLength={80}
                      placeholder={t("profile.card.linkLabel")}
                      aria-invalid={!!linkErrors?.label}
                      onChange={(event) => updateLink(index, { label: event.target.value, visibility: "contacts" })}
                    />
                    <input
                      {...textInputProps}
                      className={linkErrors?.url ? "is-invalid" : undefined}
                      value={link.url}
                      maxLength={2048}
                      placeholder={t("profile.card.linkUrl")}
                      aria-invalid={!!linkErrors?.url}
                      onChange={(event) => updateLink(index, { url: event.target.value, visibility: "contacts" })}
                    />
                    <button
                      type="button"
                      className="profile-card-remove-link"
                      onClick={() => removeLink(index)}
                      aria-label={t("profile.card.removeLink")}
                    >
                      <Trash2 size={16} aria-hidden="true" />
                    </button>
                  </div>
                  {linkErrorText && <small className="profile-card-validation-error">{linkErrorText}</small>}
                </div>
              );
            })}
          </div>
          {cardMessage && <p className="success profile-card-message">{cardMessage}</p>}
          {cardError && <div className="error inline profile-card-message">{cardError}</div>}
          <div className="profile-card-save-row">
            <button type="button" className="primary" disabled={cardBusy} onClick={() => void saveProfileCard()}>
              <Save size={16} aria-hidden="true" />
              {cardBusy ? t("profile.card.saving") : t("profile.card.save")}
            </button>
          </div>
        </section>

      {isDebugUi && (
        <details className="settings-disclosure identity-diagnostics">
          <summary>{t("profile.identityDiagnostics")}</summary>
          <section className="settings-section">
            <p className="hint">{t("profile.identityDiagnosticsHint")}</p>
            <div className="profile-field">
              <div className="profile-field-header">
                <label>{t("profile.publicId")}</label>
                <button
                  type="button"
                  className="text-link-btn"
                  onClick={() => copy(profile.public_id, t("profile.copied", { label: t("profile.publicId") }))}
                >
                  <Copy size={14} aria-hidden="true" />
                  {t("common.copy")}
                </button>
              </div>
              <code>{profile.public_id}</code>
            </div>
            <div className="profile-field">
              <div className="profile-field-header">
                <label>{t("profile.publicKey")}</label>
                <button
                  type="button"
                  className="text-link-btn"
                  onClick={() => copy(profile.public_key, t("profile.copied", { label: t("profile.publicKey") }))}
                >
                  <Copy size={14} aria-hidden="true" />
                  {t("common.copy")}
                </button>
              </div>
              <code>{profile.public_key}</code>
            </div>
          </section>
        </details>
      )}

      {otherProfiles.length > 0 && (
        <section className="settings-section profile-others-section">
          <h2>{t("profile.others.title")}</h2>
          {otherProfiles.map((entry) => (
            <div key={entry.id} className="profile-other-row">
              <strong className="profile-other-name">
                {entry.display_name || t("backup.unnamedProfile")}
              </strong>
              <button
                type="button"
                className="danger"
                onClick={() => requestDeleteProfile(entry)}
                aria-label={t("common.delete")}
                title={t("common.delete")}
              >
                <Trash2 size={14} aria-hidden="true" />
                <span className="mobile-hidden-label">{t("common.delete")}</span>
              </button>
            </div>
          ))}
        </section>
      )}

      </div>

      {toast && <div className="toast">{toast}</div>}
      {qrInviteValue && (
        <InviteQrView value={qrInviteValue} onClose={closeInviteQr} />
      )}
      {deleteTarget && (
        <div className="modal-backdrop">
          <section
            className="modal profile-delete-modal"
            role="alertdialog"
            aria-label={t("profile.others.confirmTitle")}
          >
            <h1>{t("profile.others.confirmTitle")}</h1>
            <p className="profile-delete-target">
              {deleteTarget.display_name || t("backup.unnamedProfile")}
            </p>
            <p className="hint">{t("profile.others.confirmText")}</p>
            {deleteBusy ? (
              <p className="pairing-progress-row">
                <Loader2 size={20} className="spin" aria-hidden="true" />
                {deleteBusy === "backup"
                  ? t("profile.others.savingBackup")
                  : t("profile.others.deleting")}
              </p>
            ) : (
              <>
                <label className="profile-delete-keep-backup">
                  <input
                    type="checkbox"
                    checked={deleteKeepBackup}
                    onChange={(event) => setDeleteKeepBackup(event.target.checked)}
                  />
                  <span>{t("profile.others.keepBackup")}</span>
                </label>
                {deleteKeepBackup && (
                  <label className="profile-delete-password">
                    <span>{t("profile.others.masterPassword")}</span>
                    <input
                      type="password"
                      autoComplete="off"
                      value={deletePassword}
                      onChange={(event) => setDeletePassword(event.target.value)}
                    />
                    <small className="hint">{t("profile.others.masterPasswordHint")}</small>
                  </label>
                )}
                {deleteError && <p className="error">{deleteError}</p>}
                <div className="button-row">
                  <button
                    type="button"
                    className="danger"
                    disabled={deleteKeepBackup && !deletePassword}
                    onClick={() => void confirmDeleteProfile()}
                  >
                    {t("common.delete")}
                  </button>
                  <button type="button" onClick={closeDeleteModal}>
                    {t("common.cancel")}
                  </button>
                </div>
              </>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
