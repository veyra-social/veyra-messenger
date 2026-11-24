import { useEffect, useState } from "react";
import { Mail, Phone, UserRound, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { Contact, ProfileExtensions } from "../lib/types";
import { api } from "../lib/tauriApi";
import { UserAvatar } from "./UserAvatar";

const ATTACHMENT_KINDS = ["image", "video", "audio", "file"] as const;

type Props = {
  contact: Contact;
  profileExtensions?: ProfileExtensions | null;
  onClose: () => void;
};

function fieldValue(profileExtensions: ProfileExtensions | null | undefined, key: keyof Omit<ProfileExtensions, "links">) {
  return profileExtensions?.[key]?.value?.trim() ?? "";
}

const externalLinkProps = {
  target: "_blank",
  rel: "noopener noreferrer",
} as const;

export function ContactProfileDialog({ contact, profileExtensions, onClose }: Props) {
  const { t } = useTranslation();
  const [deniedKinds, setDeniedKinds] = useState<string[] | null>(null);
  const [savingKinds, setSavingKinds] = useState(false);

  useEffect(() => {
    api
      .getContactAttachmentDeniedKinds(contact.local_id)
      .then(setDeniedKinds)
      .catch(() => setDeniedKinds([]));
  }, [contact.local_id]);

  async function toggleKind(kind: string, allowed: boolean) {
    if (!deniedKinds || savingKinds) return;
    const next = allowed
      ? deniedKinds.filter((item) => item !== kind)
      : [...deniedKinds.filter((item) => item !== kind), kind];
    setSavingKinds(true);
    const prev = deniedKinds;
    setDeniedKinds(next);
    try {
      await api.setContactAttachmentDeniedKinds(contact.local_id, next);
    } catch {
      setDeniedKinds(prev);
    } finally {
      setSavingKinds(false);
    }
  }

  const about = fieldValue(profileExtensions, "about");
  const status = fieldValue(profileExtensions, "status");
  const mood = fieldValue(profileExtensions, "mood");
  const email = fieldValue(profileExtensions, "email");
  const phone = fieldValue(profileExtensions, "phone");
  const links = profileExtensions?.links?.filter((link) => link.url.trim()) ?? [];
  const hasInfo = !!(about || status || mood || email || phone || links.length);

  return (
    <div
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="contact-profile-title"
      onClick={onClose}
    >
      <section className="modal contact-profile-dialog" onClick={(event) => event.stopPropagation()}>
        <button
          type="button"
          className="modal-close"
          onClick={onClose}
          title={t("common.close")}
          aria-label={t("common.close")}
        >
          <X size={18} />
        </button>
        <header className="contact-profile-header">
          <UserAvatar
            className="contact-profile-avatar"
            displayName={contact.display_name}
            avatarJpegBase64={contact.peer_avatar_jpeg_base64}
          />
          <div className="contact-profile-heading">
            <h2 id="contact-profile-title">{contact.display_name}</h2>
            <small className="contact-profile-id">{contact.fingerprint}</small>
          </div>
        </header>

        <section className="contact-profile-info">
          <h3>{t("contactProfile.information")}</h3>
          {!hasInfo ? (
            <p className="hint">{t("contactProfile.noInformation")}</p>
          ) : (
            <div className="contact-profile-fields">
              {about && <p>{about}</p>}
              {status && <div><span>{t("profile.card.status")}</span><strong>{status}</strong></div>}
              {mood && <div><span>{t("profile.card.mood")}</span><strong>{mood}</strong></div>}
              {email && <div><Mail size={15} /><a href={`mailto:${email}`} {...externalLinkProps}>{email}</a></div>}
              {phone && <div><Phone size={15} /><a href={`tel:${phone}`} {...externalLinkProps}>{phone}</a></div>}
              {links.map((link, index) => (
                <div key={`${link.url}-${index}`}>
                  <UserRound size={15} />
                  <a href={link.url} {...externalLinkProps}>
                    {link.label?.trim() || link.url}
                  </a>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="contact-profile-info">
          <h3>{t("contactProfile.incomingFiles")}</h3>
          <p className="hint">{t("contactProfile.incomingFilesHint")}</p>
          <div className="contact-attachment-kinds">
            {ATTACHMENT_KINDS.map((kind) => {
              const allowed = !deniedKinds?.includes(kind);
              return (
                <label key={kind} className="checkbox-row checkbox-row--plain">
                  <input
                    type="checkbox"
                    checked={allowed}
                    disabled={deniedKinds === null || savingKinds}
                    onChange={(event) => void toggleKind(kind, event.target.checked)}
                  />
                  {t(`contactProfile.fileKind.${kind}`)}
                </label>
              );
            })}
          </div>
        </section>
      </section>
    </div>
  );
}
