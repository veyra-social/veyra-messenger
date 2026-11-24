import { ShieldAlert } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { Contact } from "../lib/types";
import { api } from "../lib/tauriApi";
import { shortId } from "../lib/format";

type Props = {
  requests: Contact[];
  onChanged: () => Promise<void>;
};

export function ContactRequests({ requests, onChanged }: Props) {
  const { t } = useTranslation();
  if (!requests.length) return null;

  async function act(action: "accept" | "reject" | "block", contactId: string) {
    if (action === "accept") await api.acceptContactRequest(contactId);
    if (action === "reject") await api.rejectContactRequest(contactId);
    if (action === "block") await api.blockContact(contactId);
    await onChanged();
  }

  return (
    <section className="contact-requests">
      <h2>
        <ShieldAlert size={15} />
        {t("contactRequests.title")}
      </h2>
      {requests.map((request) => (
        <article className="request-card" key={request.local_id}>
          <strong>{request.display_name}</strong>
          <span>{t("contactRequests.incoming")}</span>
          <small>{shortId(request.fingerprint, 16, 10)}</small>
          <div className="request-actions">
            <button onClick={() => act("accept", request.local_id)}>{t("contactRequests.accept")}</button>
            <button onClick={() => act("reject", request.local_id)}>{t("contactRequests.reject")}</button>
            <button onClick={() => act("block", request.local_id)}>{t("common.block")}</button>
          </div>
        </article>
      ))}
    </section>
  );
}
