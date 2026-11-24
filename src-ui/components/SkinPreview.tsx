import type { UiSkin } from "../lib/uiPrefs";

type Props = {
  skin: UiSkin;
};

/**
 * Tiny mock chat for the skin picker in Interface settings. Reuses the same
 * `[data-skin]` cascade as the real chat (`.messages` + `.message-bubble`),
 * so changes to skin tokens automatically reflect here without duplication.
 */
export function SkinPreview({ skin }: Props) {
  return (
    <div className="skin-preview" data-skin={skin}>
      <div className="messages skin-preview-messages">
        <article className="message-row inbound">
          <div className="message-stack">
            <div className="message-bubble">
              <p>Hi!</p>
            </div>
          </div>
        </article>
        <article className="message-row outbound">
          <div className="message-stack">
            <div className="message-bubble">
              <p>Hey 👋</p>
            </div>
          </div>
        </article>
      </div>
    </div>
  );
}
