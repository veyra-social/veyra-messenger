import {
  Bell,
  Contact2,
  Info,
  Languages,
  Lock,
  MonitorSmartphone,
  Power,
  ShieldCheck,
  User,
  Wifi,
  X,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../lib/tauriApi";
import type { Contact } from "../lib/types";
import { useIsAndroid, useIsIOS } from "../lib/usePlatform";
import { ContactRequests } from "./ContactRequests";

type Props = {
  onProfile: () => void;
  onContacts: () => void;
  onSecurity: () => void;
  onNotifications: () => void;
  onDevices: () => void;
  onNetwork: () => void;
  onInterface: () => void;
  onAbout: () => void;
  onLock: () => void;
  onClose: () => void;
  contactRequests: Contact[];
  onRequestsChanged: () => Promise<void>;
};

export function HamburgerMenu(props: Props) {
  const { t } = useTranslation();
  // Desktop-only "Закрыть": mobile apps have no notion of quitting, and on
  // Ubuntu's stock GNOME there is no tray icon, so after closing the window
  // with the X the in-app menu is the only reachable full exit.
  const isDesktop = !useIsAndroid() && !useIsIOS();

  function pick(action: () => void) {
    action();
    props.onClose();
  }

  return (
    <aside className="sidebar menu-sidebar">
      <div className="menu-sidebar-header">
        <button
          type="button"
          className="menu-close"
          onClick={props.onClose}
          aria-label={t("common.close")}
        >
          <X size={22} />
        </button>
      </div>
      <ContactRequests requests={props.contactRequests} onChanged={props.onRequestsChanged} />
      <nav className="menu-drawer">
        <button onClick={() => pick(props.onProfile)}>
          <User size={16} /> {t("menu.profile")}
        </button>
        <button onClick={() => pick(props.onContacts)}>
          <Contact2 size={16} /> {t("menu.contacts")}
        </button>
        <button onClick={() => pick(props.onSecurity)}>
          <ShieldCheck size={16} /> {t("menu.security")}
        </button>
        <button onClick={() => pick(props.onNotifications)}>
          <Bell size={16} /> {t("menu.notifications")}
        </button>
        <button onClick={() => pick(props.onDevices)}>
          <MonitorSmartphone size={16} /> {t("menu.devices")}
        </button>
        <button onClick={() => pick(props.onNetwork)}>
          <Wifi size={16} /> {t("menu.network")}
        </button>
        <button onClick={() => pick(props.onInterface)}>
          <Languages size={16} /> {t("menu.interface")}
        </button>
        <button onClick={() => pick(props.onAbout)}>
          <Info size={16} /> {t("menu.about")}
        </button>
        <button onClick={() => pick(props.onLock)}>
          <Lock size={16} /> {t("menu.lock")}
        </button>
        {isDesktop && (
          <button onClick={() => api.quitApp().catch(() => {})}>
            <Power size={16} /> {t("menu.quit")}
          </button>
        )}
      </nav>
    </aside>
  );
}
