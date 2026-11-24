import {
  armStartupCueSilence,
  armStartupRingtoneSilence,
} from "./notificationSounds";
import {
  armStartupNotificationSilence,
  STARTUP_NOTIFICATION_QUIET_MS,
} from "./startupNotificationGate";

type StartupSilenceOptions = {
  macOSDesktop: boolean;
  durationMs?: number;
};

export function armNotificationStartupSilence({
  macOSDesktop,
  durationMs = STARTUP_NOTIFICATION_QUIET_MS,
}: StartupSilenceOptions) {
  armStartupCueSilence(durationMs);
  if (!macOSDesktop) return;
  armStartupNotificationSilence(durationMs);
  armStartupRingtoneSilence(durationMs);
}
