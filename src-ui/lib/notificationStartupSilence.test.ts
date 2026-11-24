import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  __resetNotificationSoundsForTests,
  playInviteSound,
  playMessageSound,
  startCallRingtone,
} from "./notificationSounds";
import {
  __resetStartupNotificationSilenceForTests,
  isStartupNotificationSilenced,
} from "./startupNotificationGate";
import { armNotificationStartupSilence } from "./notificationStartupSilence";

class FakeAudio {
  static instances: FakeAudio[] = [];

  currentTime = 0;
  loop = false;
  muted = false;
  preload = "";
  volume = 1;
  pause = vi.fn();
  play = vi.fn(() => Promise.resolve());

  constructor(public readonly src: string) {
    FakeAudio.instances.push(this);
  }
}

function playCount(): number {
  return FakeAudio.instances.reduce((count, audio) => count + audio.play.mock.calls.length, 0);
}

describe("notification startup silence helper", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-06-08T10:00:00.000Z"));
    FakeAudio.instances = [];
    vi.stubGlobal("Audio", FakeAudio);
    __resetStartupNotificationSilenceForTests(Date.now());
    __resetNotificationSoundsForTests(Date.now());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("no longer suppresses cues — arming the startup silence does not block playback", () => {
    expect(isStartupNotificationSilenced()).toBe(false);

    armNotificationStartupSilence({ macOSDesktop: true, durationMs: 30_000 });
    playMessageSound(); // first cue → plays (coalescer is the only gate now)
    startCallRingtone("call-1"); // call ringtone is no longer gated → plays

    expect(playCount()).toBe(2);
    // The banner-gate flag still toggles, but app code no longer reads it.
    expect(isStartupNotificationSilenced()).toBe(true);
  });
});
