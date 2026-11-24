import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  __resetNotificationSoundsForTests,
  playInviteSound,
  playMessageSound,
  previewCallRingtone,
  previewInviteSound,
  previewMessageSound,
  startCallRingtone,
} from "./notificationSounds";

class FakeAudio {
  static instances: FakeAudio[] = [];

  currentTime = 0;
  loop = false;
  muted = false;
  defaultMuted = false;
  preload = "";
  volume = 1;
  src = "";
  pause = vi.fn();
  load = vi.fn();
  play = vi.fn(() => Promise.resolve());

  constructor(src: string) {
    this.src = src;
    FakeAudio.instances.push(this);
  }
}

function playCount(): number {
  return FakeAudio.instances.reduce((count, audio) => count + audio.play.mock.calls.length, 0);
}

describe("notification cue coalescing", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-06-07T10:00:00.000Z"));
    FakeAudio.instances = [];
    vi.stubGlobal("Audio", FakeAudio);
    __resetNotificationSoundsForTests(Date.now());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("plays the first incoming message/invite cue", () => {
    playMessageSound();

    expect(playCount()).toBe(1);
  });

  it("coalesces a rapid message/invite burst into a single cue", () => {
    playMessageSound();
    playInviteSound();
    playMessageSound();

    expect(playCount()).toBe(1);
  });

  it("plays again once the coalesce window has passed", () => {
    playMessageSound();
    vi.setSystemTime(new Date("2026-06-07T10:00:03.000Z"));
    playMessageSound();

    expect(playCount()).toBe(2);
  });

  it("plays the call ringtone immediately (no startup/silence gate)", () => {
    startCallRingtone("call-1");

    expect(playCount()).toBe(1);
  });

  it("keeps settings previews audible and bypassing the coalescer", () => {
    previewMessageSound();
    previewInviteSound();
    previewCallRingtone();

    expect(playCount()).toBe(3);
  });
});
