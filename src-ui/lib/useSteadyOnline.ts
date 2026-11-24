import { useEffect, useRef, useState } from "react";

/**
 * Debounces the "every node connection just dropped" moment. Short-lived
 * dial connections to bootstrap nodes open and close within seconds (20 s
 * dial leases), and every close briefly zeroes `connected_peers` while
 * delivery keeps flowing over direct/WebRTC transports. Surfacing each dip
 * as "Connecting…" made the header and tray flap all day, so a drop only
 * becomes visible after it survives the grace window; recovery flips back
 * to online instantly.
 *
 * Returning to the foreground gets the same optimistic grace: deep idle
 * (§9/§10) deliberately closes every node connection between maintenance
 * rounds, so the app is ALWAYS "offline" at the moment it is reopened and
 * the banner flashed on every foreground entry (field report 2026-07-16).
 * The backend now reconnects immediately on resume; the visibility flip
 * re-arms the grace window so the banner only appears if that reconnect
 * genuinely fails to land within it.
 */
export function useSteadyOnline(rawOnline: boolean, graceMs = 10_000): boolean {
  // Start optimistic: a cold start / unlock is always "connecting" for its
  // first seconds, and flashing the banner there tells the user nothing.
  // If the first connection genuinely fails to land, the initial grace
  // window below surfaces it honestly.
  const [steady, setSteady] = useState(true);
  const timerRef = useRef<number | null>(null);
  const rawRef = useRef(rawOnline);
  rawRef.current = rawOnline;

  useEffect(() => {
    if (rawOnline) {
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      setSteady(true);
      return;
    }
    if (!steady || timerRef.current !== null) return;
    timerRef.current = window.setTimeout(() => {
      timerRef.current = null;
      setSteady(false);
    }, graceMs);
  }, [rawOnline, steady, graceMs]);

  useEffect(() => {
    const onVisibilityChange = () => {
      if (document.visibilityState !== "visible" || rawRef.current) return;
      // Optimistic foreground entry: show online and give the backend's
      // immediate resume-reconnect one grace window to land before any
      // "Connecting…" is surfaced.
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
      }
      setSteady(true);
      timerRef.current = window.setTimeout(() => {
        timerRef.current = null;
        if (!rawRef.current) {
          setSteady(false);
        }
      }, graceMs);
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => document.removeEventListener("visibilitychange", onVisibilityChange);
  }, [graceMs]);

  useEffect(
    () => () => {
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
      }
    },
    [],
  );

  return steady;
}
