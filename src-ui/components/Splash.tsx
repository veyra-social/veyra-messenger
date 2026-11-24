type Props = {
  message?: string;
};

/**
 * Splash shown by React while the app is still booting. Visually matches the
 * inline HTML splash in `index.html` so there's no flicker when React mounts.
 */
export function Splash({ message }: Props) {
  return (
    <div className="boot-splash" role="status" aria-live="polite">
      <div className="boot-splash__logo">
        <span className="boot-splash__mark">V</span>
        <span>veyra.social</span>
      </div>
      <div className="boot-splash__bar" aria-hidden="true"></div>
      <div className="boot-splash__tagline">{message ?? "Private P2P Messenger"}</div>
    </div>
  );
}
