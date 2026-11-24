import { useEffect, useState } from "react";

type Props = {
  displayName: string;
  avatarJpegBase64?: string | null;
  className?: string;
};

export function UserAvatar({ displayName, avatarJpegBase64, className }: Props) {
  const initial = (displayName.trim().slice(0, 1) || "?").toUpperCase();
  const src = avatarJpegBase64 ? `data:image/jpeg;base64,${avatarJpegBase64}` : null;
  const [showImg, setShowImg] = useState(!!src);

  useEffect(() => {
    setShowImg(!!src);
  }, [src]);

  return (
    <span className={["user-avatar", className].filter(Boolean).join(" ")}>
      {src && showImg ? (
        <img src={src} alt="" decoding="async" onError={() => setShowImg(false)} />
      ) : (
        <span className="user-avatar-initial">{initial}</span>
      )}
    </span>
  );
}
