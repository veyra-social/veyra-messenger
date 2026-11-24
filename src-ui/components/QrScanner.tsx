import { useCallback, useEffect, useRef, useState } from "react";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import jsQR from "jsqr";

type Props = {
  onScan: (text: string) => void;
};

type ScanMode = "camera" | "image";

export function QrScanner({ onScan }: Props) {
  const { t } = useTranslation();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const frameRef = useRef<number | null>(null);
  const lastScanRef = useRef(0);
  const onScanRef = useRef(onScan);
  const [mode, setMode] = useState<ScanMode>("camera");
  const [error, setError] = useState("");
  const [cameraActive, setCameraActive] = useState(false);

  useEffect(() => {
    onScanRef.current = onScan;
  }, [onScan]);

  const stopCamera = useCallback(() => {
    if (frameRef.current !== null) {
      window.cancelAnimationFrame(frameRef.current);
      frameRef.current = null;
    }
    streamRef.current?.getTracks().forEach((track) => track.stop());
    streamRef.current = null;
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    setCameraActive(false);
  }, []);

  useEffect(() => stopCamera, [stopCamera]);

  const scanCameraFrame = useCallback(
    (time: number) => {
      const video = videoRef.current;
      if (video && video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA && time - lastScanRef.current >= 200) {
        lastScanRef.current = time;
        const width = video.videoWidth;
        const height = video.videoHeight;
        if (width > 0 && height > 0) {
          const canvas = document.createElement("canvas");
          canvas.width = width;
          canvas.height = height;
          const ctx = canvas.getContext("2d");
          if (ctx) {
            ctx.drawImage(video, 0, 0, width, height);
            const data = ctx.getImageData(0, 0, width, height);
            const code = jsQR(data.data, data.width, data.height);
            if (code) {
              stopCamera();
              setError("");
              onScanRef.current(code.data);
              return;
            }
          }
        }
      }
      frameRef.current = window.requestAnimationFrame(scanCameraFrame);
    },
    [stopCamera],
  );

  async function startCamera() {
    setMode("camera");
    setError("");
    if (!navigator.mediaDevices?.getUserMedia) {
      setError(t("qr.cameraUnavailable"));
      return;
    }
    try {
      stopCamera();
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: { ideal: "environment" },
          width: { ideal: 1280 },
          height: { ideal: 720 },
        },
        audio: false,
      });
      streamRef.current = stream;
      if (!videoRef.current) {
        throw new Error(t("qr.cameraNotReady"));
      }
      videoRef.current.srcObject = stream;
      await videoRef.current.play();
      setCameraActive(true);
      lastScanRef.current = 0;
      frameRef.current = window.requestAnimationFrame(scanCameraFrame);
    } catch (err) {
      stopCamera();
      setError(cameraErrorMessage(err, t));
    }
  }

  async function handleFile(file: File) {
    setError("");
    try {
      const url = URL.createObjectURL(file);
      const img = await loadImage(url, t);
      URL.revokeObjectURL(url);
      const canvas = document.createElement("canvas");
      canvas.width = img.naturalWidth;
      canvas.height = img.naturalHeight;
      const ctx = canvas.getContext("2d");
      if (!ctx) throw new Error(t("qr.imageReadFailed"));
      ctx.drawImage(img, 0, 0);
      const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(data.data, data.width, data.height);
      if (!code) {
        setError(t("qr.noQrInImage"));
        return;
      }
      onScan(code.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("qr.imageReadFailed"));
    }
  }

  return (
    <div className="qr-scanner">
      <div className="qr-mode-toggle" role="tablist" aria-label={t("qr.modeSwitcherLabel")}>
        <button
          type="button"
          className={mode === "camera" ? "active" : ""}
          role="tab"
          aria-selected={mode === "camera"}
          onClick={() => {
            setMode("camera");
            setError("");
          }}
        >
          {t("qr.tabCamera")}
        </button>
        <button
          type="button"
          className={mode === "image" ? "active" : ""}
          role="tab"
          aria-selected={mode === "image"}
          onClick={() => {
            stopCamera();
            setMode("image");
            setError("");
          }}
        >
          {t("qr.tabImage")}
        </button>
      </div>
      <input
        ref={inputRef}
        type="file"
        accept="image/*"
        style={{ display: "none" }}
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) handleFile(file);
          event.target.value = "";
        }}
      />
      {mode === "camera" && (
        <div className="qr-camera-panel">
          <video
            ref={videoRef}
            className={`qr-camera-preview ${cameraActive ? "" : "is-hidden"}`}
            muted
            playsInline
          />
          {!cameraActive && <p className="hint">{t("qr.cameraIdleHint")}</p>}
          <div className="button-row">
            <button type="button" onClick={startCamera} disabled={cameraActive}>
              {cameraActive ? t("qr.scanning") : t("qr.startCamera")}
            </button>
            {cameraActive && (
              <button type="button" onClick={stopCamera}>
                {t("qr.stopCamera")}
              </button>
            )}
          </div>
        </div>
      )}
      {mode === "image" && (
        <button type="button" onClick={() => inputRef.current?.click()}>
          {t("qr.scanFromImage")}
        </button>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

function loadImage(src: string, t: TFunction): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error(t("qr.imageReadFailed")));
    img.src = src;
  });
}

function cameraErrorMessage(err: unknown, t: TFunction): string {
  if (err instanceof DOMException) {
    if (err.name === "NotAllowedError" || err.name === "SecurityError") {
      return t("qr.cameraPermission");
    }
    if (err.name === "NotFoundError" || err.name === "OverconstrainedError") {
      return t("qr.cameraUnsupported");
    }
  }
  return err instanceof Error ? err.message : t("qr.cameraError");
}
