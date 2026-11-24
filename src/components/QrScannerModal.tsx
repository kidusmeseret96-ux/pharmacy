import React, { useEffect, useRef, useState } from 'react';
import jsQR from 'jsqr';
import { AlertCircle, Camera, QrCode, RefreshCw, Upload, X } from 'lucide-react';
import { soundEngine } from '../lib/soundEngine.ts';

interface QrScannerModalProps {
  open: boolean;
  onClose: () => void;
  onValidQr: (type: 'clock_in' | 'clock_out', qrToken: string) => Promise<void>;
}

export function parseYoyaAttendanceQr(rawText: string): {
  type: 'clock_in' | 'clock_out';
  qrToken: string;
} | null {
  const trimmed = rawText.trim();
  if (!trimmed) return null;
  try {
    const url = trimmed.startsWith('http://') || trimmed.startsWith('https://')
      ? new URL(trimmed)
      : new URL(trimmed.startsWith('/') ? `https://yoya.local${trimmed}` : `https://yoya.local/?${trimmed}`);
    const att = url.searchParams.get('attendance');
    const qr = url.searchParams.get('qr');
    if ((att === 'clock_in' || att === 'clock_out') && qr && qr.trim().length >= 8) {
      return { type: att, qrToken: qr.trim() };
    }
    return null;
  } catch {
    return null;
  }
}

export function QrScannerModal({ open, onClose, onValidQr }: QrScannerModalProps) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const rafRef = useRef<number | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const processingRef = useRef(false);

  const [cameraActive, setCameraActive] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      stopScanner();
      setError(null);
      setSubmitting(false);
      processingRef.current = false;
      return;
    }
    void startCamera();
    return () => {
      stopScanner();
    };
  }, [open]);

  useEffect(() => {
    if (!open || !cameraActive) return;
    const video = videoRef.current;
    const stream = streamRef.current;
    if (!video || !stream) return;

    if (video.srcObject !== stream) {
      video.srcObject = stream;
    }
    void video
      .play()
      .then(() => {
        scheduleScanFrame();
      })
      .catch(() => {
        setError('Could not start camera preview. You can upload a QR image below.');
      });

    return () => {
      if (rafRef.current !== null) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };
  }, [open, cameraActive]);

  function stopScanner() {
    if (rafRef.current !== null) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    setCameraActive(false);
  }

  async function startCamera() {
    setError(null);
    if (!navigator.mediaDevices?.getUserMedia) {
      setError('Camera is not supported on this browser. Upload the QR code image below.');
      return;
    }
    try {
      let stream: MediaStream;
      try {
        stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } },
          audio: false,
        });
      } catch {
        stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
      }
      streamRef.current = stream;
      setCameraActive(true);
    } catch {
      setError('Camera permission was denied or no camera is connected. You can upload a QR photo instead.');
      setCameraActive(false);
    }
  }

  async function handleDecodedQr(rawData: string) {
    if (processingRef.current) return;
    processingRef.current = true;
    const parsed = parseYoyaAttendanceQr(rawData);
    if (!parsed) {
      soundEngine.playWarning();
      setError('Unrecognized QR code. Please scan an official YOYA Pharmacy Clock-In or Clock-Out QR poster.');
      setTimeout(() => {
        processingRef.current = false;
      }, 1500);
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      await onValidQr(parsed.type, parsed.qrToken);
      stopScanner();
      onClose();
    } catch (err) {
      soundEngine.playWarning();
      setError(err instanceof Error ? err.message : 'Invalid or expired YOYA Pharmacy QR code.');
      setTimeout(() => {
        processingRef.current = false;
      }, 1500);
    } finally {
      setSubmitting(false);
    }
  }

  function scheduleScanFrame() {
    const tick = () => {
      const video = videoRef.current;
      const canvas = canvasRef.current;
      if (!video || !canvas || !streamRef.current) return;

      if (video.readyState >= video.HAVE_ENOUGH_DATA && video.videoWidth > 0 && video.videoHeight > 0 && !processingRef.current) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        if (ctx) {
          ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: 'dontInvert',
          });
          if (code?.data) {
            void handleDecodedQr(code.data);
          }
        }
      }
      rafRef.current = requestAnimationFrame(tick);
    };
    rafRef.current = requestAnimationFrame(tick);
  }

  function handleQrImageUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;

    setError(null);
    const reader = new FileReader();
    reader.onload = () => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        const maxDim = 1200;
        const scale = Math.min(1, maxDim / Math.max(img.width, img.height));
        canvas.width = Math.max(1, Math.round(img.width * scale));
        canvas.height = Math.max(1, Math.round(img.height * scale));
        const ctx = canvas.getContext('2d');
        if (!ctx) return;
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: 'attemptBoth',
        });
        if (!code?.data) {
          soundEngine.playWarning();
          setError('No readable QR code was found in that image.');
          return;
        }
        processingRef.current = false;
        void handleDecodedQr(code.data);
      };
      img.onerror = () => setError('Could not read the selected image.');
      img.src = String(reader.result);
    };
    reader.readAsDataURL(file);
  }

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/65 backdrop-blur-md p-3 sm:p-4 overflow-y-auto">
      <div className="w-full max-w-md rounded-[26px] apple-surface yoya-modal-panel shadow-2xl overflow-hidden">
        <div className="flex items-start justify-between gap-3 px-5 py-4 border-b border-black/[0.06] dark:border-white/[0.08]">
          <div className="flex items-center gap-2.5 min-w-0">
            <QrCode className="w-5 h-5 text-[#0D6E52] dark:text-[#22C58B] shrink-0" />
            <div className="min-w-0">
              <h3 className="font-display text-base font-bold truncate">Scan Attendance QR</h3>
              <p className="text-xs text-[#5B6470] dark:text-[#98A2AE]">
                Point your camera at the pharmacy Clock-In or Clock-Out QR poster.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-full apple-inset hover:opacity-80 shrink-0"
            aria-label="Close QR scanner"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          <div className="relative aspect-square w-full max-h-[340px] rounded-2xl overflow-hidden border border-black/[0.08] dark:border-white/[0.1] bg-[#0A1114] flex items-center justify-center">
            <video
              ref={videoRef}
              playsInline
              muted
              autoPlay
              className={cameraActive ? 'w-full h-full object-cover' : 'hidden'}
            />
            <canvas ref={canvasRef} className="hidden" />
            {cameraActive ? (
              <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
                <div className="w-48 h-48 rounded-2xl border-2 border-[#22C58B] shadow-[0_0_0_9999px_rgba(0,0,0,0.38)]" />
              </div>
            ) : (
              <div className="px-6 text-center space-y-2.5">
                <Camera className="w-10 h-10 mx-auto text-[#92A8A1]" />
                <p className="text-xs text-[#92A8A1]">
                  {submitting ? 'Verifying QR code...' : 'Starting camera scanner...'}
                </p>
              </div>
            )}
          </div>

          {error && (
            <div className="flex items-start gap-2 p-3 rounded-2xl border border-red-300 dark:border-red-900/60 bg-red-50 dark:bg-red-950/40 text-xs text-red-700 dark:text-red-300">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            onChange={handleQrImageUpload}
            className="hidden"
          />

          <div className="flex flex-wrap items-center justify-between gap-2">
            <button
              type="button"
              disabled={submitting}
              onClick={() => fileInputRef.current?.click()}
              className="inline-flex items-center justify-center gap-2 px-4 py-2.5 min-h-[44px] rounded-2xl apple-inset text-xs font-semibold flex-1"
            >
              <Upload className="w-4 h-4" />
              Upload QR Image
            </button>

            <button
              type="button"
              disabled={submitting}
              onClick={() => {
                setError(null);
                processingRef.current = false;
                stopScanner();
                void startCamera();
              }}
              className="inline-flex items-center justify-center gap-2 px-4 py-2.5 min-h-[44px] rounded-2xl apple-inset text-xs font-semibold"
            >
              <RefreshCw className="w-4 h-4" />
              Retry Camera
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
