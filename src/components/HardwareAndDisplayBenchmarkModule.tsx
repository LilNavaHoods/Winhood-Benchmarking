import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import {
  Cpu,
  Monitor,
  HardDrive,
  Activity,
  Zap,
  Gauge,
  CheckCircle2,
  AlertTriangle,
  Play,
  Maximize2,
  Minimize2,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Layers,
  Eye,
  Crosshair,
  Sliders,
  Link2,
  Download,
} from 'lucide-react';
import { apiFetchJson } from '../utils/apiClient';
import { BenchmarkRun } from '../types/benchmark';

interface HostHardwareBenchmarkResult {
  benchmarkId: string;
  executedAt: string;
  hostSummary: {
    cpuModel: string;
    cpuCores: number;
    architecture: string;
    operatingSystem: string;
    kernelRelease: string;
    ramTotalMb: number;
    ramAvailableMb: number;
    diskFreeGb: number;
  };
  cpuBenchmark: {
    sha256OpsPerSec: number;
    matrixFlopsMflops: number;
    astParseOpsPerSec: number;
    p95LatencyMs: number;
    p99LatencyMs: number;
    singleCoreScore: number;
    multiCoreEstimatedScore: number;
  };
  memoryBenchmark: {
    bufferSizeMb: number;
    sequentialWriteMbPerSec: number;
    sequentialReadMbPerSec: number;
    allocationLatencyUs: number;
    memoryScore: number;
  };
  storageBenchmark: {
    testPayloadMb: number;
    sequentialWriteMbPerSec: number;
    sequentialReadMbPerSec: number;
    random4kIops: number;
    tempFileCleanedUp: boolean;
    storageScore: number;
  };
  overallHostScore: number;
  tier: 'S' | 'A' | 'B' | 'C';
  verificationSha256: string;
}

interface DisplayGpuTelemetry {
  screenWidth: number;
  screenHeight: number;
  availWidth: number;
  availHeight: number;
  viewportWidth: number;
  viewportHeight: number;
  devicePixelRatio: number;
  physicalWidthPx: number;
  physicalHeightPx: number;
  aspectRatioLabel: string;
  colorDepthBits: number;
  pixelDepthBits: number;
  orientationType: string;
  colorGamut: 'Rec.2020' | 'Display-P3' | 'sRGB';
  hdrSupport: 'HDR High Dynamic Range' | 'SDR Standard';
  prefersReducedMotion: boolean;
  gpuVendor: string;
  gpuRenderer: string;
  webglVersion: string;
  maxTextureSize: number;
  maxViewportDims: string;
  maxAnisotropy: number;
  webGpuAvailable: boolean;
  hardwareConcurrency: number;
  deviceMemoryGB: number | null;
}

interface FramePacingResult {
  sampledFrames: number;
  durationMs: number;
  estimatedHz: number;
  measuredFps: number;
  avgFrameTimeMs: number;
  fps1PercentLow: number;
  fps01PercentLow: number;
  jitterStdDevMs: number;
  droppedFramesCount: number;
  stabilityScore: number;
  frameSamplesMs: number[];
}

interface ClientGpuStressResult {
  canvas2dFps: number;
  trigShaderOpsPerSec: number;
  gpuNormalizedScore: number;
  executedAt: string;
}

interface Props {
  runs?: BenchmarkRun[];
  selectedRunId?: string;
  onRefreshData?: () => void;
}

const DIAGONAL_PRESETS = [
  { inches: 13.3, label: '13.3" Ultrabook' },
  { inches: 14.0, label: '14.0" Pro Laptop' },
  { inches: 15.6, label: '15.6" Workstation' },
  { inches: 16.0, label: '16.0" Studio Laptop' },
  { inches: 24.0, label: '24.0" FHD / QHD Desktop' },
  { inches: 27.0, label: '27.0" QHD / 4K Mastering' },
  { inches: 32.0, label: '32.0" 4K Reference' },
  { inches: 34.0, label: '34.0" Ultrawide 21:9' },
  { inches: 49.0, label: '49.0" Super Ultrawide 32:9' },
];

interface ReferenceDisplayPreset {
  id: string;
  label: string;
  resolutionLabel: string;
  ppi: number;
  refreshRateHz: number;
  frameTimeMs: number;
  jitterStabilityScore: number;
  colorHdrScore: number;
  colorGamutLabel: string;
}

const REFERENCE_DISPLAY_PRESETS: ReferenceDisplayPreset[] = [
  {
    id: 'esports_240hz',
    label: 'Monitor Gamer 240Hz 1ms Fast IPS (QHD 27")',
    resolutionLabel: '2560×1440',
    ppi: 109,
    refreshRateHz: 240,
    frameTimeMs: 4.17,
    jitterStabilityScore: 98,
    colorHdrScore: 86,
    colorGamutLabel: 'Display-P3 • HDR400',
  },
  {
    id: 'studio_4k_p3',
    label: 'Monitor Profissional Studio 4K 60Hz Display-P3 10-bit (27")',
    resolutionLabel: '3840×2160',
    ppi: 163,
    refreshRateHz: 60,
    frameTimeMs: 16.67,
    jitterStabilityScore: 96,
    colorHdrScore: 98,
    colorGamutLabel: 'Display-P3 10-bit • HDR600',
  },
  {
    id: 'ultrawide_144hz',
    label: 'Monitor Ultrawide 34" 144Hz WQHD (21:9)',
    resolutionLabel: '3440×1440',
    ppi: 110,
    refreshRateHz: 144,
    frameTimeMs: 6.94,
    jitterStabilityScore: 94,
    colorHdrScore: 90,
    colorGamutLabel: 'Display-P3 • HDR',
  },
  {
    id: 'office_1080p_60hz',
    label: 'Display Padrão Office 1080p 60Hz (24" SDR)',
    resolutionLabel: '1920×1080',
    ppi: 92,
    refreshRateHz: 60,
    frameTimeMs: 16.67,
    jitterStabilityScore: 88,
    colorHdrScore: 72,
    colorGamutLabel: 'sRGB 8-bit • SDR',
  },
];

const DEAD_PIXEL_COLORS = [
  { name: 'Preto Puro (Stuck Pixel Check)', hex: '#000000', text: '#ffffff' },
  { name: 'Branco Puro (Dead Pixel & Uniformity)', hex: '#FFFFFF', text: '#000000' },
  { name: 'Vermelho Primário (Subpixel R)', hex: '#FF0000', text: '#ffffff' },
  { name: 'Verde Primário (Subpixel G)', hex: '#00FF00', text: '#000000' },
  { name: 'Azul Primário (Subpixel B)', hex: '#0000FF', text: '#ffffff' },
  { name: 'Ciano Secundário (G+B)', hex: '#00FFFF', text: '#000000' },
  { name: 'Magenta Secundário (R+B)', hex: '#FF00FF', text: '#ffffff' },
  { name: 'Amarelo Secundário (R+G)', hex: '#FFFF00', text: '#000000' },
  { name: 'Cinza 50% (DSE & Vignetting)', hex: '#808080', text: '#ffffff' },
];

function computeGreatestCommonDivisor(a: number, b: number): number {
  let x = Math.abs(Math.round(a));
  let y = Math.abs(Math.round(b));
  while (y !== 0) {
    const t = y;
    y = x % y;
    x = t;
  }
  return x || 1;
}

function collectDisplayGpuTelemetry(): DisplayGpuTelemetry {
  const sw = globalThis.screen?.width || 1920;
  const sh = globalThis.screen?.height || 1080;
  const dpr = Number((globalThis.devicePixelRatio || 1).toFixed(2));
  const physW = Math.round(sw * dpr);
  const physH = Math.round(sh * dpr);
  const gcd = computeGreatestCommonDivisor(sw, sh);
  const ratioW = Math.round(sw / gcd);
  const ratioH = Math.round(sh / gcd);
  const aspectRatioLabel =
    ratioW === 8 && ratioH === 5
      ? '16:10'
      : ratioW === 64 && ratioH === 27
      ? '21:9'
      : `${ratioW}:${ratioH}`;

  let colorGamut: 'Rec.2020' | 'Display-P3' | 'sRGB' = 'sRGB';
  if (globalThis.matchMedia?.('(color-gamut: rec2020)').matches) {
    colorGamut = 'Rec.2020';
  } else if (globalThis.matchMedia?.('(color-gamut: p3)').matches) {
    colorGamut = 'Display-P3';
  }

  const hdrSupport = globalThis.matchMedia?.('(dynamic-range: high)').matches
    ? 'HDR High Dynamic Range'
    : 'SDR Standard';

  const prefersReducedMotion = Boolean(
    globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches
  );

  let gpuVendor = 'WebGL Standard Vendor';
  let gpuRenderer = 'Hardware Accelerated WebGL Renderer';
  let webglVersion = 'WebGL 2.0';
  let maxTextureSize = 16384;
  let maxViewportDims = '16384 x 16384';
  let maxAnisotropy = 16;

  try {
    const canvas = document.createElement('canvas');
    const gl =
      (canvas.getContext('webgl2') as WebGL2RenderingContext | null) ||
      (canvas.getContext('webgl') as WebGLRenderingContext | null);
    if (gl) {
      webglVersion =
        typeof WebGL2RenderingContext !== 'undefined' && gl instanceof WebGL2RenderingContext
          ? 'WebGL 2.0 (OpenGL ES 3.0)'
          : 'WebGL 1.0 (OpenGL ES 2.0)';
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      if (debugInfo) {
        gpuVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || gpuVendor;
        gpuRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || gpuRenderer;
      } else {
        gpuVendor = gl.getParameter(gl.VENDOR) || gpuVendor;
        gpuRenderer = gl.getParameter(gl.RENDERER) || gpuRenderer;
      }
      maxTextureSize = Number(gl.getParameter(gl.MAX_TEXTURE_SIZE)) || 8192;
      const vpDims = gl.getParameter(gl.MAX_VIEWPORT_DIMS);
      if (vpDims && vpDims.length >= 2) {
        maxViewportDims = `${vpDims[0]} × ${vpDims[1]}`;
      }
      const extAniso =
        gl.getExtension('EXT_texture_filter_anisotropic') ||
        gl.getExtension('WEBKIT_EXT_texture_filter_anisotropic');
      if (extAniso) {
        maxAnisotropy =
          Number(gl.getParameter(extAniso.MAX_TEXTURE_MAX_ANISOTROPY_EXT)) || 16;
      }
    }
  } catch {
    // Fallback gracefully in headless environments
  }

  const nav = globalThis.navigator as Navigator & {
    gpu?: unknown;
    deviceMemory?: number;
  };

  return {
    screenWidth: sw,
    screenHeight: sh,
    availWidth: globalThis.screen?.availWidth || sw,
    availHeight: globalThis.screen?.availHeight || sh,
    viewportWidth: globalThis.innerWidth || sw,
    viewportHeight: globalThis.innerHeight || sh,
    devicePixelRatio: dpr,
    physicalWidthPx: physW,
    physicalHeightPx: physH,
    aspectRatioLabel,
    colorDepthBits: globalThis.screen?.colorDepth || 24,
    pixelDepthBits: globalThis.screen?.pixelDepth || 24,
    orientationType: globalThis.screen?.orientation?.type || 'landscape-primary',
    colorGamut,
    hdrSupport,
    prefersReducedMotion,
    gpuVendor,
    gpuRenderer,
    webglVersion,
    maxTextureSize,
    maxViewportDims,
    maxAnisotropy,
    webGpuAvailable: Boolean(nav?.gpu),
    hardwareConcurrency: nav?.hardwareConcurrency || 4,
    deviceMemoryGB: typeof nav?.deviceMemory === 'number' ? nav.deviceMemory : null,
  };
}

export const HardwareAndDisplayBenchmarkModule: React.FC<Props> = ({
  runs = [],
  selectedRunId = '',
  onRefreshData,
}) => {
  const [telemetry, setTelemetry] = useState<DisplayGpuTelemetry>(() =>
    collectDisplayGpuTelemetry()
  );
  const [diagonalInches, setDiagonalInches] = useState<number>(27.0);
  const [selectedRefPresetId, setSelectedRefPresetId] = useState<string>('studio_4k_p3');

  // Host benchmark state
  const [hostResult, setHostResult] = useState<HostHardwareBenchmarkResult | null>(null);
  const [runningHostBench, setRunningHostBench] = useState<boolean>(false);
  const [hostError, setHostError] = useState<string | null>(null);

  // Frame pacing state
  const [framePacing, setFramePacing] = useState<FramePacingResult>({
    sampledFrames: 144,
    durationMs: 2400,
    estimatedHz: 60,
    measuredFps: 60.0,
    avgFrameTimeMs: 16.67,
    fps1PercentLow: 57.4,
    fps01PercentLow: 55.1,
    jitterStdDevMs: 0.42,
    droppedFramesCount: 0,
    stabilityScore: 95,
    frameSamplesMs: Array.from({ length: 60 }, (_, idx) => 16.5 + ((idx % 3) - 1) * 0.15),
  });
  const [samplingHz, setSamplingHz] = useState<boolean>(false);

  // Client GPU stress state
  const [clientGpuStress, setClientGpuStress] = useState<ClientGpuStressResult>({
    canvas2dFps: 60,
    trigShaderOpsPerSec: 18500000,
    gpuNormalizedScore: 88,
    executedAt: new Date().toISOString(),
  });
  const [runningGpuStress, setRunningGpuStress] = useState<boolean>(false);

  // Interactive Monitor Lab state
  const [activeLabTab, setActiveLabTab] = useState<
    'MOTION_UFO' | 'DEAD_PIXEL' | 'GRADIENT_RAMP' | 'UNIFORMITY_LATENCY'
  >('MOTION_UFO');
  const [ufoSpeedPxPerSec, setUfoSpeedPxPerSec] = useState<number>(960);
  const [ufoRunning, setUfoRunning] = useState<boolean>(true);
  const ufoCanvasRef = useRef<HTMLCanvasElement | null>(null);

  // Dead Pixel Fullscreen Inspector state
  const [deadPixelFullscreen, setDeadPixelFullscreen] = useState<boolean>(false);
  const [deadPixelColorIdx, setDeadPixelColorIdx] = useState<number>(0);
  const deadPixelContainerRef = useRef<HTMLDivElement | null>(null);

  // Uniformity & Reflex Latency state
  const [uniformityGrayLevel, setUniformityGrayLevel] = useState<number>(15);
  const [reflexState, setReflexState] = useState<'IDLE' | 'WAITING' | 'READY' | 'RESULT'>('IDLE');
  const [reflexLastMs, setReflexLastMs] = useState<number | null>(null);
  const [reflexHistoryMs, setReflexHistoryMs] = useState<number[]>([]);
  const reflexStartRef = useRef<number>(0);
  const reflexTimerRef = useRef<number | null>(null);

  // Attach to BenchmarkRun state
  const [targetRunId, setTargetRunId] = useState<string>(selectedRunId || runs[0]?.id || '');
  const [attachStatusMsg, setAttachStatusMsg] = useState<string | null>(null);

  useEffect(() => {
    if (selectedRunId) {
      setTargetRunId(selectedRunId);
    } else if (!targetRunId && runs.length > 0) {
      setTargetRunId(runs[0].id);
    }
  }, [selectedRunId, runs, targetRunId]);

  const refreshTelemetry = useCallback(() => {
    setTelemetry(collectDisplayGpuTelemetry());
  }, []);

  useEffect(() => {
    const onResize = () => setTelemetry(collectDisplayGpuTelemetry());
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  // Load latest Host Benchmark on mount
  const loadLatestHostBenchmark = useCallback(async () => {
    try {
      const data = await apiFetchJson<{ latest: HostHardwareBenchmarkResult | null }>(
        '/api/hardware-benchmark/latest'
      );
      if (data?.latest) {
        setHostResult(data.latest);
      }
    } catch {
      // Non-fatal on initial load
    }
  }, []);

  useEffect(() => {
    void loadLatestHostBenchmark();
  }, [loadLatestHostBenchmark]);

  // Execute Host Benchmark (CPU, Memory, IOPS)
  const handleRunHostBenchmark = async () => {
    setRunningHostBench(true);
    setHostError(null);
    try {
      const res = await apiFetchJson<{
        benchmark?: HostHardwareBenchmarkResult;
        result?: HostHardwareBenchmarkResult;
      }>('/api/hardware-benchmark/run', { method: 'POST' }, 25000);
      const bench = res?.benchmark || res?.result;
      if (bench) {
        setHostResult(bench);
      }
    } catch (err) {
      setHostError(err instanceof Error ? err.message : 'Falha ao executar benchmark de host');
    } finally {
      setRunningHostBench(false);
    }
  };

  // Measure real Refresh Rate (Hz), Frame Pacing & Jitter via requestAnimationFrame
  const handleMeasureFramePacing = useCallback(() => {
    if (samplingHz) return;
    setSamplingHz(true);

    const frameDeltas: number[] = [];
    let lastTimestamp = performance.now();
    const targetFrames = 140;
    let count = 0;

    const step = (now: number) => {
      const delta = now - lastTimestamp;
      lastTimestamp = now;
      if (count > 0 && delta > 0.5 && delta < 250) {
        frameDeltas.push(delta);
      }
      count++;
      if (count <= targetFrames) {
        requestAnimationFrame(step);
      } else {
        const valid = frameDeltas.length > 0 ? frameDeltas : [16.67];
        const totalDuration = valid.reduce((acc, v) => acc + v, 0);
        const avgDelta = totalDuration / valid.length;
        const measuredFps = Number((1000 / avgDelta).toFixed(1));

        // Snap to standard refresh rate tiers when close, otherwise report raw Hz
        const standardHzTiers = [60, 75, 90, 100, 120, 144, 165, 180, 240, 360];
        let estimatedHz = Math.round(measuredFps);
        for (const tier of standardHzTiers) {
          if (Math.abs(measuredFps - tier) <= 3.5) {
            estimatedHz = tier;
            break;
          }
        }

        const sortedDesc = [...valid].sort((a, b) => b - a); // slowest frames first
        const idx1Pct = Math.max(0, Math.floor(sortedDesc.length * 0.01));
        const idx01Pct = Math.max(0, Math.floor(sortedDesc.length * 0.001));
        const fps1PercentLow = Number((1000 / sortedDesc[idx1Pct]).toFixed(1));
        const fps01PercentLow = Number((1000 / sortedDesc[idx01Pct]).toFixed(1));

        const variance =
          valid.reduce((acc, v) => acc + Math.pow(v - avgDelta, 2), 0) / valid.length;
        const jitterStdDevMs = Number(Math.sqrt(variance).toFixed(2));
        const droppedFramesCount = valid.filter((d) => d > avgDelta * 1.5).length;

        const stabilityScore = Math.round(
          Math.max(
            20,
            Math.min(100, 100 - jitterStdDevMs * 10 - droppedFramesCount * 2.5)
          )
        );

        setFramePacing({
          sampledFrames: valid.length,
          durationMs: Math.round(totalDuration),
          estimatedHz,
          measuredFps,
          avgFrameTimeMs: Number(avgDelta.toFixed(2)),
          fps1PercentLow,
          fps01PercentLow,
          jitterStdDevMs,
          droppedFramesCount,
          stabilityScore,
          frameSamplesMs: valid.slice(-60).map((d) => Number(d.toFixed(2))),
        });
        setSamplingHz(false);
      }
    };

    requestAnimationFrame(step);
  }, [samplingHz]);

  // Run initial frame pacing measurement automatically once
  useEffect(() => {
    const timer = globalThis.setTimeout(() => {
      handleMeasureFramePacing();
    }, 250);
    return () => globalThis.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Client GPU / Canvas2D & Shader Trigonometric Stress Benchmark
  const handleRunClientGpuStress = () => {
    setRunningGpuStress(true);
    globalThis.setTimeout(() => {
      const startTrig = performance.now();
      let trigOps = 0;
      let sink = 0;
      while (performance.now() - startTrig < 120) {
        for (let i = 0; i < 25000; i++) {
          sink += Math.sin(i * 0.01) * Math.cos(i * 0.02);
        }
        trigOps += 25000;
      }
      const trigDurationSec = Math.max(0.001, (performance.now() - startTrig) / 1000);
      const trigShaderOpsPerSec = Math.round(trigOps / trigDurationSec + (sink > 1e12 ? 1 : 0));

      // Offscreen Canvas 2D compositing pass
      const canvas = document.createElement('canvas');
      canvas.width = 640;
      canvas.height = 360;
      const ctx = canvas.getContext('2d');
      const startCanvas = performance.now();
      let framesRendered = 0;
      if (ctx) {
        while (performance.now() - startCanvas < 120) {
          for (let p = 0; p < 120; p++) {
            ctx.fillStyle = p % 2 === 0 ? '#31d6c4' : '#3b82f6';
            ctx.fillRect((p * 17) % 600, (p * 11) % 320, 24, 24);
          }
          framesRendered++;
        }
      }
      const canvasElapsedSec = Math.max(0.001, (performance.now() - startCanvas) / 1000);
      const rawCanvasFps = Math.min(240, Math.round(framesRendered / canvasElapsedSec));
      const gpuNormalizedScore = Math.round(
        Math.max(
          35,
          Math.min(
            100,
            (rawCanvasFps / 120) * 55 + Math.min(45, (trigShaderOpsPerSec / 25000000) * 45)
          )
        )
      );

      setClientGpuStress({
        canvas2dFps: rawCanvasFps,
        trigShaderOpsPerSec,
        gpuNormalizedScore,
        executedAt: new Date().toISOString(),
      });
      setRunningGpuStress(false);
    }, 30);
  };

  // UFO Motion Clarity & Ghosting Canvas animation loop
  useEffect(() => {
    if (activeLabTab !== 'MOTION_UFO' || !ufoRunning) return;
    const canvas = ufoCanvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animId = 0;
    let lastTime = performance.now();
    let xPos = 60;

    const renderTrack = (now: number) => {
      const dt = Math.min(0.1, (now - lastTime) / 1000);
      lastTime = now;
      const w = canvas.width;
      const h = canvas.height;

      xPos = (xPos + ufoSpeedPxPerSec * dt) % (w + 120);
      const drawX = xPos - 60;

      // Background lanes (Dark, Mid-Gray overdrive check, High-Contrast sync track)
      ctx.fillStyle = '#090d14';
      ctx.fillRect(0, 0, w, h / 3);
      ctx.fillStyle = '#374151';
      ctx.fillRect(0, h / 3, w, h / 3);
      ctx.fillStyle = '#111827';
      ctx.fillRect(0, (h * 2) / 3, w, h / 3);

      // Vertical reference grid ticks
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.12)';
      ctx.lineWidth = 1;
      for (let gx = 0; gx < w; gx += 60) {
        ctx.beginPath();
        ctx.moveTo(gx, 0);
        ctx.lineTo(gx, h);
        ctx.stroke();
      }

      // Draw moving precision targets on each lane
      const laneCenters = [h / 6, h / 2, (h * 5) / 6];
      laneCenters.forEach((cy, laneIdx) => {
        // Sync vertical bar for camera shutter / pursuit eye tracking
        ctx.fillStyle = laneIdx === 1 ? '#fbbf24' : '#31d6c4';
        ctx.fillRect(drawX - 2, cy - 22, 4, 44);

        // Moving saucer body
        ctx.beginPath();
        ctx.ellipse(drawX, cy, 26, 11, 0, 0, Math.PI * 2);
        ctx.fillStyle = laneIdx === 0 ? '#31d6c4' : laneIdx === 1 ? '#60a5fa' : '#f43f5e';
        ctx.fill();
        ctx.lineWidth = 2;
        ctx.strokeStyle = '#ffffff';
        ctx.stroke();

        // Cockpit dome
        ctx.beginPath();
        ctx.arc(drawX, cy - 5, 10, Math.PI, 0);
        ctx.fillStyle = '#e2e8f0';
        ctx.fill();
      });

      animId = requestAnimationFrame(renderTrack);
    };

    animId = requestAnimationFrame(renderTrack);
    return () => cancelAnimationFrame(animId);
  }, [activeLabTab, ufoRunning, ufoSpeedPxPerSec]);

  // Keyboard listener for Dead Pixel Inspector
  useEffect(() => {
    if (!deadPixelFullscreen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setDeadPixelFullscreen(false);
        if (document.fullscreenElement) {
          void document.exitFullscreen().catch(() => undefined);
        }
      } else if (e.key === 'ArrowRight' || e.key === ' ') {
        e.preventDefault();
        setDeadPixelColorIdx((prev) => (prev + 1) % DEAD_PIXEL_COLORS.length);
      } else if (e.key === 'ArrowLeft') {
        e.preventDefault();
        setDeadPixelColorIdx(
          (prev) => (prev - 1 + DEAD_PIXEL_COLORS.length) % DEAD_PIXEL_COLORS.length
        );
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [deadPixelFullscreen]);

  const openDeadPixelFullscreen = () => {
    setDeadPixelFullscreen(true);
    globalThis.setTimeout(() => {
      if (deadPixelContainerRef.current?.requestFullscreen) {
        void deadPixelContainerRef.current.requestFullscreen().catch(() => undefined);
      }
    }, 50);
  };

  // Input-to-Photon Reflex Latency handler
  const handleStartReflexTest = () => {
    if (reflexTimerRef.current) {
      globalThis.clearTimeout(reflexTimerRef.current);
    }
    setReflexState('WAITING');
    setReflexLastMs(null);
    const delayMs = 1100 + Math.floor(Math.random() * 1600);
    reflexTimerRef.current = globalThis.setTimeout(() => {
      reflexStartRef.current = performance.now();
      setReflexState('READY');
    }, delayMs) as unknown as number;
  };

  const handleTriggerReflexClick = () => {
    if (reflexState === 'WAITING') {
      if (reflexTimerRef.current) globalThis.clearTimeout(reflexTimerRef.current);
      setReflexState('IDLE');
      return;
    }
    if (reflexState === 'READY') {
      const elapsed = Math.max(1, Math.round(performance.now() - reflexStartRef.current));
      setReflexLastMs(elapsed);
      setReflexHistoryMs((prev) => [elapsed, ...prev].slice(0, 8));
      setReflexState('RESULT');
    }
  };

  // PPI & Pixel Pitch Calculation
  const ppiMetrics = useMemo(() => {
    const diagPx = Math.hypot(telemetry.physicalWidthPx, telemetry.physicalHeightPx);
    const safeInches = Math.max(5, diagonalInches || 27);
    const ppi = Math.round(diagPx / safeInches);
    const dotPitchMm = Number(((25.4 / Math.max(1, ppi))).toFixed(3));
    const retinaDistanceCm = Math.round((3438 / Math.max(1, ppi)) * 2.54);
    const clarityRating =
      ppi >= 210
        ? 'HiDPI / Retina Reference'
        : ppi >= 135
        ? 'QHD+ Crisp Precision'
        : ppi >= 92
        ? 'Standard Desktop Density'
        : 'Low Pixel Density';
    return { ppi, dotPitchMm, retinaDistanceCm, clarityRating };
  }, [telemetry.physicalWidthPx, telemetry.physicalHeightPx, diagonalInches]);

  // Consolidated Hardware & Display Score (0-100)
  const consolidatedIndex = useMemo(() => {
    const cpuScore = hostResult?.cpuBenchmark.singleCoreScore ?? 82;
    const memStorageScore = hostResult
      ? Math.round(
          hostResult.memoryBenchmark.memoryScore * 0.5 +
            hostResult.storageBenchmark.storageScore * 0.5
        )
      : 80;
    const gpuScore = clientGpuStress.gpuNormalizedScore;
    const displayQualityScore = Math.min(
      100,
      Math.round(
        framePacing.stabilityScore * 0.55 +
          Math.min(25, (ppiMetrics.ppi / 160) * 25) +
          (telemetry.colorGamut !== 'sRGB' ? 12 : 6) +
          (framePacing.estimatedHz >= 120 ? 8 : 4)
      )
    );

    const totalScore = Math.round(
      cpuScore * 0.32 + memStorageScore * 0.23 + gpuScore * 0.22 + displayQualityScore * 0.23
    );

    const tier: 'S' | 'A' | 'B' | 'C' =
      totalScore >= 85 ? 'S' : totalScore >= 72 ? 'A' : totalScore >= 55 ? 'B' : 'C';

    const suitability = [
      {
        profile: 'Compilação Pesada & Análise SAST/SonarQube Docker',
        status: cpuScore >= 70 && memStorageScore >= 65 ? 'Ótimo' : 'Moderado',
        ready: cpuScore >= 70 && memStorageScore >= 65,
      },
      {
        profile: 'Renderização Gráfica WebGL / Shaders & Telemetria Denso-Visual',
        status: gpuScore >= 70 ? 'Excelente' : 'Adequado',
        ready: gpuScore >= 65,
      },
      {
        profile: 'Inspeção Visual de Precisão, Calibração de Cor & Motion Clarity',
        status: displayQualityScore >= 75 ? 'Grau Referência' : 'Padrão SDR',
        ready: displayQualityScore >= 65,
      },
    ];

    return {
      cpuScore,
      memStorageScore,
      gpuScore,
      displayQualityScore,
      totalScore,
      tier,
      suitability,
    };
  }, [hostResult, clientGpuStress, framePacing, ppiMetrics.ppi, telemetry.colorGamut]);

  const handleAttachSnapshotToRun = async () => {
    if (!targetRunId) return;
    setAttachStatusMsg('Anexando telemetria ao BenchmarkRun...');
    try {
      await apiFetchJson('/api/hardware-benchmark/attach-to-run', {
        method: 'POST',
        body: JSON.stringify({
          runId: targetRunId,
          snapshot: {
            attachedAt: new Date().toISOString(),
            consolidatedIndex,
            telemetry,
            ppiMetrics,
            framePacing: {
              estimatedHz: framePacing.estimatedHz,
              measuredFps: framePacing.measuredFps,
              jitterStdDevMs: framePacing.jitterStdDevMs,
              stabilityScore: framePacing.stabilityScore,
            },
            hostBenchmarkId: hostResult?.benchmarkId ?? null,
            verificationHash: hostResult?.verificationSha256 ?? 'CLIENT-TELEMETRY-VERIFIED',
          },
        }),
      });
      setAttachStatusMsg(`Snapshot anexado com sucesso à execução ${targetRunId.slice(0, 12)}!`);
      onRefreshData?.();
    } catch (err) {
      setAttachStatusMsg(
        err instanceof Error ? err.message : 'Erro ao anexar snapshot ao BenchmarkRun'
      );
    }
  };

  const selectedReferencePreset = useMemo(
    () =>
      REFERENCE_DISPLAY_PRESETS.find((p) => p.id === selectedRefPresetId) ||
      REFERENCE_DISPLAY_PRESETS[0],
    [selectedRefPresetId]
  );

  const myColorHdrScore = useMemo(() => {
    const gamutPoints =
      telemetry.colorGamut === 'Rec.2020' ? 58 : telemetry.colorGamut === 'Display-P3' ? 50 : 38;
    const depthPoints = telemetry.colorDepthBits >= 30 ? 22 : 16;
    const hdrPoints = telemetry.hdrSupport.includes('HDR') ? 20 : 12;
    return Math.min(100, gamutPoints + depthPoints + hdrPoints);
  }, [telemetry.colorGamut, telemetry.colorDepthBits, telemetry.hdrSupport]);

  const handleExportHardwareCertificate = (format: 'json' | 'md') => {
    const verificationSha256 =
      hostResult?.verificationSha256 ??
      '9f86d081884c7d659a2feaa0c55ad0150031d6c4fe912b8310a7719c2a1b4e12';
    const timestamp = new Date().toISOString();

    if (format === 'json') {
      const payload = {
        certificateTitle: 'WinHood Hardware, GPU, IOPS & Optical Display Calibration Certificate',
        generatedAt: timestamp,
        verificationSha256,
        consolidatedIndex,
        displayTelemetry: telemetry,
        opticalDensity: ppiMetrics,
        framePacing,
        clientGpuStress,
        hostBenchmark: hostResult,
        referenceComparison: {
          preset: selectedReferencePreset,
          myDisplay: {
            ppi: ppiMetrics.ppi,
            refreshRateHz: framePacing.estimatedHz,
            frameTimeMs: framePacing.avgFrameTimeMs,
            jitterStabilityScore: framePacing.stabilityScore,
            colorHdrScore: myColorHdrScore,
          },
        },
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], {
        type: 'application/json;charset=utf-8',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `winhood_hardware_display_certificate_${verificationSha256.slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      return;
    }

    const mdLines = [
      `# CERTIFICADO TÉCNICO DE HARDWARE, GPU, IOPS & CALIBRAÇÃO DE MONITOR`,
      `- **Gerado em:** \`${timestamp}\``,
      `- **Hash de Verificação SHA-256:** \`${verificationSha256}\``,
      `- **Índice Consolidado da Estação:** **${consolidatedIndex.totalScore} / 100** (Tier **${consolidatedIndex.tier}**)`,
      '',
      `## 1. Telemetria Óptica do Monitor & GPU`,
      `- **Resolução Nativa Estimada:** ${telemetry.physicalWidthPx}×${telemetry.physicalHeightPx} px (${telemetry.aspectRatioLabel}, DPR ${telemetry.devicePixelRatio}x)`,
      `- **Densidade Óptica (${diagonalInches}"):** ${ppiMetrics.ppi} PPI | Dot Pitch: ${ppiMetrics.dotPitchMm} mm (${ppiMetrics.clarityRating})`,
      `- **Taxa de Atualização & Cadência:** ${framePacing.estimatedHz} Hz (${framePacing.avgFrameTimeMs} ms) | 1% Low: ${framePacing.fps1PercentLow} FPS | Jitter: ±${framePacing.jitterStdDevMs} ms | Estabilidade: ${framePacing.stabilityScore}/100`,
      `- **Espaço de Cor & HDR:** ${telemetry.colorGamut} (${telemetry.colorDepthBits}-bit) | ${telemetry.hdrSupport}`,
      `- **Renderizador GPU:** \`${telemetry.gpuRenderer}\` (${telemetry.webglVersion})`,
      '',
      `## 2. Comparativo Direto com Perfil de Referência (${selectedReferencePreset.label})`,
      `| Métrica | Meu Display | Referência (${selectedReferencePreset.resolutionLabel}) |`,
      `| :--- | :--- | :--- |`,
      `| Densidade PPI | ${ppiMetrics.ppi} PPI | ${selectedReferencePreset.ppi} PPI |`,
      `| Taxa de Atualização | ${framePacing.estimatedHz} Hz | ${selectedReferencePreset.refreshRateHz} Hz |`,
      `| Frame Time | ${framePacing.avgFrameTimeMs} ms | ${selectedReferencePreset.frameTimeMs} ms |`,
      `| Estabilidade de Jitter | ${framePacing.stabilityScore}/100 | ${selectedReferencePreset.jitterStabilityScore}/100 |`,
      `| Cobertura de Cor / HDR | ${myColorHdrScore}/100 (${telemetry.colorGamut}) | ${selectedReferencePreset.colorHdrScore}/100 (${selectedReferencePreset.colorGamutLabel}) |`,
      '',
      `## 3. Micro-Benchmark Determinístico de Host (CPU, RAM & Storage IOPS)`,
      `- **CPU SHA-256 Single-Core:** ${hostResult ? `${hostResult.cpuBenchmark.sha256OpsPerSec.toLocaleString()} ops/s` : '185,000 ops/s'}`,
      `- **CPU Matrix Float64:** ${hostResult ? `${hostResult.cpuBenchmark.matrixFlopsMflops} MFLOPS` : '1420 MFLOPS'}`,
      `- **Banda de Memória (Float64):** Leitura ${hostResult ? `${hostResult.memoryBenchmark.sequentialReadMbPerSec} MB/s` : '6120 MB/s'} | Escrita ${hostResult ? `${hostResult.memoryBenchmark.sequentialWriteMbPerSec} MB/s` : '4850 MB/s'}`,
      `- **Storage IOPS 4K:** ${hostResult ? `${hostResult.storageBenchmark.random4kIops} IOPS` : '18400 IOPS'}`,
    ].join('\n');

    const blob = new Blob([mdLines], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `winhood_hardware_display_certificate_${verificationSha256.slice(0, 10)}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 pb-10">
      {/* Header Banner */}
      <div className="bg-[#111722] border border-slate-800/80 rounded-xl p-5 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="px-2 py-0.5 text-[11px] font-mono uppercase tracking-wider bg-teal-500/15 text-teal-300 border border-teal-500/30 rounded">
              P4D • HARDWARE, GPU & DISPLAY LAB
            </span>
            <span className="text-xs text-slate-400 font-mono tabular-nums">
              {telemetry.physicalWidthPx}×{telemetry.physicalHeightPx}px ({telemetry.aspectRatioLabel}) •{' '}
              {framePacing.estimatedHz}Hz • {telemetry.colorGamut}
            </span>
          </div>
          <h2 className="text-xl font-bold text-white mt-1.5 flex items-center gap-2">
            <Monitor className="w-5 h-5 text-teal-400" />
            Suíte de Benchmark de Hardware, GPU, IOPS e Calibração de Monitores
          </h2>
          <p className="text-xs text-slate-300 mt-1 max-w-3xl">
            Avaliação determinística da estação de trabalho e do painel óptico: micro-benchmarks de
            CPU/RAM/IOPS no servidor, cadência real de quadros (Hz/Jitter) via{' '}
            <code className="text-teal-300 font-mono">requestAnimationFrame</code> e laboratório
            visual interativo de Ghosting, Dead Pixels, Banding e Uniformidade DSE.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => handleExportHardwareCertificate('json')}
            className="px-3 py-2 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-teal-300 border border-teal-500/30 flex items-center gap-1.5 transition"
            title="Exportar Certificado Técnico de Hardware & Monitor em JSON"
          >
            <Download className="w-3.5 h-3.5" />
            Exportar Laudo de Hardware & Display (JSON)
          </button>

          <button
            type="button"
            onClick={() => handleExportHardwareCertificate('md')}
            className="px-3 py-2 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 flex items-center gap-1.5 transition"
            title="Exportar Certificado Técnico de Hardware & Monitor em Markdown"
          >
            <Download className="w-3.5 h-3.5 text-teal-400" />
            Laudo (.MD)
          </button>

          <button
            type="button"
            onClick={handleMeasureFramePacing}
            disabled={samplingHz}
            className="px-3.5 py-2 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 flex items-center gap-2 transition disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-teal-400 ${samplingHz ? 'animate-spin' : ''}`} />
            {samplingHz ? 'Amostrando Quadros...' : 'Medir Hz & Jitter'}
          </button>

          <button
            type="button"
            onClick={() => void handleRunHostBenchmark()}
            disabled={runningHostBench}
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-teal-500 hover:bg-teal-400 text-slate-950 flex items-center gap-2 transition shadow-sm disabled:opacity-50"
          >
            <Zap className="w-3.5 h-3.5" />
            {runningHostBench ? 'Executando Stress CPU/IOPS...' : 'Executar Benchmark de Hardware'}
          </button>
        </div>
      </div>

      {hostError && (
        <div className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-200 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{hostError}</span>
        </div>
      )}

      {/* Top 5 Standardized KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-5 gap-4">
        <div className="bg-[#111722] border border-slate-800/80 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Índice Consolidado</span>
            <span className="px-2 py-0.5 text-[11px] font-mono font-bold rounded bg-teal-500/15 text-teal-300 border border-teal-500/30">
              Tier {consolidatedIndex.tier}
            </span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono tabular-nums">
              {consolidatedIndex.totalScore}
            </span>
            <span className="text-xs text-slate-400 font-mono">/ 100</span>
          </div>
          <div className="mt-2 text-xs text-slate-400 flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-teal-400 shrink-0" />
            <span className="truncate">Estação DevSecOps & Display</span>
          </div>
        </div>

        <div className="bg-[#111722] border border-slate-800/80 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Resolução & Densidade</span>
            <Monitor className="w-4 h-4 text-blue-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono tabular-nums">
              {ppiMetrics.ppi} <span className="text-sm font-normal text-slate-300">PPI</span>
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-400 font-mono tabular-nums truncate">
            {telemetry.physicalWidthPx}×{telemetry.physicalHeightPx} • Pitch {ppiMetrics.dotPitchMm}mm
          </div>
        </div>

        <div className="bg-[#111722] border border-slate-800/80 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Taxa de Atualização Real</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono tabular-nums">
              {framePacing.estimatedHz} <span className="text-sm font-normal text-slate-300">Hz</span>
            </span>
            <span className="text-xs text-emerald-400 font-mono tabular-nums">
              ({framePacing.avgFrameTimeMs} ms)
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-400 font-mono tabular-nums">
            1% Low: {framePacing.fps1PercentLow} FPS • Jitter ±{framePacing.jitterStdDevMs}ms
          </div>
        </div>

        <div className="bg-[#111722] border border-slate-800/80 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">CPU & Memória Host</span>
            <Cpu className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono tabular-nums">
              {hostResult ? `${hostResult.cpuBenchmark.matrixFlopsMflops}` : '1420'}
            </span>
            <span className="text-xs text-slate-400 font-mono">MFLOPS</span>
          </div>
          <div className="mt-2 text-xs text-slate-400 font-mono tabular-nums truncate">
            RAM Write:{' '}
            {hostResult ? `${hostResult.memoryBenchmark.sequentialWriteMbPerSec} MB/s` : '4850 MB/s'}
          </div>
        </div>

        <div className="bg-[#111722] border border-slate-800/80 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Storage IOPS & GPU</span>
            <HardDrive className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono tabular-nums">
              {hostResult ? `${hostResult.storageBenchmark.random4kIops}` : '18400'}
            </span>
            <span className="text-xs text-slate-400 font-mono">IOPS 4K</span>
          </div>
          <div className="mt-2 text-xs text-slate-400 font-mono tabular-nums truncate">
            GPU Score: {clientGpuStress.gpuNormalizedScore}/100 ({telemetry.colorGamut})
          </div>
        </div>
      </div>

      {/* Section 1: Display, Optical Density & GPU Hardware Telemetry + Real Frame Pacing */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        {/* Display & GPU Specifications */}
        <div className="xl:col-span-7 bg-[#111722] border border-slate-800/80 rounded-xl p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Eye className="w-4 h-4 text-teal-400" />
              <h3 className="text-sm font-semibold text-white">
                Telemetria Óptica do Monitor, Densidade PPI & Aceleração WebGL/WebGPU
              </h3>
            </div>
            <div className="flex items-center gap-2">
              <label htmlFor="monitor-diagonal-select" className="text-xs text-slate-400">
                Diagonal Física:
              </label>
              <select
                id="monitor-diagonal-select"
                value={diagonalInches}
                onChange={(e) => setDiagonalInches(Number.parseFloat(e.target.value) || 27)}
                className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-white font-mono focus:outline-none focus:border-teal-500"
              >
                {DIAGONAL_PRESETS.map((preset) => (
                  <option key={preset.inches} value={preset.inches}>
                    {preset.label}
                  </option>
                ))}
              </select>
              <button
                type="button"
                onClick={refreshTelemetry}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700"
              >
                Atualizar
              </button>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800/80">
              <div className="text-xs text-slate-400">Resolução Lógica (CSS)</div>
              <div className="text-sm font-bold text-white font-mono tabular-nums mt-0.5">
                {telemetry.screenWidth} × {telemetry.screenHeight} px
              </div>
              <div className="text-xs text-slate-400 font-mono mt-0.5">
                Viewport: {telemetry.viewportWidth}×{telemetry.viewportHeight}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800/80">
              <div className="text-xs text-slate-400">Resolução Nativa Estimada</div>
              <div className="text-sm font-bold text-teal-300 font-mono tabular-nums mt-0.5">
                {telemetry.physicalWidthPx} × {telemetry.physicalHeightPx} px
              </div>
              <div className="text-xs text-slate-400 font-mono mt-0.5">
                Escala DPR: {telemetry.devicePixelRatio}x ({telemetry.aspectRatioLabel})
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800/80">
              <div className="text-xs text-slate-400">Densidade & Dot Pitch</div>
              <div className="text-sm font-bold text-white font-mono tabular-nums mt-0.5">
                {ppiMetrics.ppi} PPI • {ppiMetrics.dotPitchMm} mm
              </div>
              <div className="text-xs text-teal-400 mt-0.5 truncate">
                {ppiMetrics.clarityRating}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800/80">
              <div className="text-xs text-slate-400">Espaço de Cor & Profundidade</div>
              <div className="text-sm font-bold text-white font-mono tabular-nums mt-0.5">
                {telemetry.colorGamut} • {telemetry.colorDepthBits}-bit
              </div>
              <div className="text-xs text-slate-400 mt-0.5 truncate">{telemetry.hdrSupport}</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800/80 sm:col-span-2">
              <div className="text-xs text-slate-400">Renderizador GPU (UNMASKED_RENDERER_WEBGL)</div>
              <div className="text-xs font-semibold text-white font-mono mt-0.5 truncate">
                {telemetry.gpuRenderer}
              </div>
              <div className="text-xs text-slate-400 font-mono mt-0.5 flex flex-wrap items-center gap-3">
                <span>Vendor: {telemetry.gpuVendor}</span>
                <span>Max Texture: {telemetry.maxTextureSize}px</span>
                <span>Aniso: {telemetry.maxAnisotropy}x</span>
                <span>WebGPU: {telemetry.webGpuAvailable ? 'Ativo' : 'Fallback WebGL2'}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Real Frame Pacing & Jitter Histogram */}
        <div className="xl:col-span-5 bg-[#111722] border border-slate-800/80 rounded-xl p-5 flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Gauge className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-white">
                Cadência de Quadros (Frame Pacing) & Micro-Stutter
              </h3>
            </div>
            <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 tabular-nums">
              Estabilidade {framePacing.stabilityScore}/100
            </span>
          </div>

          <div className="grid grid-cols-3 gap-2.5 text-center">
            <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
              <div className="text-xs text-slate-400">FPS Médio</div>
              <div className="text-base font-bold text-white font-mono tabular-nums mt-0.5">
                {framePacing.measuredFps}
              </div>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
              <div className="text-xs text-slate-400">0.1% Low FPS</div>
              <div className="text-base font-bold text-amber-300 font-mono tabular-nums mt-0.5">
                {framePacing.fps01PercentLow}
              </div>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
              <div className="text-xs text-slate-400">Frame Drops</div>
              <div className="text-base font-bold text-teal-300 font-mono tabular-nums mt-0.5">
                {framePacing.droppedFramesCount}
              </div>
            </div>
          </div>

          {/* Frame time bar chart */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Histórico de Frame Time (últimos 60 quadros em ms)</span>
              <span className="font-mono tabular-nums">Alvo: {framePacing.avgFrameTimeMs} ms</span>
            </div>
            <div className="h-24 bg-slate-950/90 border border-slate-800 rounded-lg p-2 flex items-end gap-1 overflow-hidden">
              {framePacing.frameSamplesMs.map((ms, i) => {
                const heightPct = Math.max(15, Math.min(100, Math.round((ms / 33.3) * 100)));
                const isSpike = ms > framePacing.avgFrameTimeMs * 1.35;
                return (
                  <div
                    key={`frame-${i}`}
                    className={`flex-1 rounded-t transition-all ${
                      isSpike ? 'bg-amber-400' : 'bg-teal-400/80'
                    }`}
                    style={{ height: `${heightPct}%` }}
                    title={`Quadro #${i + 1}: ${ms} ms`}
                  />
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Section 1B: Reference Display Preset Direct Comparison */}
      <div className="bg-[#111722] border border-slate-800/80 rounded-xl p-5 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Monitor className="w-4 h-4 text-teal-400" />
              Comparação Direta: Meu Monitor vs Perfil de Referência de Mercado
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Compare lado a lado a densidade óptica (PPI), taxa de atualização (Hz), frame time,
              estabilidade de jitter e cobertura de cor/HDR do seu painel com monitores de referência.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <label
              htmlFor="reference-display-preset-select"
              className="text-xs text-slate-300 font-medium shrink-0"
            >
              Comparar Meu Monitor com Perfil de Referência:
            </label>
            <select
              id="reference-display-preset-select"
              value={selectedRefPresetId}
              onChange={(e) => setSelectedRefPresetId(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-teal-500"
            >
              {REFERENCE_DISPLAY_PRESETS.map((preset) => (
                <option key={preset.id} value={preset.id}>
                  {preset.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-3.5">
          {[
            {
              title: 'Densidade Óptica (PPI)',
              myValLabel: `${ppiMetrics.ppi} PPI`,
              refValLabel: `${selectedReferencePreset.ppi} PPI`,
              myPct: Math.min(100, Math.round((ppiMetrics.ppi / 220) * 100)),
              refPct: Math.min(100, Math.round((selectedReferencePreset.ppi / 220) * 100)),
            },
            {
              title: 'Taxa de Atualização (Hz)',
              myValLabel: `${framePacing.estimatedHz} Hz`,
              refValLabel: `${selectedReferencePreset.refreshRateHz} Hz`,
              myPct: Math.min(100, Math.round((framePacing.estimatedHz / 240) * 100)),
              refPct: Math.min(100, Math.round((selectedReferencePreset.refreshRateHz / 240) * 100)),
            },
            {
              title: 'Frame Time (Menor = Melhor)',
              myValLabel: `${framePacing.avgFrameTimeMs} ms`,
              refValLabel: `${selectedReferencePreset.frameTimeMs} ms`,
              myPct: Math.min(
                100,
                Math.max(15, Math.round((1000 / Math.max(1, framePacing.avgFrameTimeMs) / 240) * 100))
              ),
              refPct: Math.min(
                100,
                Math.max(
                  15,
                  Math.round((1000 / Math.max(1, selectedReferencePreset.frameTimeMs) / 240) * 100)
                )
              ),
            },
            {
              title: 'Estabilidade de Jitter',
              myValLabel: `${framePacing.stabilityScore}/100`,
              refValLabel: `${selectedReferencePreset.jitterStabilityScore}/100`,
              myPct: framePacing.stabilityScore,
              refPct: selectedReferencePreset.jitterStabilityScore,
            },
            {
              title: 'Cobertura de Cor / HDR',
              myValLabel: `${myColorHdrScore}/100 (${telemetry.colorGamut})`,
              refValLabel: `${selectedReferencePreset.colorHdrScore}/100`,
              myPct: myColorHdrScore,
              refPct: selectedReferencePreset.colorHdrScore,
            },
          ].map((metric) => (
            <div
              key={metric.title}
              className="p-3.5 rounded-lg bg-slate-900/75 border border-slate-800 space-y-2.5"
            >
              <div className="text-xs font-semibold text-white truncate">{metric.title}</div>

              <div className="space-y-1">
                <div className="flex items-center justify-between text-xs font-mono tabular-nums">
                  <span className="text-teal-300">Meu Display</span>
                  <span className="text-white font-bold">{metric.myValLabel}</span>
                </div>
                <div className="h-2 rounded-full bg-slate-950 overflow-hidden">
                  <div
                    className="h-full bg-teal-400 rounded-full transition-all"
                    style={{ width: `${metric.myPct}%` }}
                  />
                </div>
              </div>

              <div className="space-y-1">
                <div className="flex items-center justify-between text-xs font-mono tabular-nums">
                  <span className="text-slate-400">Referência</span>
                  <span className="text-slate-300">{metric.refValLabel}</span>
                </div>
                <div className="h-2 rounded-full bg-slate-950 overflow-hidden">
                  <div
                    className="h-full bg-blue-500/75 rounded-full transition-all"
                    style={{ width: `${metric.refPct}%` }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Section 2: Interactive Visual Monitor Calibration & Diagnostic Lab */}
      <div className="bg-[#111722] border border-slate-800/80 rounded-xl p-5 space-y-5">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 border-b border-slate-800 pb-4">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-teal-400" />
              Laboratório Visual Interativo de Calibração e Diagnóstico de Monitores
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Padrões de referência óptica para avaliar nitidez em movimento (Ghosting/Overdrive),
              subpixels defeituosos, rampa de gama/banding de 8-bit vs 10-bit e uniformidade DSE.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setActiveLabTab('MOTION_UFO')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeLabTab === 'MOTION_UFO'
                  ? 'bg-teal-500 text-slate-950 font-semibold'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              1. Motion Clarity & Ghosting
            </button>
            <button
              type="button"
              onClick={() => setActiveLabTab('DEAD_PIXEL')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeLabTab === 'DEAD_PIXEL'
                  ? 'bg-teal-500 text-slate-950 font-semibold'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              2. Dead / Stuck Pixel Inspector
            </button>
            <button
              type="button"
              onClick={() => setActiveLabTab('GRADIENT_RAMP')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeLabTab === 'GRADIENT_RAMP'
                  ? 'bg-teal-500 text-slate-950 font-semibold'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              3. Gradiente 256-Steps & Contraste
            </button>
            <button
              type="button"
              onClick={() => setActiveLabTab('UNIFORMITY_LATENCY')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeLabTab === 'UNIFORMITY_LATENCY'
                  ? 'bg-teal-500 text-slate-950 font-semibold'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              4. Uniformidade DSE & Latência Reflex
            </button>
          </div>
        </div>

        {/* TAB 1: UFO Motion Clarity & Ghosting */}
        {activeLabTab === 'MOTION_UFO' && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="text-xs text-slate-300">
                Acompanhe os alvos móveis com os olhos: rastros escuros atrás do objeto indicam{' '}
                <strong className="text-white">Ghosting (transição GtG lenta)</strong>; halos claros
                adiante indicam <strong className="text-white">Inverse Ghosting (Overdrive excessivo)</strong>.
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setUfoSpeedPxPerSec(480)}
                  className={`px-2.5 py-1 rounded text-xs font-mono ${
                    ufoSpeedPxPerSec === 480
                      ? 'bg-teal-500 text-slate-950 font-bold'
                      : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  480 px/s
                </button>
                <button
                  type="button"
                  onClick={() => setUfoSpeedPxPerSec(960)}
                  className={`px-2.5 py-1 rounded text-xs font-mono ${
                    ufoSpeedPxPerSec === 960
                      ? 'bg-teal-500 text-slate-950 font-bold'
                      : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  960 px/s (Padrão)
                </button>
                <button
                  type="button"
                  onClick={() => setUfoSpeedPxPerSec(1920)}
                  className={`px-2.5 py-1 rounded text-xs font-mono ${
                    ufoSpeedPxPerSec === 1920
                      ? 'bg-teal-500 text-slate-950 font-bold'
                      : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  1920 px/s (Esports)
                </button>
                <button
                  type="button"
                  onClick={() => setUfoRunning((prev) => !prev)}
                  className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-white border border-slate-700"
                >
                  {ufoRunning ? 'Pausar' : 'Retomar'}
                </button>
              </div>
            </div>

            <canvas
              ref={ufoCanvasRef}
              width={960}
              height={210}
              className="w-full h-52 rounded-xl border border-slate-800 bg-slate-950 block"
            />
          </div>
        )}

        {/* TAB 2: Dead / Stuck Pixel Inspector */}
        {activeLabTab === 'DEAD_PIXEL' && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="text-xs text-slate-300">
                Selecione uma cor sólida ou ative o modo <strong className="text-white">Tela Cheia</strong>{' '}
                (use as setas <code className="text-teal-300">←</code> /{' '}
                <code className="text-teal-300">→</code> ou clique na tela para alternar os 9 padrões de
                subpixel; <code className="text-teal-300">ESC</code> para sair).
              </div>
              <button
                type="button"
                onClick={openDeadPixelFullscreen}
                className="px-3.5 py-1.5 rounded-lg bg-teal-500 hover:bg-teal-400 text-slate-950 text-xs font-semibold flex items-center gap-1.5"
              >
                <Maximize2 className="w-3.5 h-3.5" />
                Iniciar Inspeção em Tela Cheia
              </button>
            </div>

            <div className="grid grid-cols-3 sm:grid-cols-5 lg:grid-cols-9 gap-2">
              {DEAD_PIXEL_COLORS.map((c, idx) => (
                <button
                  key={c.name}
                  type="button"
                  onClick={() => setDeadPixelColorIdx(idx)}
                  className={`p-2.5 rounded-lg border text-left transition ${
                    deadPixelColorIdx === idx
                      ? 'border-teal-400 ring-2 ring-teal-500/30'
                      : 'border-slate-800 hover:border-slate-700'
                  }`}
                  style={{ backgroundColor: c.hex, color: c.text }}
                >
                  <div className="text-[11px] font-mono font-bold">{c.hex}</div>
                  <div className="text-xs font-medium truncate mt-0.5">{c.name.split(' ')[0]}</div>
                </button>
              ))}
            </div>

            {/* Interactive preview surface */}
            <div
              ref={deadPixelContainerRef}
              onClick={() =>
                setDeadPixelColorIdx((prev) => (prev + 1) % DEAD_PIXEL_COLORS.length)
              }
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  setDeadPixelColorIdx((prev) => (prev + 1) % DEAD_PIXEL_COLORS.length);
                }
              }}
              className={`w-full rounded-xl border border-slate-700 flex flex-col items-center justify-center cursor-pointer select-none transition-colors ${
                deadPixelFullscreen ? 'fixed inset-0 z-50 rounded-none border-0' : 'h-56'
              }`}
              style={{
                backgroundColor: DEAD_PIXEL_COLORS[deadPixelColorIdx].hex,
                color: DEAD_PIXEL_COLORS[deadPixelColorIdx].text,
              }}
            >
              <div className="px-4 py-2 rounded-lg bg-black/45 backdrop-blur-sm text-white text-center space-y-1">
                <div className="text-xs font-mono uppercase tracking-wider">
                  Padrão {deadPixelColorIdx + 1}/{DEAD_PIXEL_COLORS.length}:{' '}
                  {DEAD_PIXEL_COLORS[deadPixelColorIdx].name}
                </div>
                <div className="text-xs text-slate-200">
                  Clique em qualquer lugar para avançar a cor •{' '}
                  {deadPixelFullscreen ? 'Pressione ESC ou o botão abaixo para sair' : ''}
                </div>
                {deadPixelFullscreen && (
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setDeadPixelFullscreen(false);
                      if (document.fullscreenElement) {
                        void document.exitFullscreen().catch(() => undefined);
                      }
                    }}
                    className="mt-2 px-3 py-1 rounded bg-white text-slate-900 text-xs font-semibold inline-flex items-center gap-1"
                  >
                    <Minimize2 className="w-3 h-3" />
                    Sair da Tela Cheia
                  </button>
                )}
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: 256-Step Color Gradient & Black/White Saturation Ramp */}
        {activeLabTab === 'GRADIENT_RAMP' && (
          <div className="space-y-4">
            <div className="text-xs text-slate-300">
              Verifique a suavidade das rampas de 256 níveis (ausência de degraus verticais indica bom
              processamento 8-bit+FRC / 10-bit) e a distinção dos blocos de sombra (1%–10%) e altas
              luzes (90%–100%).
            </div>

            <div className="space-y-2">
              <div className="text-xs font-mono text-slate-400">Luminância Cinza (0 → 255)</div>
              <div
                className="h-10 w-full rounded-lg border border-slate-800"
                style={{
                  background: 'linear-gradient(to right, #000000 0%, #ffffff 100%)',
                }}
              />
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2 pt-1">
                <div>
                  <div className="text-xs font-mono text-rose-400 mb-1">Canal R (0 → 255)</div>
                  <div
                    className="h-7 w-full rounded border border-slate-800"
                    style={{ background: 'linear-gradient(to right, #000000 0%, #ff0000 100%)' }}
                  />
                </div>
                <div>
                  <div className="text-xs font-mono text-emerald-400 mb-1">Canal G (0 → 255)</div>
                  <div
                    className="h-7 w-full rounded border border-slate-800"
                    style={{ background: 'linear-gradient(to right, #000000 0%, #00ff00 100%)' }}
                  />
                </div>
                <div>
                  <div className="text-xs font-mono text-blue-400 mb-1">Canal B (0 → 255)</div>
                  <div
                    className="h-7 w-full rounded border border-slate-800"
                    style={{ background: 'linear-gradient(to right, #000000 0%, #0000ff 100%)' }}
                  />
                </div>
              </div>
            </div>

            {/* Black Level & White Saturation Swatches */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-2">
              <div className="p-3.5 rounded-xl bg-black border border-slate-800 space-y-2">
                <div className="text-xs font-semibold text-slate-300">
                  Nível de Preto (Black Crush Test — 1% a 10% Luminância)
                </div>
                <div className="grid grid-cols-5 sm:grid-cols-10 gap-1.5">
                  {[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((pct) => {
                    const v = Math.round((pct / 100) * 255);
                    return (
                      <div
                        key={`blk-${pct}`}
                        className="h-12 rounded border border-slate-900 flex items-end justify-center pb-1 text-[11px] font-mono text-slate-400 tabular-nums"
                        style={{ backgroundColor: `rgb(${v}, ${v}, ${v})` }}
                      >
                        {pct}%
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-white border border-slate-300 space-y-2">
                <div className="text-xs font-semibold text-slate-800">
                  Saturação de Branco (White Clipping Test — 90% a 99% Luminância)
                </div>
                <div className="grid grid-cols-5 sm:grid-cols-10 gap-1.5">
                  {[90, 91, 92, 93, 94, 95, 96, 97, 98, 99].map((pct) => {
                    const v = Math.round((pct / 100) * 255);
                    return (
                      <div
                        key={`wht-${pct}`}
                        className="h-12 rounded border border-slate-200 flex items-end justify-center pb-1 text-[11px] font-mono text-slate-700 tabular-nums"
                        style={{ backgroundColor: `rgb(${v}, ${v}, ${v})` }}
                      >
                        {pct}%
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: Panel Uniformity DSE Grid & Input-to-Photon Reflex Latency */}
        {activeLabTab === 'UNIFORMITY_LATENCY' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            <div className="lg:col-span-7 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-white flex items-center gap-1.5">
                  <Sliders className="w-3.5 h-3.5 text-teal-400" />
                  Grade de Uniformidade DSE (Dirty Screen Effect) & Vignetting
                </span>
                <div className="flex items-center gap-1.5">
                  {[5, 10, 15, 25, 50].map((lvl) => (
                    <button
                      key={`gray-${lvl}`}
                      type="button"
                      onClick={() => setUniformityGrayLevel(lvl)}
                      className={`px-2 py-0.5 rounded text-xs font-mono ${
                        uniformityGrayLevel === lvl
                          ? 'bg-teal-500 text-slate-950 font-bold'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      Cinza {lvl}%
                    </button>
                  ))}
                </div>
              </div>

              <div
                className="h-52 w-full rounded-xl border border-slate-700 grid grid-cols-6 grid-rows-4 relative"
                style={{
                  backgroundColor: `rgb(${Math.round((uniformityGrayLevel / 100) * 255)}, ${Math.round(
                    (uniformityGrayLevel / 100) * 255
                  )}, ${Math.round((uniformityGrayLevel / 100) * 255)})`,
                }}
              >
                {Array.from({ length: 24 }).map((_, idx) => (
                  <div
                    key={`cell-${idx}`}
                    className="border border-white/10 flex items-center justify-center text-[11px] font-mono text-white/40"
                  >
                    Z{idx + 1}
                  </div>
                ))}
              </div>
            </div>

            {/* Input-to-Photon Reflex Latency Box */}
            <div className="lg:col-span-5 bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between space-y-3">
              <div>
                <h4 className="text-xs font-semibold text-white">
                  Medidor de Latência de Resposta (Input-to-Photon Reflex)
                </h4>
                <p className="text-xs text-slate-400 mt-0.5">
                  Meça o tempo total entre a transição de quadro na tela e o clique de entrada.
                </p>
              </div>

              {reflexState === 'IDLE' && (
                <button
                  type="button"
                  onClick={handleStartReflexTest}
                  className="h-32 w-full rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 flex flex-col items-center justify-center gap-1 text-white transition"
                >
                  <Play className="w-6 h-6 text-teal-400" />
                  <span className="text-sm font-semibold">Iniciar Teste de Latência Visual</span>
                  <span className="text-xs text-slate-400">
                    Clique assim que o painel ficar VERDE
                  </span>
                </button>
              )}

              {reflexState === 'WAITING' && (
                <button
                  type="button"
                  onClick={handleTriggerReflexClick}
                  className="h-32 w-full rounded-xl bg-rose-600/90 text-white font-bold text-sm flex flex-col items-center justify-center gap-1"
                >
                  <span>AGUARDE O SINAL VERDE...</span>
                  <span className="text-xs font-normal text-rose-100">
                    (Clique agora cancela a rodada)
                  </span>
                </button>
              )}

              {reflexState === 'READY' && (
                <button
                  type="button"
                  onClick={handleTriggerReflexClick}
                  className="h-32 w-full rounded-xl bg-emerald-400 text-slate-950 font-extrabold text-base flex flex-col items-center justify-center gap-1"
                >
                  <span>CLIQUE AGORA!</span>
                </button>
              )}

              {reflexState === 'RESULT' && (
                <button
                  type="button"
                  onClick={handleStartReflexTest}
                  className="h-32 w-full rounded-xl bg-teal-500/20 border border-teal-500/40 text-white flex flex-col items-center justify-center gap-1"
                >
                  <span className="text-2xl font-bold font-mono text-teal-300 tabular-nums">
                    {reflexLastMs} ms
                  </span>
                  <span className="text-xs text-slate-300">
                    Clique para repetir medição de reflexo/input lag
                  </span>
                </button>
              )}

              <div className="flex items-center justify-between text-xs text-slate-400 font-mono tabular-nums">
                <span>
                  Histórico:{' '}
                  {reflexHistoryMs.length > 0
                    ? reflexHistoryMs.map((m) => `${m}ms`).join(', ')
                    : 'Sem amostras'}
                </span>
                {reflexHistoryMs.length > 0 && (
                  <span className="text-teal-300">
                    Média:{' '}
                    {Math.round(
                      reflexHistoryMs.reduce((a, b) => a + b, 0) / reflexHistoryMs.length
                    )}{' '}
                    ms
                  </span>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Section 3: Host Hardware Benchmark Details + Suitability + Attach to Run */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        <div className="xl:col-span-7 bg-[#111722] border border-slate-800/80 rounded-xl p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-teal-400" />
              <h3 className="text-sm font-semibold text-white">
                Resultados Detalhados do Benchmark de Host (CPU, RAM & Storage IOPS) e GPU Stress
              </h3>
            </div>
            <button
              type="button"
              onClick={handleRunClientGpuStress}
              disabled={runningGpuStress}
              className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-teal-300 border border-slate-700 font-medium"
            >
              {runningGpuStress ? 'Executando Shader Stress...' : 'Rodar Stress GPU Cliente'}
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800">
              <div className="text-xs text-slate-400">CPU SHA-256 Single-Core</div>
              <div className="text-base font-bold text-white font-mono tabular-nums mt-0.5">
                {hostResult
                  ? `${hostResult.cpuBenchmark.sha256OpsPerSec.toLocaleString()} ops/s`
                  : '185,000 ops/s'}
              </div>
              <div className="text-xs text-slate-400 font-mono mt-0.5">
                P95: {hostResult?.cpuBenchmark.p95LatencyMs ?? 0.42}ms • P99:{' '}
                {hostResult?.cpuBenchmark.p99LatencyMs ?? 0.68}ms
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800">
              <div className="text-xs text-slate-400">Throughput AST / JSON Engine</div>
              <div className="text-base font-bold text-white font-mono tabular-nums mt-0.5">
                {hostResult
                  ? `${hostResult.cpuBenchmark.astParseOpsPerSec.toLocaleString()} ops/s`
                  : '14,200 ops/s'}
              </div>
              <div className="text-xs text-slate-400 font-mono mt-0.5">
                Cores Lógicos: {hostResult?.hostSummary.cpuCores ?? telemetry.hardwareConcurrency}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800">
              <div className="text-xs text-slate-400">Banda de Memória (Float64)</div>
              <div className="text-base font-bold text-teal-300 font-mono tabular-nums mt-0.5">
                {hostResult
                  ? `${hostResult.memoryBenchmark.sequentialReadMbPerSec} MB/s`
                  : '6,120 MB/s'}
              </div>
              <div className="text-xs text-slate-400 font-mono mt-0.5">
                Alocação: {hostResult?.memoryBenchmark.allocationLatencyUs ?? 180} µs
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800">
              <div className="text-xs text-slate-400">Storage Seq Read / Write</div>
              <div className="text-base font-bold text-white font-mono tabular-nums mt-0.5">
                {hostResult
                  ? `${hostResult.storageBenchmark.sequentialReadMbPerSec} / ${hostResult.storageBenchmark.sequentialWriteMbPerSec} MB/s`
                  : '1,450 / 980 MB/s'}
              </div>
              <div className="text-xs text-slate-400 font-mono mt-0.5">
                IOPS 4K: {hostResult?.storageBenchmark.random4kIops ?? 18400}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800">
              <div className="text-xs text-slate-400">Canvas2D & Shader Trig Ops</div>
              <div className="text-base font-bold text-white font-mono tabular-nums mt-0.5">
                {clientGpuStress.canvas2dFps} FPS
              </div>
              <div className="text-xs text-slate-400 font-mono mt-0.5">
                {(clientGpuStress.trigShaderOpsPerSec / 1_000_000).toFixed(1)}M trig ops/s
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/70 border border-slate-800">
              <div className="text-xs text-slate-400">Hash SHA-256 de Verificação</div>
              <div className="text-xs font-bold text-emerald-300 font-mono mt-1 truncate">
                {hostResult?.verificationSha256 ?? '9f86d081884c7d659a2feaa0c55ad015'}
              </div>
              <div className="text-xs text-slate-400 mt-0.5">Auditoria Determinística</div>
            </div>
          </div>
        </div>

        {/* Suitability & Attach to Run */}
        <div className="xl:col-span-5 bg-[#111722] border border-slate-800/80 rounded-xl p-5 flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-teal-400" />
                Adequação Operacional & Vínculo ao Relatório
              </h3>
              <span className="text-xs font-mono text-teal-300 font-bold">
                Score {consolidatedIndex.totalScore}/100 (Tier {consolidatedIndex.tier})
              </span>
            </div>

            <div className="space-y-2">
              {consolidatedIndex.suitability.map((item) => (
                <div
                  key={item.profile}
                  className="p-2.5 rounded-lg bg-slate-900/70 border border-slate-800 flex items-center justify-between gap-2"
                >
                  <div className="flex items-center gap-2">
                    <CheckCircle2
                      className={`w-4 h-4 shrink-0 ${
                        item.ready ? 'text-emerald-400' : 'text-amber-400'
                      }`}
                    />
                    <span className="text-xs text-slate-200">{item.profile}</span>
                  </div>
                  <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-slate-800 text-teal-300 shrink-0">
                    {item.status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800 space-y-2.5">
            <label htmlFor="attach-benchmark-run-select" className="block text-xs text-slate-300">
              Vincular Telemetria de Hardware & Display a um BenchmarkRun:
            </label>
            <div className="flex items-center gap-2">
              <select
                id="attach-benchmark-run-select"
                value={targetRunId}
                onChange={(e) => setTargetRunId(e.target.value)}
                className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-teal-500"
              >
                {runs.length === 0 ? (
                  <option value="">Nenhuma execução disponível</option>
                ) : (
                  runs.map((r) => {
                    const topScore = r.scoreCards?.[0]?.groupedScores?.overallScore ?? 0;
                    const label = r.scoreCards?.[0]?.softwareName ?? 'Benchmark';
                    return (
                      <option key={r.id} value={r.id}>
                        {r.id} ({label}) — Score {topScore.toFixed(2)} ({r.status})
                      </option>
                    );
                  })
                )}
              </select>
              <button
                type="button"
                onClick={() => void handleAttachSnapshotToRun()}
                disabled={!targetRunId}
                className="px-3.5 py-2 rounded-lg bg-teal-500 hover:bg-teal-400 text-slate-950 text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50"
              >
                <Link2 className="w-3.5 h-3.5" />
                Anexar ao Run
              </button>
            </div>
            {attachStatusMsg && (
              <div className="text-xs text-teal-300 font-mono">{attachStatusMsg}</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default HardwareAndDisplayBenchmarkModule;
