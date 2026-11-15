import React, { useEffect, useRef, useState } from 'react';

export type HairlineFigureType =
  | 'padlock'
  | 'vault'
  | 'lockers'
  | 'phosphor'
  | 'terrain'
  | 'exploded'
  | 'turntable'
  | 'stack'
  | 'router'
  | 'sieve'
  | 'terminal'
  | 'loupe'
  | 'layers'
  | 'gauge';

export interface HairlineAnimatedFigureProps {
  type: HairlineFigureType;
  size?: number;
  className?: string;
  color?: string;
  accentColor?: string;
  cycleDurationMs?: number;
  pauseDurationMs?: number;
  title?: string;
}

const COS30 = 0.8660254;
const SIN30 = 0.5;

const CATEGORY_DEFAULT_COLORS: Record<string, { stroke: string; glow: string; bg: string }> = {
  lockers: {
    stroke: '#3b82f6',
    glow: 'rgba(59, 130, 246, 0.25)',
    bg: 'rgba(59, 130, 246, 0.08)',
  },
  vault: {
    stroke: '#10b981',
    glow: 'rgba(16, 185, 129, 0.25)',
    bg: 'rgba(16, 185, 129, 0.08)',
  },
  padlock: {
    stroke: '#f59e0b',
    glow: 'rgba(245, 158, 11, 0.25)',
    bg: 'rgba(245, 158, 11, 0.08)',
  },
  router: {
    stroke: '#06b6d4',
    glow: 'rgba(6, 182, 212, 0.25)',
    bg: 'rgba(6, 182, 212, 0.08)',
  },
  exploded: {
    stroke: '#8b5cf6',
    glow: 'rgba(139, 92, 246, 0.25)',
    bg: 'rgba(139, 92, 246, 0.08)',
  },
  layers: {
    stroke: '#8b5cf6',
    glow: 'rgba(139, 92, 246, 0.25)',
    bg: 'rgba(139, 92, 246, 0.08)',
  },
  turntable: {
    stroke: '#f43f5e',
    glow: 'rgba(244, 63, 94, 0.25)',
    bg: 'rgba(244, 63, 94, 0.08)',
  },
  gauge: {
    stroke: '#f43f5e',
    glow: 'rgba(244, 63, 94, 0.25)',
    bg: 'rgba(244, 63, 94, 0.08)',
  },
  phosphor: {
    stroke: '#31d6c4',
    glow: 'rgba(49, 214, 196, 0.25)',
    bg: 'rgba(49, 214, 196, 0.08)',
  },
  terrain: {
    stroke: '#14b8a6',
    glow: 'rgba(20, 184, 166, 0.25)',
    bg: 'rgba(20, 184, 166, 0.08)',
  },
  stack: {
    stroke: '#6366f1',
    glow: 'rgba(99, 102, 241, 0.25)',
    bg: 'rgba(99, 102, 241, 0.08)',
  },
  sieve: {
    stroke: '#eab308',
    glow: 'rgba(234, 179, 8, 0.25)',
    bg: 'rgba(234, 179, 8, 0.08)',
  },
  terminal: {
    stroke: '#31d6c4',
    glow: 'rgba(49, 214, 196, 0.25)',
    bg: 'rgba(49, 214, 196, 0.08)',
  },
  loupe: {
    stroke: '#0ea5e9',
    glow: 'rgba(14, 165, 233, 0.25)',
    bg: 'rgba(14, 165, 233, 0.08)',
  },
};

/**
 * Projeção isométrica real a 30° (COS30 = 0.8660254, SIN30 = 0.5).
 */
export function isoProject(
  x: number,
  y: number,
  z: number,
  cx = 60,
  cy = 60
): { sx: number; sy: number } {
  return {
    sx: Number((cx + (x - y) * COS30).toFixed(2)),
    sy: Number((cy + (x + y) * SIN30 - z).toFixed(2)),
  };
}

function isoPolygonPoints(
  pts: Array<[number, number, number]>,
  cx = 60,
  cy = 60
): string {
  return pts
    .map(([x, y, z]) => {
      const p = isoProject(x, y, z, cx, cy);
      return `${p.sx},${p.sy}`;
    })
    .join(' ');
}

/**
 * Curva cinética Action-Then-Pause com pausa explícita de 2000ms entre ciclos.
 */
export function computeActionThenPauseWave(
  elapsedMs: number,
  activeDurationMs = 2600,
  pauseDurationMs = 2000
): number {
  const totalCycle = activeDurationMs + pauseDurationMs;
  const phaseTime = ((elapsedMs % totalCycle) + totalCycle) % totalCycle;
  if (phaseTime >= activeDurationMs) {
    return 0;
  }
  const normalized = phaseTime / activeDurationMs;
  return 0.5 * (1 - Math.cos(normalized * Math.PI * 2));
}

function computeLinearSweepWithPause(
  elapsedMs: number,
  activeDurationMs = 2600,
  pauseDurationMs = 2000
): number {
  const totalCycle = activeDurationMs + pauseDurationMs;
  const phaseTime = ((elapsedMs % totalCycle) + totalCycle) % totalCycle;
  if (phaseTime >= activeDurationMs) {
    return 1;
  }
  const t = phaseTime / activeDurationMs;
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

type TickSubscriber = (elapsedMs: number) => void;
const activeSubscribers = new Set<TickSubscriber>();
let globalRafId: number | null = null;
let startTimestamp: number | null = null;

function stepGlobalClock(now: number) {
  if (startTimestamp === null) startTimestamp = now;
  const elapsed = now - startTimestamp;
  for (const sub of activeSubscribers) {
    sub(elapsed);
  }
  if (activeSubscribers.size > 0) {
    globalRafId = window.requestAnimationFrame(stepGlobalClock);
  } else {
    globalRafId = null;
  }
}

function subscribeClock(cb: TickSubscriber): () => void {
  activeSubscribers.add(cb);
  if (globalRafId === null && typeof window !== 'undefined') {
    globalRafId = window.requestAnimationFrame(stepGlobalClock);
  }
  return () => {
    activeSubscribers.delete(cb);
    if (activeSubscribers.size === 0 && globalRafId !== null && typeof window !== 'undefined') {
      window.cancelAnimationFrame(globalRafId);
      globalRafId = null;
    }
  };
}

/**
 * HairlineAnimatedFigure — Ilustrações técnicas vetoriais isométricas a 30°
 * com oclusão geométrica real (chapas opacas --hairline-plate), traço fino (strokeWidth="1.25")
 * e cadência Action-Then-Pause com repouso estrito de 2000ms.
 */
export const HairlineAnimatedFigure: React.FC<HairlineAnimatedFigureProps> = React.memo(
  ({
    type,
    size = 48,
    className = '',
    color,
    accentColor,
    cycleDurationMs = 2600,
    pauseDurationMs = 2000,
    title,
  }) => {
    const canonicalType =
      type === 'layers' ? 'exploded' : type === 'gauge' ? 'turntable' : type;

    const colorConfig =
      CATEGORY_DEFAULT_COLORS[type] ||
      CATEGORY_DEFAULT_COLORS[canonicalType] ||
      CATEGORY_DEFAULT_COLORS.vault;
    const activeStroke = color || accentColor || colorConfig.stroke;

    const containerRef = useRef<HTMLDivElement | null>(null);
    const [isVisible, setIsVisible] = useState(true);
    const [elapsedMs, setElapsedMs] = useState(0);

    useEffect(() => {
      const el = containerRef.current;
      if (!el || typeof IntersectionObserver === 'undefined') return;
      const obs = new IntersectionObserver(
        (entries) => {
          const entry = entries[0];
          if (entry) setIsVisible(entry.isIntersecting);
        },
        { threshold: 0.05 }
      );
      obs.observe(el);
      return () => obs.disconnect();
    }, []);

    useEffect(() => {
      if (!isVisible) return;
      return subscribeClock((ms) => {
        setElapsedMs(ms);
      });
    }, [isVisible]);

    const wave = computeActionThenPauseWave(elapsedMs, cycleDurationMs, pauseDurationMs);
    const sweep = computeLinearSweepWithPause(elapsedMs, cycleDurationMs, pauseDurationMs);
    const isPaused =
      ((elapsedMs % (cycleDurationMs + pauseDurationMs)) +
        (cycleDurationMs + pauseDurationMs)) %
        (cycleDurationMs + pauseDurationMs) >=
      cycleDurationMs;

    const renderIsoPrismPlate = (
      halfSize: number,
      zHeight: number,
      thickness: number,
      isAccent = false,
      cx = 60,
      cy = 64
    ) => {
      const s = halfSize;
      const zTop = zHeight;
      const zBot = zHeight - thickness;
      const topPts = isoPolygonPoints(
        [
          [-s, -s, zTop],
          [s, -s, zTop],
          [s, s, zTop],
          [-s, s, zTop],
        ],
        cx,
        cy
      );
      const leftPts = isoPolygonPoints(
        [
          [-s, s, zTop],
          [s, s, zTop],
          [s, s, zBot],
          [-s, s, zBot],
        ],
        cx,
        cy
      );
      const rightPts = isoPolygonPoints(
        [
          [s, -s, zTop],
          [s, s, zTop],
          [s, s, zBot],
          [s, -s, zBot],
        ],
        cx,
        cy
      );
      return (
        <g
          stroke={isAccent ? activeStroke : 'currentColor'}
          strokeWidth="1.25"
          strokeLinejoin="round"
        >
          <polygon points={leftPts} fill="var(--hairline-plate, #0f141c)" />
          <polygon points={rightPts} fill="var(--hairline-plate, #0f141c)" />
          <polygon points={topPts} fill="var(--hairline-plate, #0f141c)" />
        </g>
      );
    };

    return (
      <div
        ref={containerRef}
        title={title}
        style={{
          width: size,
          height: size,
          backgroundColor: colorConfig.bg,
          boxShadow: isPaused ? 'none' : `0 0 14px -3px ${colorConfig.glow}`,
        }}
        className={`relative inline-flex items-center justify-center rounded-xl border border-slate-200/70 dark:border-slate-800/80 transition-shadow duration-300 select-none shrink-0 text-slate-600 dark:text-slate-300 ${className}`}
      >
        <svg
          width={Math.round(size * 0.88)}
          height={Math.round(size * 0.88)}
          viewBox="0 0 120 120"
          fill="none"
          aria-hidden="true"
        >
          {/* Grade técnica sutil de fundo */}
          <g stroke="currentColor" strokeOpacity="0.14" strokeWidth="1">
            <line x1="12" y1="60" x2="108" y2="60" strokeDasharray="2 3" />
            <line x1="60" y1="12" x2="60" y2="108" strokeDasharray="2 3" />
            <circle cx="60" cy="60" r="46" strokeOpacity="0.1" />
          </g>

          {canonicalType === 'padlock' && (() => {
            const shackleLift = wave * 9;
            const pinOffsets = [wave * 4, (1 - wave) * 3.5, wave * 5];
            return (
              <g strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round">
                <g transform={`translate(0, ${(-shackleLift).toFixed(2)})`}>
                  <path
                    d="M 44 50 L 44 33 A 16 14 0 0 1 76 33 L 76 50"
                    stroke={activeStroke}
                    strokeWidth="1.5"
                  />
                  <path
                    d="M 48 50 L 48 34 A 12 10 0 0 1 72 34 L 72 50"
                    stroke="currentColor"
                  />
                </g>
                {renderIsoPrismPlate(22, 8, 22, false, 60, 74)}
                {[0, 1, 2].map((idx) => {
                  const x = 52 + idx * 8;
                  const yTop = 62 - pinOffsets[idx];
                  return (
                    <g key={idx}>
                      <line x1={x} y1={yTop} x2={x} y2={76} stroke={activeStroke} />
                      <circle
                        cx={x}
                        cy={yTop}
                        r="1.8"
                        fill="var(--hairline-plate, #0f141c)"
                        stroke={activeStroke}
                      />
                    </g>
                  );
                })}
              </g>
            );
          })()}

          {canonicalType === 'vault' && (() => {
            const wheelDeg = sweep * 120;
            const boltExtend = wave * 7;
            return (
              <g strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round">
                <rect
                  x="24"
                  y="22"
                  width="72"
                  height="76"
                  rx="6"
                  fill="var(--hairline-plate, #0f141c)"
                  stroke="currentColor"
                />
                <line
                  x1={18 - boltExtend}
                  y1="42"
                  x2="28"
                  y2="42"
                  stroke={activeStroke}
                  strokeWidth="2"
                />
                <line
                  x1={18 - boltExtend}
                  y1="78"
                  x2="28"
                  y2="78"
                  stroke={activeStroke}
                  strokeWidth="2"
                />
                <line
                  x1="92"
                  y1="42"
                  x2={102 + boltExtend}
                  y2="42"
                  stroke={activeStroke}
                  strokeWidth="2"
                />
                <line
                  x1="92"
                  y1="78"
                  x2={102 + boltExtend}
                  y2="78"
                  stroke={activeStroke}
                  strokeWidth="2"
                />
                <circle
                  cx="60"
                  cy="60"
                  r="24"
                  fill="var(--hairline-plate, #0f141c)"
                  stroke="currentColor"
                />
                <circle cx="60" cy="60" r="18" stroke={activeStroke} strokeDasharray="3 3" />
                <g transform={`rotate(${wheelDeg.toFixed(1)} 60 60)`} stroke={activeStroke}>
                  <line x1="60" y1="43" x2="60" y2="77" />
                  <line x1="45" y1="51" x2="75" y2="69" />
                  <line x1="75" y1="51" x2="45" y2="69" />
                  <circle
                    cx="60"
                    cy="60"
                    r="5"
                    fill="var(--hairline-plate, #0f141c)"
                    stroke={activeStroke}
                  />
                </g>
              </g>
            );
          })()}

          {canonicalType === 'lockers' && (() => {
            const drawerPull = wave * 11;
            return (
              <g strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round">
                {renderIsoPrismPlate(22, -12, 10, false, 60, 62)}
                <g
                  transform={`translate(${(drawerPull * COS30).toFixed(2)}, ${(
                    drawerPull * SIN30
                  ).toFixed(2)})`}
                >
                  {renderIsoPrismPlate(22, 2, 10, true, 60, 62)}
                </g>
                {renderIsoPrismPlate(22, 16, 10, false, 60, 62)}
              </g>
            );
          })()}

          {canonicalType === 'phosphor' && (() => {
            const radarDeg = sweep * 360;
            return (
              <g strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round">
                <circle
                  cx="60"
                  cy="60"
                  r="36"
                  fill="var(--hairline-plate, #0f141c)"
                  stroke="currentColor"
                />
                <circle cx="60" cy="60" r="24" stroke="currentColor" strokeOpacity="0.45" />
                <circle cx="60" cy="60" r="12" stroke="currentColor" strokeOpacity="0.35" />
                <path
                  d={`M 28 60 Q 44 ${(42 + wave * 16).toFixed(1)} 60 60 T 92 60`}
                  stroke={activeStroke}
                  strokeWidth="1.4"
                />
                <g transform={`rotate(${radarDeg.toFixed(1)} 60 60)`}>
                  <line x1="60" y1="60" x2="60" y2="25" stroke={activeStroke} strokeWidth="1.5" />
                  <circle cx="60" cy="36" r="2.2" fill={activeStroke} />
                </g>
                <circle
                  cx="60"
                  cy="60"
                  r="3"
                  fill="var(--hairline-plate, #0f141c)"
                  stroke={activeStroke}
                />
              </g>
            );
          })()}

          {canonicalType === 'terrain' && (() => {
            const scanShift = (wave - 0.5) * 18;
            return (
              <g strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round">
                {[-18, -9, 0, 9, 18].map((yOff, idx) => {
                  const pts: string[] = [];
                  for (let x = -22; x <= 22; x += 4) {
                    const dist = Math.hypot(x - scanShift * 0.4, yOff);
                    const z = Math.max(0, 16 - dist * 0.65) * (0.65 + 0.35 * wave);
                    const p = isoProject(x, yOff, z, 60, 68);
                    pts.push(`${p.sx},${p.sy}`);
                  }
                  return (
                    <polyline
                      key={idx}
                      points={pts.join(' ')}
                      fill="none"
                      stroke={idx === 2 ? activeStroke : 'currentColor'}
                      strokeWidth={idx === 2 ? '1.5' : '1.1'}
                    />
                  );
                })}
              </g>
            );
          })()}

          {canonicalType === 'exploded' && (() => {
            const spread = wave * 11;
            return (
              <g strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round">
                <line
                  x1="60"
                  y1="16"
                  x2="60"
                  y2="104"
                  stroke={activeStroke}
                  strokeDasharray="2 3"
                />
                {renderIsoPrismPlate(22, -14 - spread, 5, false, 60, 64)}
                {renderIsoPrismPlate(22, 2, 5, true, 60, 64)}
                {renderIsoPrismPlate(22, 18 + spread, 5, false, 60, 64)}
              </g>
            );
          })()}

          {canonicalType === 'turntable' && (() => {
            const needleAngle = -55 + wave * 110;
            const ringSpin = sweep * 180;
            return (
              <g strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round">
                <circle
                  cx="60"
                  cy="64"
                  r="34"
                  fill="var(--hairline-plate, #0f141c)"
                  stroke="currentColor"
                />
                <g transform={`rotate(${ringSpin.toFixed(1)} 60 64)`}>
                  <circle
                    cx="60"
                    cy="64"
                    r="26"
                    stroke={activeStroke}
                    strokeDasharray="6 4"
                  />
                </g>
                <path d="M 34 64 A 26 26 0 0 1 86 64" stroke="currentColor" />
                <g transform={`rotate(${needleAngle.toFixed(1)} 60 64)`}>
                  <line x1="60" y1="64" x2="60" y2="36" stroke={activeStroke} strokeWidth="1.6" />
                  <circle cx="60" cy="36" r="2" fill={activeStroke} />
                </g>
                <circle
                  cx="60"
                  cy="64"
                  r="4"
                  fill="var(--hairline-plate, #0f141c)"
                  stroke={activeStroke}
                />
              </g>
            );
          })()}

          {canonicalType === 'stack' && (() => {
            const liftTop = wave * 10;
            const liftMid = wave * 5;
            return (
              <g strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round">
                {renderIsoPrismPlate(24, -14, 7, false, 60, 66)}
                {renderIsoPrismPlate(20, 0 + liftMid, 7, false, 60, 66)}
                {renderIsoPrismPlate(16, 14 + liftTop, 7, true, 60, 66)}
              </g>
            );
          })()}

          {canonicalType === 'router' && (() => {
            const packetPos = sweep;
            const hub = isoProject(0, 0, 6, 60, 62);
            const nodes = [
              isoProject(-24, -16, 0, 60, 62),
              isoProject(24, -16, 0, 60, 62),
              isoProject(-22, 20, 0, 60, 62),
              isoProject(22, 20, 0, 60, 62),
            ];
            return (
              <g strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round">
                {nodes.map((n, idx) => {
                  const px = hub.sx + (n.sx - hub.sx) * packetPos;
                  const py = hub.sy + (n.sy - hub.sy) * packetPos;
                  return (
                    <g key={idx}>
                      <line x1={hub.sx} y1={hub.sy} x2={n.sx} y2={n.sy} stroke="currentColor" />
                      <circle
                        cx={n.sx}
                        cy={n.sy}
                        r="4.5"
                        fill="var(--hairline-plate, #0f141c)"
                        stroke="currentColor"
                      />
                      <circle
                        cx={px}
                        cy={py}
                        r="2.3"
                        fill={activeStroke}
                        stroke="var(--hairline-plate, #0f141c)"
                      />
                    </g>
                  );
                })}
                {renderIsoPrismPlate(11, 10, 6, true, 60, 62)}
              </g>
            );
          })()}

          {canonicalType === 'sieve' && (() => {
            const dropZ = 22 - sweep * 38;
            return (
              <g strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round">
                {renderIsoPrismPlate(22, -10, 3, false, 60, 64)}
                {renderIsoPrismPlate(22, 10, 3, true, 60, 64)}
                {[-10, 0, 10].map((xOff, i) => {
                  const p = isoProject(xOff, (i - 1) * 8, dropZ + i * 3, 60, 64);
                  return (
                    <circle
                      key={i}
                      cx={p.sx}
                      cy={p.sy}
                      r="2.4"
                      fill="var(--hairline-plate, #0f141c)"
                      stroke={activeStroke}
                    />
                  );
                })}
              </g>
            );
          })()}

          {canonicalType === 'terminal' && (() => {
            const scanY = 38 + wave * 42;
            return (
              <g strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round">
                <rect
                  x="20"
                  y="24"
                  width="80"
                  height="72"
                  rx="6"
                  fill="var(--hairline-plate, #0f141c)"
                  stroke="currentColor"
                />
                <line x1="20" y1="36" x2="100" y2="36" stroke="currentColor" />
                <circle cx="28" cy="30" r="1.5" fill={activeStroke} />
                <circle cx="34" cy="30" r="1.5" fill="currentColor" />
                <circle cx="40" cy="30" r="1.5" fill="currentColor" />
                <line x1="28" y1="46" x2="62" y2="46" stroke={activeStroke} />
                <line x1="34" y1="56" x2="84" y2="56" stroke="currentColor" />
                <line x1="34" y1="66" x2="74" y2="66" stroke="currentColor" />
                <line x1="28" y1="76" x2="54" y2="76" stroke={activeStroke} />
                <line x1="28" y1="86" x2="78" y2="86" stroke="currentColor" />
                <line
                  x1="23"
                  y1={scanY.toFixed(1)}
                  x2="97"
                  y2={scanY.toFixed(1)}
                  stroke={activeStroke}
                  strokeDasharray="3 2"
                />
              </g>
            );
          })()}

          {canonicalType === 'loupe' && (() => {
            const lensX = 54 + (wave - 0.5) * 16;
            const lensY = 54 + Math.sin(wave * Math.PI) * 8;
            return (
              <g strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round">
                {renderIsoPrismPlate(24, -4, 5, false, 60, 68)}
                <g transform={`translate(${(lensX - 60).toFixed(2)}, ${(lensY - 56).toFixed(2)})`}>
                  <circle
                    cx="60"
                    cy="52"
                    r="16"
                    fill="var(--hairline-plate, #0f141c)"
                    fillOpacity="0.88"
                    stroke={activeStroke}
                    strokeWidth="1.5"
                  />
                  <line x1="54" y1="52" x2="66" y2="52" stroke={activeStroke} />
                  <line x1="60" y1="46" x2="60" y2="58" stroke={activeStroke} />
                  <line x1="71" y1="63" x2="84" y2="76" stroke={activeStroke} strokeWidth="2" />
                </g>
              </g>
            );
          })()}
        </svg>
      </div>
    );
  }
);
export default HairlineAnimatedFigure;
