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
  width?: number;
  height?: number;
  variant?: 'hero' | 'card' | 'badge';
  active?: boolean;
  unlocked?: boolean;
  typingProgress?: number;
  scanning?: boolean;
  className?: string;
  color?: string;
  accentColor?: string;
  cycleDurationMs?: number;
  pauseDurationMs?: number;
  title?: string;
  subtitle?: string;
}

const COS30 = 0.8660254;
const SIN30 = 0.5;
const CYCLE_MS = 1800;
const PAUSE_MS = 2000;

const CATEGORY_DEFAULT_COLORS: Record<string, { stroke: string; glow: string; bg: string }> = {
  lockers: {
    stroke: '#38bdf8',
    glow: 'rgba(56, 189, 248, 0.28)',
    bg: 'rgba(56, 189, 248, 0.08)',
  },
  vault: {
    stroke: '#f43f5e',
    glow: 'rgba(244, 63, 94, 0.28)',
    bg: 'rgba(244, 63, 94, 0.08)',
  },
  padlock: {
    stroke: '#a855f7',
    glow: 'rgba(168, 85, 247, 0.28)',
    bg: 'rgba(168, 85, 247, 0.08)',
  },
  router: {
    stroke: '#10b981',
    glow: 'rgba(16, 185, 129, 0.28)',
    bg: 'rgba(16, 185, 129, 0.08)',
  },
  exploded: {
    stroke: '#f59e0b',
    glow: 'rgba(245, 158, 11, 0.28)',
    bg: 'rgba(245, 158, 11, 0.08)',
  },
  layers: {
    stroke: '#f59e0b',
    glow: 'rgba(245, 158, 11, 0.28)',
    bg: 'rgba(245, 158, 11, 0.08)',
  },
  turntable: {
    stroke: '#06b6d4',
    glow: 'rgba(6, 182, 212, 0.28)',
    bg: 'rgba(6, 182, 212, 0.08)',
  },
  gauge: {
    stroke: '#06b6d4',
    glow: 'rgba(6, 182, 212, 0.28)',
    bg: 'rgba(6, 182, 212, 0.08)',
  },
  phosphor: {
    stroke: '#10b981',
    glow: 'rgba(16, 185, 129, 0.28)',
    bg: 'rgba(16, 185, 129, 0.08)',
  },
  terrain: {
    stroke: '#10b981',
    glow: 'rgba(16, 185, 129, 0.28)',
    bg: 'rgba(16, 185, 129, 0.08)',
  },
  stack: {
    stroke: '#a855f7',
    glow: 'rgba(168, 85, 247, 0.28)',
    bg: 'rgba(168, 85, 247, 0.08)',
  },
  sieve: {
    stroke: '#f59e0b',
    glow: 'rgba(245, 158, 11, 0.28)',
    bg: 'rgba(245, 158, 11, 0.08)',
  },
  terminal: {
    stroke: '#10b981',
    glow: 'rgba(16, 185, 129, 0.28)',
    bg: 'rgba(16, 185, 129, 0.08)',
  },
  loupe: {
    stroke: '#38bdf8',
    glow: 'rgba(56, 189, 248, 0.28)',
    bg: 'rgba(56, 189, 248, 0.08)',
  },
};

/**
 * Projeção isométrica real a 30° com suporte a inclinação interativa por mouse (tiltX, tiltY).
 */
export function isoProject(
  x: number,
  y: number,
  z: number,
  cx = 80,
  cy = 72,
  tiltX = 0,
  tiltY = 0
): { sx: number; sy: number } {
  const cosAngle = COS30 + tiltX * 0.04;
  const sinAngle = SIN30 + tiltY * 0.035;
  return {
    sx: Number((cx + (x - y) * cosAngle).toFixed(2)),
    sy: Number((cy + (x + y) * sinAngle - z).toFixed(2)),
  };
}

function isoPolygonPoints(
  pts: Array<[number, number, number]>,
  cx = 80,
  cy = 72,
  tiltX = 0,
  tiltY = 0
): string {
  return pts
    .map(([x, y, z]) => {
      const p = isoProject(x, y, z, cx, cy, tiltX, tiltY);
      return `${p.sx},${p.sy}`;
    })
    .join(' ');
}

export function isoRoundedPlatePath(
  halfW: number,
  halfD: number,
  z: number,
  cx = 80,
  cy = 72,
  tiltX = 0,
  tiltY = 0
): string {
  const p0 = isoProject(-halfW, -halfD, z, cx, cy, tiltX, tiltY);
  const p1 = isoProject(halfW, -halfD, z, cx, cy, tiltX, tiltY);
  const p2 = isoProject(halfW, halfD, z, cx, cy, tiltX, tiltY);
  const p3 = isoProject(-halfW, halfD, z, cx, cy, tiltX, tiltY);
  return `M ${p0.sx} ${p0.sy} L ${p1.sx} ${p1.sy} L ${p2.sx} ${p2.sy} L ${p3.sx} ${p3.sy} Z`;
}

/**
 * Curva cinética Action-Then-Pause: 1 ciclo de 1800ms seguido de 2000ms de pausa estática.
 */
export function computeActionThenPauseWave(
  elapsedMs: number,
  activeDurationMs = CYCLE_MS,
  pauseDurationMs = PAUSE_MS
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
  activeDurationMs = CYCLE_MS,
  pauseDurationMs = PAUSE_MS
): number {
  const totalCycle = activeDurationMs + pauseDurationMs;
  const phaseTime = ((elapsedMs % totalCycle) + totalCycle) % totalCycle;
  if (phaseTime >= activeDurationMs) {
    return 1;
  }
  const t = phaseTime / activeDurationMs;
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

interface HairlineSpringState {
  x: number;
  y: number;
  vx: number;
  vy: number;
  tx: number;
  ty: number;
}

function stepHairlineSpring(s: HairlineSpringState): boolean {
  const stiffness = 0.14;
  const damping = 0.76;
  const ax = (s.tx - s.x) * stiffness;
  const ay = (s.ty - s.y) * stiffness;
  s.vx = (s.vx + ax) * damping;
  s.vy = (s.vy + ay) * damping;
  s.x += s.vx;
  s.y += s.vy;
  return (
    Math.abs(s.tx - s.x) > 0.005 ||
    Math.abs(s.ty - s.y) > 0.005 ||
    Math.abs(s.vx) > 0.005 ||
    Math.abs(s.vy) > 0.005
  );
}

type TickSubscriber = (elapsedMs: number) => void;
const activeSubscribers = new Set<TickSubscriber>();
let globalRafId: number | null = null;
let startTimestamp: number | null = null;
let lastNotifyTimestamp = 0;

function stepGlobalClock(now: number) {
  if (startTimestamp === null) startTimestamp = now;
  if (now - lastNotifyTimestamp >= 32) {
    lastNotifyTimestamp = now;
    const elapsed = now - startTimestamp;
    for (const sub of activeSubscribers) {
      sub(elapsed);
    }
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
 * HairlineAnimatedFigure — Projeção 3D Isométrica Interativa estilo Winhood-MAX
 * com mola física ao cursor (HairlineSpring), base isométrica em dupla camada,
 * ciclo cinético de 1.8s + 2.0s de pausa e suporte a variant="hero" | "card" | "badge".
 */
export const HairlineAnimatedFigure: React.FC<HairlineAnimatedFigureProps> = React.memo(
  ({
    type,
    size,
    width,
    height,
    variant = 'card',
    active = true,
    unlocked = false,
    typingProgress = 0,
    scanning = false,
    className = '',
    color,
    accentColor,
    cycleDurationMs = CYCLE_MS,
    pauseDurationMs = PAUSE_MS,
    title,
    subtitle,
  }) => {
    const canonicalType =
      type === 'layers' ? 'exploded' : type === 'gauge' ? 'turntable' : type;

    const colorConfig =
      CATEGORY_DEFAULT_COLORS[type] ||
      CATEGORY_DEFAULT_COLORS[canonicalType] ||
      CATEGORY_DEFAULT_COLORS.vault;

    const resolvedAccent =
      unlocked && canonicalType === 'padlock'
        ? '#10b981'
        : accentColor || color || colorConfig.stroke;

    // Resolve dimensions according to variant & explicit props
    const resolvedWidth =
      width !== undefined
        ? width
        : size !== undefined
          ? size
          : variant === 'hero'
            ? 188
            : variant === 'card'
              ? 64
              : 56;

    const resolvedHeight =
      height !== undefined
        ? height
        : size !== undefined
          ? size
          : variant === 'hero'
            ? 148
            : variant === 'card'
              ? 64
              : 56;

    const containerRef = useRef<HTMLDivElement | null>(null);
    const [isVisible, setIsVisible] = useState(true);
    const [isHovered, setIsHovered] = useState(false);
    const [elapsedMs, setElapsedMs] = useState(0);
    const springRef = useRef<HairlineSpringState>({
      x: 0,
      y: 0,
      vx: 0,
      vy: 0,
      tx: 0,
      ty: 0,
    });
    const [tilt, setTilt] = useState<{ mx: number; my: number }>({ mx: 0, my: 0 });

    useEffect(() => {
      const el = containerRef.current;
      if (!el || typeof IntersectionObserver === 'undefined') return;
      const obs = new IntersectionObserver(
        (entries) => {
          const entry = entries[0];
          if (entry) setIsVisible(entry.isIntersecting);
        },
        { threshold: 0.02 }
      );
      obs.observe(el);
      return () => obs.disconnect();
    }, []);

    const pausedRef = useRef(false);

    useEffect(() => {
      if (!isVisible || !active) return;
      return subscribeClock((ms) => {
        const effectiveMs = scanning ? ms * 1.65 : ms;
        const effPause = scanning || isHovered ? 350 : pauseDurationMs;
        const period = cycleDurationMs + effPause;
        const phase = ((effectiveMs % period) + period) % period;
        const currentlyInPause = !isHovered && !scanning && phase >= cycleDurationMs;
        const moved = stepHairlineSpring(springRef.current);

        if (moved) {
          setTilt({
            mx: Number(springRef.current.x.toFixed(3)),
            my: Number(springRef.current.y.toFixed(3)),
          });
        }

        if (!currentlyInPause) {
          pausedRef.current = false;
          setElapsedMs(effectiveMs);
        } else if (!pausedRef.current) {
          pausedRef.current = true;
          setElapsedMs(cycleDurationMs + 1);
        }
      });
    }, [isVisible, active, scanning, isHovered, cycleDurationMs, pauseDurationMs]);

    const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
      const rect = e.currentTarget.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      const nx = ((e.clientX - rect.left) / rect.width - 0.5) * 2;
      const ny = ((e.clientY - rect.top) / rect.height - 0.5) * 2;
      springRef.current.tx = Math.max(-1, Math.min(1, nx));
      springRef.current.ty = Math.max(-1, Math.min(1, ny));
      if (!isHovered) setIsHovered(true);
    };

    const handleMouseLeave = () => {
      springRef.current.tx = 0;
      springRef.current.ty = 0;
      setIsHovered(false);
    };

    const effectivePauseMs = scanning || isHovered ? 350 : pauseDurationMs;
    const wave = computeActionThenPauseWave(elapsedMs, cycleDurationMs, effectivePauseMs);
    const sweep = computeLinearSweepWithPause(elapsedMs, cycleDurationMs, effectivePauseMs);
    const totalPeriod = cycleDurationMs + effectivePauseMs;
    const isPaused =
      !isHovered &&
      !scanning &&
      ((elapsedMs % totalPeriod) + totalPeriod) % totalPeriod >= cycleDurationMs;

    const cx = 80;
    const cy = subtitle && (variant === 'hero' || resolvedWidth >= 120) ? 64 : 69;
    const { mx, my } = tilt;

    /**
     * Renderiza um prisma 3D isométrico completo (faces frontal-esquerda, frontal-direita e topo)
     * com oclusão real e iluminação sutil nas arestas.
     */
    const renderIsoPrism = (
      x0: number,
      y0: number,
      zBot: number,
      w: number,
      d: number,
      h: number,
      isAccent = false,
      customStroke?: string,
      topFillOpacity = 0.94
    ) => {
      const x1 = x0 + w;
      const y1 = y0 + d;
      const zTop = zBot + h;
      const strokeColor = customStroke || (isAccent ? resolvedAccent : 'currentColor');

      const leftPts = isoPolygonPoints(
        [
          [x0, y1, zTop],
          [x1, y1, zTop],
          [x1, y1, zBot],
          [x0, y1, zBot],
        ],
        cx,
        cy,
        mx,
        my
      );
      const rightPts = isoPolygonPoints(
        [
          [x1, y0, zTop],
          [x1, y1, zTop],
          [x1, y1, zBot],
          [x1, y0, zBot],
        ],
        cx,
        cy,
        mx,
        my
      );
      const topPts = isoPolygonPoints(
        [
          [x0, y0, zTop],
          [x1, y0, zTop],
          [x1, y1, zTop],
          [x0, y1, zTop],
        ],
        cx,
        cy,
        mx,
        my
      );

      return (
        <g
          stroke={strokeColor}
          strokeWidth={isAccent ? '1.35' : '1.15'}
          strokeLinejoin="round"
          strokeLinecap="round"
        >
          <polygon
            points={leftPts}
            fill="var(--hairline-plate, #0b1018)"
            fillOpacity={topFillOpacity}
          />
          <polygon
            points={rightPts}
            fill="var(--hairline-plate, #0f1622)"
            fillOpacity={topFillOpacity}
          />
          <polygon
            points={topPts}
            fill={isAccent ? `${strokeColor}18` : 'var(--hairline-plate, #131c2b)'}
            fillOpacity={topFillOpacity}
          />
        </g>
      );
    };

    const renderCenteredPlate = (
      halfW: number,
      halfD: number,
      zTop: number,
      thickness: number,
      isAccent = false,
      customStroke?: string
    ) => {
      return renderIsoPrism(
        -halfW,
        -halfD,
        zTop - thickness,
        halfW * 2,
        halfD * 2,
        thickness,
        isAccent,
        customStroke
      );
    };

    const isHero = variant === 'hero' || resolvedWidth >= 120;
    const isBadge = variant === 'badge' || resolvedWidth <= 48;

    const dynamicBg =
      unlocked && canonicalType === 'padlock'
        ? 'rgba(16, 185, 129, 0.09)'
        : accentColor || color
          ? `${resolvedAccent}12`
          : colorConfig.bg;

    return (
      <div
        ref={containerRef}
        title={title}
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
        data-testid={`hairline-figure-${type}`}
        data-figure-type={type}
        data-variant={variant}
        style={{
          width: resolvedWidth,
          height: resolvedHeight,
          backgroundColor: dynamicBg,
          boxShadow:
            isPaused && !unlocked
              ? 'none'
              : `0 0 ${isHero ? '24px' : isBadge ? '10px' : '15px'} -3px ${
                  unlocked ? 'rgba(16, 185, 129, 0.42)' : `${resolvedAccent}48`
                }`,
          borderColor: isHovered || unlocked ? `${resolvedAccent}88` : `${resolvedAccent}33`,
        }}
        className={`relative inline-flex flex-col items-center justify-center rounded-xl border border-slate-200/80 dark:border-slate-800/90 transition-all duration-300 select-none shrink-0 text-slate-600 dark:text-slate-300 overflow-hidden ${className}`}
      >
        <svg
          width="100%"
          height="100%"
          viewBox="0 0 160 130"
          preserveAspectRatio="xMidYMid meet"
          fill="none"
          aria-hidden="true"
          className="w-full h-full"
        >
          {/* Base Isométrica 3D de Dupla Camada + Grade de Calibração (Opacidade 0.22) */}
          <g stroke="currentColor" strokeOpacity="0.22" strokeWidth="0.9">
            {[-36, -18, 0, 18, 36].map((g) => {
              const a1 = isoProject(g, -36, -18, cx, cy, mx, my);
              const a2 = isoProject(g, 36, -18, cx, cy, mx, my);
              const b1 = isoProject(-36, g, -18, cx, cy, mx, my);
              const b2 = isoProject(36, g, -18, cx, cy, mx, my);
              return (
                <React.Fragment key={g}>
                  <line x1={a1.sx} y1={a1.sy} x2={a2.sx} y2={a2.sy} strokeDasharray="2 2.5" />
                  <line x1={b1.sx} y1={b1.sy} x2={b2.sx} y2={b2.sy} strokeDasharray="2 2.5" />
                </React.Fragment>
              );
            })}
            <path
              d={isoRoundedPlatePath(40, 40, -18, cx, cy, mx, my)}
              stroke={resolvedAccent}
              strokeOpacity={0.35 + wave * 0.25}
              fill="var(--hairline-plate, #090d14)"
              fillOpacity="0.55"
            />
            <path
              d={isoRoundedPlatePath(34, 34, -14, cx, cy, mx, my)}
              stroke="currentColor"
              strokeOpacity="0.28"
              strokeDasharray="3 2"
            />
          </g>

          {/* Ponto focal pulsante na base isométrica */}
          {(() => {
            const baseCenter = isoProject(0, 0, -14, cx, cy, mx, my);
            return (
              <circle
                cx={baseCenter.sx}
                cy={baseCenter.sy}
                r={(2.2 + wave * 1.8).toFixed(2)}
                fill={resolvedAccent}
                fillOpacity={0.35 + wave * 0.45}
              />
            );
          })()}

          {/* 1. LOCKERS: Matriz isométrica 2x2 de gavetas 3D onde a gaveta superior direita desliza no eixo +X */}
          {canonicalType === 'lockers' && (() => {
            const slideX = 3 + wave * 15;
            return (
              <g>
                {/* Chassi traseiro do gabinete modular */}
                {renderIsoPrism(-24, -22, -12, 48, 44, 38, false)}
                {/* Gaveta Inferior Esquerda */}
                {renderIsoPrism(-20, 2, -9, 19, 18, 13, false)}
                {/* Gaveta Inferior Direita */}
                {renderIsoPrism(2, 2, -9, 19, 18, 13, false)}
                {/* Gaveta Superior Esquerda */}
                {renderIsoPrism(-20, -19, 7, 19, 18, 13, false)}
                {/* Gaveta Superior Direita (Deslizante no eixo +X isométrico com registros brilhantes) */}
                {renderIsoPrism(2 + slideX, -19, 7, 19, 18, 13, true, resolvedAccent)}
                {[0, 1, 2].map((i) => {
                  const recPt = isoProject(8 + slideX + i * 4, -10, 21 + wave * 2, cx, cy, mx, my);
                  return (
                    <circle
                      key={i}
                      cx={recPt.sx}
                      cy={recPt.sy}
                      r="1.9"
                      fill={resolvedAccent}
                    />
                  );
                })}
              </g>
            );
          })()}

          {/* 2. VAULT: Cofre Criptográfico 3D com porta espessa em camadas, barras retráteis e volante de 6 raios */}
          {canonicalType === 'vault' && (() => {
            const doorOut = wave * 8;
            const wheelDeg = sweep * 120;
            const boltExtend = (1 - wave * 0.7) * 6;
            const wheelCenter = isoProject(18 + doorOut, 0, 8, cx, cy, mx, my);

            return (
              <g>
                {/* Corpo blindado principal 3D */}
                {renderIsoPrism(-24, -24, -12, 42, 48, 42, false)}
                {/* Moldura interna do cofre */}
                {renderIsoPrism(-16, -18, -7, 28, 36, 32, false, resolvedAccent)}
                {/* Porta espessa projetada à frente no eixo +X */}
                {renderIsoPrism(12 + doorOut, -18, -8, 8, 36, 34, true, resolvedAccent)}
                {/* Barras de travamento laterais retráteis */}
                {[-8, 6, 18].map((zOff, idx) => {
                  const b1 = isoProject(16 + doorOut, -18, zOff, cx, cy, mx, my);
                  const b2 = isoProject(16 + doorOut, -18 - boltExtend, zOff, cx, cy, mx, my);
                  const b3 = isoProject(16 + doorOut, 18, zOff, cx, cy, mx, my);
                  const b4 = isoProject(16 + doorOut, 18 + boltExtend, zOff, cx, cy, mx, my);
                  return (
                    <g key={idx} stroke={resolvedAccent} strokeWidth="1.8" strokeLinecap="round">
                      <line x1={b1.sx} y1={b1.sy} x2={b2.sx} y2={b2.sy} />
                      <line x1={b3.sx} y1={b3.sy} x2={b4.sx} y2={b4.sy} />
                    </g>
                  );
                })}
                {/* Volante central de 6 raios */}
                <g transform={`translate(${wheelCenter.sx}, ${wheelCenter.sy})`}>
                  <ellipse
                    cx="0"
                    cy="0"
                    rx="11"
                    ry="13"
                    fill="var(--hairline-plate, #0b1018)"
                    stroke={resolvedAccent}
                    strokeWidth="1.5"
                  />
                  <g transform={`rotate(${wheelDeg.toFixed(1)})`} stroke={resolvedAccent} strokeWidth="1.3">
                    {[0, 60, 120].map((ang) => (
                      <line
                        key={ang}
                        x1="0"
                        y1="-10"
                        x2="0"
                        y2="10"
                        transform={`rotate(${ang})`}
                      />
                    ))}
                  </g>
                  <circle cx="0" cy="0" r="3" fill={resolvedAccent} />
                </g>
              </g>
            );
          })()}

          {/* 3. PADLOCK: Cadeado Criptográfico 3D com corpo laminado, colares de encaixe, haste tubular 3D projetada no topo e tambor rotativo isométrico */}
          {canonicalType === 'padlock' && (() => {
            const clampedTyping = Math.max(0, Math.min(1, typingProgress));
            const shackleLift = unlocked ? 13 : wave * 9.5 + clampedTyping * 3.5;
            const shackleOpenAngle = unlocked ? 0.58 : wave * 0.34;
            const keyRotation = clampedTyping * 140 + sweep * 90;

            // Posições dos soquetes na face superior do corpo (zTop = 15)
            const zBodyTop = 15;
            const leftSocket = isoProject(-10, 0, zBodyTop, cx, cy, mx, my);
            const rightSocket = isoProject(10, 0, zBodyTop, cx, cy, mx, my);

            // Cálculo 3D real da haste (shackle) com rotação em torno do poste esquerdo (-10, 0)
            const projectShacklePoint = (localX: number, localZ: number, yOffset = 0) => {
              const dx = localX - -10;
              const rotX = -10 + dx * Math.cos(shackleOpenAngle);
              const rotY = yOffset - dx * Math.sin(shackleOpenAngle);
              return isoProject(rotX, rotY, localZ + shackleLift, cx, cy, mx, my);
            };

            // Gera pontos suaves do arco 3D externo (raio = 10) e interno (raio = 6.6)
            const buildArchPolyline = (radius: number, zLegBottomRight: number, yOffset = 0) => {
              const pts: string[] = [];
              const pLeftBot = projectShacklePoint(-10, zBodyTop - shackleLift * 0.35, yOffset);
              pts.push(`${pLeftBot.sx},${pLeftBot.sy}`);
              const steps = 14;
              for (let i = 0; i <= steps; i++) {
                const theta = Math.PI - (i / steps) * Math.PI; // de -radius a +radius
                const lx = radius * Math.cos(theta);
                const lz = 26 + radius * Math.sin(theta) * 0.92;
                const pt = projectShacklePoint(lx, lz, yOffset);
                pts.push(`${pt.sx},${pt.sy}`);
              }
              const pRightBot = projectShacklePoint(radius, zLegBottomRight, yOffset);
              pts.push(`${pRightBot.sx},${pRightBot.sy}`);
              return pts.join(' ');
            };

            const outerBackArch = buildArchPolyline(10, 17, -1.8);
            const outerFrontArch = buildArchPolyline(10, 17, 1.8);
            const innerArch = buildArchPolyline(6.5, 19, 0);

            // Feixe de varredura holográfico ao redor do cadeado
            const scanZ = -8 + sweep * 24;
            const dialCenter = isoProject(-4, 15, 2.5, cx, cy, mx, my);
            const statusLedPt = isoProject(11, 15, 10.5, cx, cy, mx, my);

            return (
              <g>
                {/* Aura holográfica na base quando desbloqueado ou digitando */}
                {(unlocked || clampedTyping > 0.05) && (
                  <path
                    d={isoRoundedPlatePath(29, 22, -11, cx, cy, mx, my)}
                    stroke={unlocked ? '#10b981' : resolvedAccent}
                    strokeOpacity={0.5 + wave * 0.35}
                    strokeWidth="1.3"
                    strokeDasharray="4 2.5"
                    fill={unlocked ? 'rgba(16, 185, 129, 0.08)' : `${resolvedAccent}10`}
                  />
                )}

                {/* 1º na Ordem do Pintor: Corpo 3D Isométrico com 3 Placas Blindadas Laminadas */}
                {renderCenteredPlate(21, 15, -3, 8, false)}
                {renderCenteredPlate(21, 15, 6, 8, true, resolvedAccent)}
                {renderCenteredPlate(21, 15, zBodyTop, 8, false, resolvedAccent)}

                {/* Feixe laser perimetral de verificação criptográfica */}
                <path
                  d={isoRoundedPlatePath(22.5, 16.5, scanZ, cx, cy, mx, my)}
                  stroke={resolvedAccent}
                  strokeOpacity={0.28 + wave * 0.45}
                  strokeWidth="1.1"
                  strokeDasharray="3 2"
                />

                {/* 2º na Ordem do Pintor: Colares/Soquetes Isométricos na Face Superior (z = 15) */}
                {[leftSocket, rightSocket].map((sock, idx) => (
                  <g key={idx}>
                    <ellipse
                      cx={sock.sx}
                      cy={sock.sy}
                      rx="5.2"
                      ry="3.1"
                      fill="var(--hairline-plate, #070b11)"
                      stroke={resolvedAccent}
                      strokeWidth="1.3"
                    />
                    <ellipse
                      cx={sock.sx}
                      cy={sock.sy}
                      rx="2.6"
                      ry="1.5"
                      fill={resolvedAccent}
                      fillOpacity={idx === 1 && (shackleLift > 3 || unlocked) ? '0.25' : '0.6'}
                    />
                  </g>
                ))}

                {/* 3º na Ordem do Pintor: Haste 3D (Shackle) renderizada SOBRE o topo do corpo (sem oclusão!) */}
                <g strokeLinecap="round" strokeLinejoin="round">
                  {/* Face traseira da haste tubular 3D */}
                  <polyline
                    points={outerBackArch}
                    fill="none"
                    stroke="currentColor"
                    strokeOpacity="0.55"
                    strokeWidth="2.2"
                  />
                  {/* Arco interno da haste */}
                  <polyline
                    points={innerArch}
                    fill="none"
                    stroke="currentColor"
                    strokeOpacity="0.82"
                    strokeWidth="1.5"
                  />
                  {/* Arco principal frontal iluminado em neon */}
                  <polyline
                    points={outerFrontArch}
                    fill="none"
                    stroke={resolvedAccent}
                    strokeWidth="2.8"
                  />
                </g>

                {/* 4º na Ordem do Pintor: Cilindro Criptográfico Rotativo na Face Frontal-Esquerda Isométrica */}
                <g transform={`translate(${dialCenter.sx}, ${dialCenter.sy}) skewY(26)`}>
                  <circle
                    cx="0"
                    cy="0"
                    r="7.2"
                    fill="var(--hairline-plate, #080c14)"
                    stroke={resolvedAccent}
                    strokeWidth="1.45"
                  />
                  <circle
                    cx="0"
                    cy="0"
                    r="5.1"
                    fill="none"
                    stroke="currentColor"
                    strokeOpacity="0.45"
                    strokeWidth="0.9"
                    strokeDasharray="1.8 1.8"
                  />
                  <g transform={`rotate(${keyRotation.toFixed(1)})`}>
                    <line
                      x1="0"
                      y1="-3.6"
                      x2="0"
                      y2="3.6"
                      stroke={resolvedAccent}
                      strokeWidth="1.85"
                      strokeLinecap="round"
                    />
                    <circle cx="0" cy="-1.6" r="1.4" fill={resolvedAccent} />
                  </g>
                </g>

                {/* Indicador LED de Status KMS na face frontal */}
                <circle
                  cx={statusLedPt.sx}
                  cy={statusLedPt.sy}
                  r="2.1"
                  fill={unlocked ? '#10b981' : resolvedAccent}
                />
              </g>
            );
          })()}

          {/* 4. ROUTER: Chassi isométrico com LEDs frontais, 3 antenas verticais e ondas elípticas +Z */}
          {canonicalType === 'router' && (() => {
            const antPositions: Array<[number, number]> = [
              [-16, -14],
              [0, -16],
              [16, -14],
            ];
            const tipCenter = isoProject(0, -16, 30, cx, cy, mx, my);

            return (
              <g>
                {/* Barramentos de dados no piso isométrico */}
                {[
                  [-32, 22],
                  [32, 22],
                  [-32, -22],
                  [32, -22],
                ].map(([nx, ny], idx) => {
                  const hub = isoProject(0, 0, -4, cx, cy, mx, my);
                  const node = isoProject(nx, ny, -12, cx, cy, mx, my);
                  const px = hub.sx + (node.sx - hub.sx) * sweep;
                  const py = hub.sy + (node.sy - hub.sy) * sweep;
                  return (
                    <g key={idx}>
                      <line
                        x1={hub.sx}
                        y1={hub.sy}
                        x2={node.sx}
                        y2={node.sy}
                        stroke="currentColor"
                        strokeOpacity="0.45"
                        strokeWidth="1.15"
                      />
                      <circle
                        cx={node.sx}
                        cy={node.sy}
                        r="3.2"
                        fill="var(--hairline-plate, #0b1018)"
                        stroke={resolvedAccent}
                        strokeWidth="1.2"
                      />
                      <circle cx={px} cy={py} r="2.2" fill={resolvedAccent} />
                    </g>
                  );
                })}

                {/* Chassi isométrico do Roteador */}
                {renderCenteredPlate(24, 18, 2, 10, true, resolvedAccent)}

                {/* LEDs de porta frontais */}
                {[-14, -7, 0, 7, 14].map((lx, i) => {
                  const ledPt = isoProject(lx, 18, -3, cx, cy, mx, my);
                  const activeLed = (i + Math.round(sweep * 5)) % 2 === 0;
                  return (
                    <circle
                      key={i}
                      cx={ledPt.sx}
                      cy={ledPt.sy}
                      r="1.6"
                      fill={activeLed ? resolvedAccent : 'currentColor'}
                    />
                  );
                })}

                {/* 3 Antenas verticais */}
                {antPositions.map(([ax, ay], i) => {
                  const base = isoProject(ax, ay, 2, cx, cy, mx, my);
                  const top = isoProject(ax, ay, 28 + (i === 1 ? 4 : 0), cx, cy, mx, my);
                  return (
                    <g key={i}>
                      <line
                        x1={base.sx}
                        y1={base.sy}
                        x2={top.sx}
                        y2={top.sy}
                        stroke="currentColor"
                        strokeWidth="1.6"
                        strokeLinecap="round"
                      />
                      <circle cx={top.sx} cy={top.sy} r="2" fill={resolvedAccent} />
                    </g>
                  );
                })}

                {/* Ondas elípticas concêntricas no eixo +Z */}
                {[1, 2].map((ring) => {
                  const rx = 10 + ring * 9 + wave * 8;
                  const ry = 5 + ring * 4 + wave * 3.5;
                  return (
                    <ellipse
                      key={ring}
                      cx={tipCenter.sx}
                      cy={tipCenter.sy - wave * 4}
                      rx={rx}
                      ry={ry}
                      stroke={resolvedAccent}
                      strokeOpacity={Math.max(0.18, 0.85 - ring * 0.25 - wave * 0.3)}
                      strokeWidth="1.2"
                      strokeDasharray="3 2"
                    />
                  );
                })}
              </g>
            );
          })()}

          {/* 5. EXPLODED: 3 Placas de Circuito Isométricas (UI Layer, Domain Engine, Crypto Storage) */}
          {canonicalType === 'exploded' && (() => {
            const spread = 4 + wave * 12;
            const zLow = -6 - spread * 0.7;
            const zMid = 8;
            const zHigh = 22 + spread;

            return (
              <g>
                {/* Placa 1: Crypto Storage */}
                {renderCenteredPlate(25, 25, zLow, 5, false)}
                {/* Placa 2: Domain Engine */}
                {renderCenteredPlate(25, 25, zMid, 5, true, resolvedAccent)}
                {/* Placa 3: UI Layer */}
                {renderCenteredPlate(25, 25, zHigh, 5, false, resolvedAccent)}

                {/* Trilhas verticais pontilhadas com pulsos luminosos nos 4 cantos */}
                {[
                  [-16, -16],
                  [16, -16],
                  [16, 16],
                  [-16, 16],
                ].map(([px, py], idx) => {
                  const bot = isoProject(px, py, zLow, cx, cy, mx, my);
                  const top = isoProject(px, py, zHigh, cx, cy, mx, my);
                  const pulseZ = zLow + (zHigh - zLow) * sweep;
                  const pulsePt = isoProject(px, py, pulseZ, cx, cy, mx, my);
                  return (
                    <g key={idx}>
                      <line
                        x1={bot.sx}
                        y1={bot.sy}
                        x2={top.sx}
                        y2={top.sy}
                        stroke={resolvedAccent}
                        strokeOpacity="0.65"
                        strokeWidth="1.15"
                        strokeDasharray="2 2.5"
                      />
                      <circle cx={pulsePt.sx} cy={pulsePt.sy} r="2.1" fill={resolvedAccent} />
                    </g>
                  );
                })}
              </g>
            );
          })()}

          {/* 6. TURNTABLE: Plataforma Giratória de Hardware 3D com plinto chanfrado, prato e braço */}
          {canonicalType === 'turntable' && (() => {
            const platterCenter = isoProject(-2, 2, 5, cx, cy, mx, my);
            const armPivot = isoProject(20, -16, 9, cx, cy, mx, my);
            const armHead = isoProject(4 + (wave - 0.5) * 8, 6 + wave * 5, 8, cx, cy, mx, my);
            const spinDeg = sweep * 180;

            return (
              <g>
                {/* Plinto isométrico chanfrado */}
                {renderCenteredPlate(28, 24, 3, 9, false)}
                {/* Prato estroboscópico em perspectiva isométrica */}
                <g transform={`translate(${platterCenter.sx}, ${platterCenter.sy})`}>
                  <ellipse
                    cx="0"
                    cy="0"
                    rx="24"
                    ry="14"
                    fill="var(--hairline-plate, #0b1018)"
                    stroke="currentColor"
                    strokeWidth="1.3"
                  />
                  <ellipse
                    cx="0"
                    cy="-2"
                    rx="21"
                    ry="12"
                    fill="var(--hairline-plate, #101826)"
                    stroke={resolvedAccent}
                    strokeWidth="1.35"
                    strokeDasharray="5 3"
                  />
                  {/* Wafer/SoC central rotativo */}
                  <g transform={`scale(1, 0.58) rotate(${spinDeg.toFixed(1)})`}>
                    <rect
                      x="-8"
                      y="-8"
                      width="16"
                      height="16"
                      rx="2"
                      fill={`${resolvedAccent}22`}
                      stroke={resolvedAccent}
                      strokeWidth="1.5"
                    />
                    <line x1="-12" y1="0" x2="12" y2="0" stroke={resolvedAccent} strokeWidth="1.2" />
                    <line x1="0" y1="-12" x2="0" y2="12" stroke={resolvedAccent} strokeWidth="1.2" />
                  </g>
                </g>
                {/* Braço de leitura (tonearm) pivotante */}
                <circle
                  cx={armPivot.sx}
                  cy={armPivot.sy}
                  r="4"
                  fill="var(--hairline-plate, #0b1018)"
                  stroke={resolvedAccent}
                  strokeWidth="1.4"
                />
                <line
                  x1={armPivot.sx}
                  y1={armPivot.sy}
                  x2={armHead.sx}
                  y2={armHead.sy}
                  stroke={resolvedAccent}
                  strokeWidth="1.8"
                  strokeLinecap="round"
                />
                <circle cx={armHead.sx} cy={armHead.sy} r="2.5" fill={resolvedAccent} />
              </g>
            );
          })()}

          {/* 7. PHOSPHOR: Osciloscópio de Fósforo 3D com moldura CRT isométrica e onda senoidal dupla */}
          {canonicalType === 'phosphor' && (() => {
            const wavePts1: string[] = [];
            const wavePts2: string[] = [];
            for (let i = 0; i <= 16; i++) {
              const t = i / 16;
              const x = -22 + t * 44;
              const amp1 = Math.sin(t * Math.PI * 2 + sweep * Math.PI * 2) * (7 + wave * 5);
              const amp2 = Math.cos(t * Math.PI * 2 - sweep * Math.PI * 2) * (4 + wave * 3);
              const p1 = isoProject(x, 8, 12 + amp1, cx, cy, mx, my);
              const p2 = isoProject(x, 8, 12 + amp2, cx, cy, mx, my);
              wavePts1.push(`${p1.sx},${p1.sy}`);
              wavePts2.push(`${p2.sx},${p2.sy}`);
            }
            const scanX = -22 + sweep * 44;
            const scanTop = isoProject(scanX, 8, 25, cx, cy, mx, my);
            const scanBot = isoProject(scanX, 8, -1, cx, cy, mx, my);

            return (
              <g>
                {/* Gabinete CRT isométrico 3D */}
                {renderIsoPrism(-26, -16, -8, 52, 26, 38, false)}
                {/* Moldura frontal de fósforo */}
                {renderIsoPrism(-24, 8, -4, 48, 4, 32, true, resolvedAccent)}
                {/* Onda senoidal secundária */}
                <polyline
                  points={wavePts2.join(' ')}
                  fill="none"
                  stroke="currentColor"
                  strokeOpacity="0.55"
                  strokeWidth="1.2"
                />
                {/* Onda senoidal principal de alta definição */}
                <polyline
                  points={wavePts1.join(' ')}
                  fill="none"
                  stroke={resolvedAccent}
                  strokeWidth="1.85"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                {/* Feixe varredor vertical */}
                <line
                  x1={scanTop.sx}
                  y1={scanTop.sy}
                  x2={scanBot.sx}
                  y2={scanBot.sy}
                  stroke={resolvedAccent}
                  strokeOpacity="0.75"
                  strokeWidth="1.2"
                  strokeDasharray="2 2"
                />
              </g>
            );
          })()}

          {/* 8. LOUPE: Lupa Óptica de Mercado 3D sobre matriz de documentos isométricos */}
          {canonicalType === 'loupe' && (() => {
            const offsetX = (wave - 0.5) * 16;
            const offsetY = Math.sin(wave * Math.PI * 2) * 7;
            const lensCenter = isoProject(offsetX, offsetY, 18, cx, cy, mx, my);
            const handleEnd = isoProject(offsetX + 18, offsetY + 18, 12, cx, cy, mx, my);

            return (
              <g>
                {/* Matriz de documentos isométricos na base */}
                {renderIsoPrism(-24, -20, -8, 20, 16, 4, false)}
                {renderIsoPrism(4, -20, -8, 20, 16, 4, false)}
                {renderIsoPrism(-24, 2, -8, 20, 16, 4, false)}
                {renderIsoPrism(4, 2, -8, 20, 16, 4, true, resolvedAccent)}

                {/* Feixe cônico de inspeção óptica */}
                <ellipse
                  cx={lensCenter.sx}
                  cy={lensCenter.sy + 14}
                  rx="14"
                  ry="8"
                  fill={`${resolvedAccent}18`}
                  stroke={resolvedAccent}
                  strokeOpacity="0.4"
                  strokeDasharray="2 2"
                />

                {/* Aro cilíndrico 3D suspenso da Lupa */}
                <ellipse
                  cx={lensCenter.sx}
                  cy={lensCenter.sy + 3}
                  rx="16"
                  ry="10"
                  fill="var(--hairline-plate, #0b1018)"
                  fillOpacity="0.82"
                  stroke="currentColor"
                  strokeWidth="1.3"
                />
                <ellipse
                  cx={lensCenter.sx}
                  cy={lensCenter.sy}
                  rx="16"
                  ry="10"
                  fill={`${resolvedAccent}22`}
                  stroke={resolvedAccent}
                  strokeWidth="1.8"
                />
                {/* Nós ampliados dentro da lente */}
                <circle cx={lensCenter.sx - 4} cy={lensCenter.sy - 1} r="2.2" fill={resolvedAccent} />
                <circle cx={lensCenter.sx + 5} cy={lensCenter.sy + 2} r="1.8" fill="currentColor" />
                <line
                  x1={lensCenter.sx - 4}
                  y1={lensCenter.sy - 1}
                  x2={lensCenter.sx + 5}
                  y2={lensCenter.sy + 2}
                  stroke={resolvedAccent}
                  strokeWidth="1.2"
                />
                {/* Cabo isométrico */}
                <line
                  x1={lensCenter.sx + 11}
                  y1={lensCenter.sy + 7}
                  x2={handleEnd.sx}
                  y2={handleEnd.sy}
                  stroke={resolvedAccent}
                  strokeWidth="3"
                  strokeLinecap="round"
                />
              </g>
            );
          })()}

          {/* 9. SIEVE: Funil / Peneira SAST 3D com 3 malhas empilhadas e retenção de vulnerabilidades */}
          {canonicalType === 'sieve' && (() => {
            const zTopMesh = 22;
            const zMidMesh = 8;
            const zBotMesh = -6;
            const cleanZ = 28 - sweep * 38;

            return (
              <g>
                {/* 3 Malhas isométricas empilhadas */}
                {renderCenteredPlate(24, 24, zBotMesh, 3, false, '#10b981')}
                {renderCenteredPlate(24, 24, zMidMesh, 3, false)}
                {renderCenteredPlate(24, 24, zTopMesh, 3, true, resolvedAccent)}

                {/* Vulnerabilidades críticas retidas na malha superior (pulsando em âmbar/vermelho) */}
                {[
                  [-8, -6],
                  [7, 4],
                  [-4, 9],
                ].map(([vx, vy], i) => {
                  const pt = isoProject(vx, vy, zTopMesh + 2 + wave * 2, cx, cy, mx, my);
                  return (
                    <circle
                      key={`vuln-${i}`}
                      cx={pt.sx}
                      cy={pt.sy}
                      r={(2.6 + wave * 0.9).toFixed(2)}
                      fill="#f43f5e"
                      stroke="#fda4af"
                      strokeWidth="1"
                    />
                  );
                })}

                {/* Partículas de código limpo atravessando em verde/ciano no eixo -Z */}
                {[
                  [-10, 6],
                  [0, -4],
                  [10, -8],
                ].map(([cxOff, cyOff], i) => {
                  const zPos = ((cleanZ - i * 8 + 40) % 38) - 10;
                  const pt = isoProject(cxOff, cyOff, zPos, cx, cy, mx, my);
                  return (
                    <circle
                      key={`clean-${i}`}
                      cx={pt.sx}
                      cy={pt.sy}
                      r="2.2"
                      fill="#10b981"
                    />
                  );
                })}
              </g>
            );
          })()}

          {/* 10. TERRAIN: Topografia 3D de Maturidade (Malha wireframe isométrica 7x7) */}
          {canonicalType === 'terrain' && (() => {
            const coords = [-24, -16, -8, 0, 8, 16, 24];
            const phase = sweep * Math.PI * 2;
            const heightAt = (x: number, y: number) =>
              Math.sin(x * 0.11 + phase) * Math.cos(y * 0.11 + phase * 0.7) * (8 + wave * 6) + 8;

            return (
              <g strokeLinecap="round" strokeLinejoin="round">
                {/* Plano de corte de benchmark */}
                <path
                  d={isoRoundedPlatePath(28, 28, 4, cx, cy, mx, my)}
                  stroke={resolvedAccent}
                  strokeOpacity="0.35"
                  strokeDasharray="3 2"
                />
                {/* Linhas nos eixos X e Y da malha 7x7 */}
                {coords.map((yVal, rIdx) => {
                  const rowPts = coords
                    .map((xVal) => {
                      const p = isoProject(xVal, yVal, heightAt(xVal, yVal), cx, cy, mx, my);
                      return `${p.sx},${p.sy}`;
                    })
                    .join(' ');
                  return (
                    <polyline
                      key={`row-${rIdx}`}
                      points={rowPts}
                      fill="none"
                      stroke={rIdx === 3 ? resolvedAccent : 'currentColor'}
                      strokeOpacity={rIdx === 3 ? 0.95 : 0.55}
                      strokeWidth={rIdx === 3 ? '1.6' : '1.05'}
                    />
                  );
                })}
                {coords.map((xVal, cIdx) => {
                  const colPts = coords
                    .map((yVal) => {
                      const p = isoProject(xVal, yVal, heightAt(xVal, yVal), cx, cy, mx, my);
                      return `${p.sx},${p.sy}`;
                    })
                    .join(' ');
                  return (
                    <polyline
                      key={`col-${cIdx}`}
                      points={colPts}
                      fill="none"
                      stroke={cIdx === 3 ? resolvedAccent : 'currentColor'}
                      strokeOpacity={cIdx === 3 ? 0.95 : 0.45}
                      strokeWidth={cIdx === 3 ? '1.5' : '0.95'}
                    />
                  );
                })}
              </g>
            );
          })()}

          {/* 11. STACK: Pilha de Governança & SBOM 3D (4 blocos isométricos + feixe SPDX) */}
          {canonicalType === 'stack' && (() => {
            const lift = wave * 4.5;
            const laserZ = -8 + sweep * 38;
            const beamLeft = isoProject(-28, 24, laserZ, cx, cy, mx, my);
            const beamRight = isoProject(28, -24, laserZ, cx, cy, mx, my);

            return (
              <g>
                {renderCenteredPlate(26, 24, -6, 6, false)}
                {renderCenteredPlate(23, 21, 3 + lift * 0.6, 6, false)}
                {renderCenteredPlate(20, 18, 12 + lift * 1.3, 6, true, resolvedAccent)}
                {renderCenteredPlate(16, 15, 21 + lift * 2.1, 6, true, resolvedAccent)}
                {/* Feixe de verificação lateral de licenças SPDX */}
                <line
                  x1={beamLeft.sx}
                  y1={beamLeft.sy}
                  x2={beamRight.sx}
                  y2={beamRight.sy}
                  stroke={resolvedAccent}
                  strokeWidth="1.6"
                  strokeDasharray="4 2"
                />
                <circle cx={beamLeft.sx} cy={beamLeft.sy} r="2.2" fill={resolvedAccent} />
                <circle cx={beamRight.sx} cy={beamRight.sy} r="2.2" fill={resolvedAccent} />
              </g>
            );
          })()}

          {/* 12. TERMINAL: Console DevSecOps 3D inclinado com linhas de código vetoriais escaneadas */}
          {canonicalType === 'terminal' && (() => {
            const activeLine = Math.floor(sweep * 5);
            return (
              <g>
                {/* Pedestal e painel isométrico inclinado */}
                {renderCenteredPlate(18, 16, -8, 5, false)}
                {renderIsoPrism(-26, -10, -4, 52, 8, 36, true, resolvedAccent)}
                {/* Linhas de código vetoriais proyectadas no painel */}
                {[0, 1, 2, 3, 4].map((lineIdx) => {
                  const zLine = 24 - lineIdx * 5.5;
                  const len = [32, 24, 36, 20, 28][lineIdx];
                  const pStart = isoProject(-18, -2, zLine, cx, cy, mx, my);
                  const pEnd = isoProject(-18 + len, -2, zLine, cx, cy, mx, my);
                  const isCurrent = lineIdx === activeLine;
                  return (
                    <line
                      key={lineIdx}
                      x1={pStart.sx}
                      y1={pStart.sy}
                      x2={pEnd.sx}
                      y2={pEnd.sy}
                      stroke={isCurrent ? resolvedAccent : 'currentColor'}
                      strokeOpacity={isCurrent ? 1 : 0.65}
                      strokeWidth={isCurrent ? '2.1' : '1.3'}
                      strokeLinecap="round"
                    />
                  );
                })}
              </g>
            );
          })()}
        </svg>

        {subtitle && isHero && (
          <div className="absolute bottom-1.5 inset-x-2 text-center text-[10px] font-mono text-slate-400 truncate pointer-events-none">
            {subtitle}
          </div>
        )}
      </div>
    );
  }
);
export default HairlineAnimatedFigure;
