import React, { useId } from 'react';

export interface WinHoodLogoProps {
  /** Dimensão do ícone em pixels (34 para .brand-mark da Sidebar, 48 para headers, 160 para showcase) */
  size?: number;
  /** Forçar variante de tema ou adaptar automaticamente ao tema ativo da aplicação */
  variant?: 'auto' | 'dark' | 'light';
  /** Classes utilitárias adicionais (ex.: "brand-mark shrink-0") */
  className?: string;
  /** Título acessível do SVG */
  title?: string;
}

/**
 * Componente Oficial da Identidade Visual "01. WinHood Pulse"
 * - Geometria vetorial exata (`viewBox="0 0 160 160"`):
 *   1. Container Squircle Adaptativo (`rx="34"`): `#0c1017` no Dark Mode e `#ffffff` no Light Mode.
 *   2. Arco de Suporte Segmentado Inferior (Gradiente Wini IA: Roxo `#a855f7` -> Índigo `#6366f1` -> Azul `#3b82f6`).
 *   3. Duplo Chevron "W" Superior (Gradiente SLA Turquesa: `#31d6c4` -> `#10b981`) encaixando na cavidade do arco.
 */
export const WinHoodLogo: React.FC<WinHoodLogoProps> = ({
  size = 34,
  variant = 'auto',
  className = '',
  title = 'WinHood Pulse — Identidade Visual Oficial',
}) => {
  const rawId = useId().replace(/:/g, '');
  const arcGradId = `wh-wini-arc-${rawId}`;
  const wGradId = `wh-sla-w-${rawId}`;
  const glowGradId = `wh-glow-${rawId}`;

  const isForcedLight = variant === 'light';
  const isForcedDark = variant === 'dark';

  const rectFillClass = isForcedLight
    ? 'fill-white stroke-slate-200'
    : isForcedDark
      ? 'fill-[#0c1017] stroke-[#1e293b]'
      : 'fill-white stroke-slate-200 dark:fill-[#0c1017] dark:stroke-[#1e293b]';

  const tickStrokeClass = isForcedLight
    ? 'stroke-white'
    : isForcedDark
      ? 'stroke-[#0c1017]'
      : 'stroke-white dark:stroke-[#0c1017]';

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 160 160"
      width={size}
      height={size}
      fill="none"
      role="img"
      aria-label={title}
      className={`select-none ${className}`.trim()}
    >
      <title>{title}</title>
      <defs>
        <linearGradient
          id={arcGradId}
          x1="24"
          y1="84"
          x2="136"
          y2="140"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor="#a855f7" />
          <stop offset="50%" stopColor="#6366f1" />
          <stop offset="100%" stopColor="#3b82f6" />
        </linearGradient>
        <linearGradient
          id={wGradId}
          x1="38"
          y1="36"
          x2="122"
          y2="98"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor="#31d6c4" />
          <stop offset="60%" stopColor="#2dd4bf" />
          <stop offset="100%" stopColor="#10b981" />
        </linearGradient>
        <radialGradient id={glowGradId} cx="50%" cy="52%" r="48%">
          <stop offset="0%" stopColor="#31d6c4" stopOpacity="0.16" />
          <stop offset="60%" stopColor="#6366f1" stopOpacity="0.08" />
          <stop offset="100%" stopColor="#0c1017" stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* 1. Container Squircle Adaptativo */}
      <rect
        x="4"
        y="4"
        width="152"
        height="152"
        rx="34"
        strokeWidth="2.5"
        className={rectFillClass}
      />
      <circle cx="80" cy="82" r="64" fill={`url(#${glowGradId})`} />

      {/* 2. Arco de Suporte Segmentado Inferior (Wini IA: #a855f7 -> #6366f1 -> #3b82f6) */}
      <g stroke={`url(#${arcGradId})`} fill="none" strokeLinecap="round">
        <path d="M 26 84 A 54 54 0 0 0 134 84" strokeWidth="5.5" />
        <path
          d="M 35 84 A 45 45 0 0 0 125 84"
          strokeWidth="4.5"
          strokeOpacity="0.92"
        />
        <path
          d="M 44 84 A 36 36 0 0 0 116 84"
          strokeWidth="3.5"
          strokeOpacity="0.82"
        />
        <line x1="25" y1="84" x2="45" y2="84" strokeWidth="4.5" />
        <line x1="115" y1="84" x2="135" y2="84" strokeWidth="4.5" />
      </g>

      {/* Divisórias Radiais de Segmentação do Arco */}
      <g className={tickStrokeClass} strokeWidth="3" strokeLinecap="butt">
        <line x1="51" y1="101" x2="32" y2="112" />
        <line x1="68" y1="117" x2="60" y2="137" />
        <line x1="92" y1="117" x2="100" y2="137" />
        <line x1="109" y1="101" x2="128" y2="112" />
      </g>

      {/* 3. Duplo Chevron "W" Superior (SLA Turquesa: #31d6c4 -> #10b981) */}
      <g
        stroke={`url(#${wGradId})`}
        fill="none"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M 38 38 L 62 96 L 80 54 L 98 96 L 122 38" strokeWidth="7.5" />
        <path d="M 48 38 L 62 73 L 80 36 L 98 73 L 112 38" strokeWidth="5" />
      </g>
    </svg>
  );
};
