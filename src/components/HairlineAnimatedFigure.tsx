import React, { useEffect, useRef, useState } from 'react';

export type HairlineFigureType =
  | 'lockers'
  | 'vault'
  | 'padlock'
  | 'router'
  | 'layers'
  | 'gauge';

interface HairlineAnimatedFigureProps {
  type: HairlineFigureType;
  size?: number;
  className?: string;
  color?: string;
  cycleDurationMs?: number;
  pauseDurationMs?: number;
  title?: string;
}

const CATEGORY_DEFAULT_COLORS: Record<HairlineFigureType, { stroke: string; glow: string; bg: string }> = {
  lockers: {
    stroke: '#3b82f6', // Azul Índigo / Storage & DB
    glow: 'rgba(59, 130, 246, 0.25)',
    bg: 'rgba(59, 130, 246, 0.08)',
  },
  vault: {
    stroke: '#10b981', // Esmeralda / Segurança Geral & DevSecOps
    glow: 'rgba(16, 185, 129, 0.25)',
    bg: 'rgba(16, 185, 129, 0.08)',
  },
  padlock: {
    stroke: '#f59e0b', // Âmbar / IAM, Senhas & Segredos
    glow: 'rgba(245, 158, 11, 0.25)',
    bg: 'rgba(245, 158, 11, 0.08)',
  },
  router: {
    stroke: '#06b6d4', // Ciano / Rede, APIs & TLS
    glow: 'rgba(6, 182, 212, 0.25)',
    bg: 'rgba(6, 182, 212, 0.08)',
  },
  layers: {
    stroke: '#8b5cf6', // Púrpura / Código & Arquitetura
    glow: 'rgba(139, 92, 246, 0.25)',
    bg: 'rgba(139, 92, 246, 0.08)',
  },
  gauge: {
    stroke: '#f43f5e', // Rubi / Performance & Hardware
    glow: 'rgba(244, 63, 94, 0.25)',
    bg: 'rgba(244, 63, 94, 0.08)',
  },
};

/**
 * HairlineAnimatedFigure
 * Componente vetorial minimalista com traços finos (strokeWidth 1.25 a 1.5).
 * Executa 1 ciclo de animação, aguarda exatamente 2 segundos (2000ms) de repouso,
 * e reinicia o ciclo de forma determinística e acelerada por GPU.
 */
export const HairlineAnimatedFigure: React.FC<HairlineAnimatedFigureProps> = React.memo(
  ({
    type,
    size = 48,
    className = '',
    color,
    cycleDurationMs = 2400,
    pauseDurationMs = 2000,
    title,
  }) => {
    const [phase, setPhase] = useState<'animating' | 'paused'>('animating');
    const [cycleCount, setCycleCount] = useState<number>(0);
    const containerRef = useRef<HTMLDivElement>(null);
    const [isVisible, setIsVisible] = useState(true);

    const colorConfig = CATEGORY_DEFAULT_COLORS[type] || CATEGORY_DEFAULT_COLORS.vault;
    const activeStroke = color || colorConfig.stroke;

    // IntersectionObserver para pausar animações fora da viewport e garantir 60/120fps fluidos
    useEffect(() => {
      const node = containerRef.current;
      if (!node || typeof IntersectionObserver === 'undefined') return;

      const observer = new IntersectionObserver(
        (entries) => {
          const entry = entries[0];
          setIsVisible(entry?.isIntersecting ?? true);
        },
        { threshold: 0.1 }
      );
      observer.observe(node);
      return () => observer.disconnect();
    }, []);

    // Controle de ciclo + pausa de exatamente 2000ms
    useEffect(() => {
      if (!isVisible) return;

      let timer: NodeJS.Timeout;
      if (phase === 'animating') {
        timer = setTimeout(() => {
          setPhase('paused');
        }, cycleDurationMs);
      } else {
        timer = setTimeout(() => {
          setPhase('animating');
          setCycleCount((c) => c + 1);
        }, pauseDurationMs);
      }

      return () => clearTimeout(timer);
    }, [phase, isVisible, cycleDurationMs, pauseDurationMs]);

    const isAnim = phase === 'animating' && isVisible;

    // Renderizadores vetoriais Hairline
    const renderContent = () => {
      switch (type) {
        case 'lockers':
          return (
            <svg
              viewBox="0 0 48 48"
              fill="none"
              stroke={activeStroke}
              strokeWidth="1.35"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="w-full h-full"
              style={{ willChange: 'transform, opacity' }}
            >
              {/* Armário Externo */}
              <rect x="8" y="6" width="32" height="36" rx="2" strokeDasharray={isAnim ? '136' : 'none'} />
              {/* Gaveta Superior */}
              <line x1="8" y1="18" x2="40" y2="18" />
              <rect
                x="18"
                y="11"
                width="12"
                height="3"
                rx="1"
                className={isAnim ? 'transition-transform duration-700 ease-out' : ''}
                style={{
                  transform: isAnim ? 'translateX(3px)' : 'translateX(0)',
                  transition: 'transform 800ms cubic-bezier(0.16, 1, 0.3, 1)',
                }}
              />
              <circle cx="12" cy="12" r="1" fill={activeStroke} />

              {/* Gaveta Central */}
              <line x1="8" y1="30" x2="40" y2="30" />
              <rect
                x="18"
                y="23"
                width="12"
                height="3"
                rx="1"
                style={{
                  transform: isAnim ? 'translateX(-3px)' : 'translateX(0)',
                  transition: 'transform 800ms cubic-bezier(0.16, 1, 0.3, 1) 200ms',
                }}
              />
              <circle cx="12" cy="24" r="1" fill={activeStroke} />

              {/* Gaveta Inferior */}
              <rect
                x="18"
                y="35"
                width="12"
                height="3"
                rx="1"
                style={{
                  transform: isAnim ? 'translateX(2px)' : 'translateX(0)',
                  transition: 'transform 800ms cubic-bezier(0.16, 1, 0.3, 1) 400ms',
                }}
              />
              <circle cx="12" cy="36" r="1" fill={activeStroke} />

              {/* Pés do Rack */}
              <line x1="12" y1="42" x2="12" y2="45" />
              <line x1="36" y1="42" x2="36" y2="45" />
            </svg>
          );

        case 'vault':
          return (
            <svg
              viewBox="0 0 48 48"
              fill="none"
              stroke={activeStroke}
              strokeWidth="1.35"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="w-full h-full"
              style={{ willChange: 'transform, opacity' }}
            >
              {/* Moldura Externa do Cofre */}
              <rect x="6" y="6" width="36" height="36" rx="4" />
              <circle cx="10" cy="10" r="1" fill={activeStroke} />
              <circle cx="38" cy="10" r="1" fill={activeStroke} />
              <circle cx="10" cy="38" r="1" fill={activeStroke} />
              <circle cx="38" cy="38" r="1" fill={activeStroke} />

              {/* Engrenagem / Roda Rotativa do Segredo */}
              <g
                style={{
                  transformOrigin: '24px 24px',
                  transform: isAnim ? 'rotate(180deg)' : 'rotate(0deg)',
                  transition: 'transform 1400ms cubic-bezier(0.34, 1.56, 0.64, 1)',
                }}
              >
                <circle cx="24" cy="24" r="12" strokeDasharray="2 3" />
                <circle cx="24" cy="24" r="5" />
                <line x1="24" y1="12" x2="24" y2="15" />
                <line x1="24" y1="33" x2="24" y2="36" />
                <line x1="12" y1="24" x2="15" y2="24" />
                <line x1="33" y1="24" x2="36" y2="24" />
              </g>

              {/* Ferrolhos Retráteis */}
              <line
                x1="42"
                y1="18"
                x2={isAnim ? '38' : '45'}
                y2="18"
                strokeWidth="2"
                style={{ transition: 'all 600ms ease' }}
              />
              <line
                x1="42"
                y1="30"
                x2={isAnim ? '38' : '45'}
                y2="30"
                strokeWidth="2"
                style={{ transition: 'all 600ms ease 100ms' }}
              />
            </svg>
          );

        case 'padlock':
          return (
            <svg
              viewBox="0 0 48 48"
              fill="none"
              stroke={activeStroke}
              strokeWidth="1.35"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="w-full h-full"
              style={{ willChange: 'transform, opacity' }}
            >
              {/* Arco do Cadeado que abre e trava */}
              <path
                d="M16 20V14C16 9.58 19.58 6 24 6C28.42 6 32 9.58 32 14V20"
                style={{
                  transformOrigin: '16px 20px',
                  transform: isAnim ? 'translateY(-4px) rotate(-8deg)' : 'translateY(0) rotate(0)',
                  transition: 'transform 800ms cubic-bezier(0.16, 1, 0.3, 1)',
                }}
              />
              {/* Corpo do Cadeado */}
              <rect x="10" y="20" width="28" height="22" rx="3" />
              {/* Orifício da Chave com rotação sutil */}
              <circle cx="24" cy="29" r="2.5" />
              <path
                d="M24 31.5V36"
                strokeWidth="1.75"
                style={{
                  transformOrigin: '24px 29px',
                  transform: isAnim ? 'rotate(45deg)' : 'rotate(0deg)',
                  transition: 'transform 700ms ease-in-out 400ms',
                }}
              />
              {/* Linhas de blindagem */}
              <line x1="14" y1="24" x2="16" y2="24" />
              <line x1="32" y1="24" x2="34" y2="24" />
            </svg>
          );

        case 'router':
          return (
            <svg
              viewBox="0 0 48 48"
              fill="none"
              stroke={activeStroke}
              strokeWidth="1.35"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="w-full h-full"
              style={{ willChange: 'transform, opacity' }}
            >
              {/* Ondas Concéntricas de Sinal */}
              <path
                d="M17 12C21.4 8 26.6 8 31 12"
                style={{
                  opacity: isAnim ? 1 : 0.3,
                  transform: isAnim ? 'scale(1.08)' : 'scale(1)',
                  transformOrigin: '24px 18px',
                  transition: 'all 600ms ease-out',
                }}
              />
              <path
                d="M12 7C19.2 1.5 28.8 1.5 36 7"
                style={{
                  opacity: isAnim ? 1 : 0.2,
                  transform: isAnim ? 'scale(1.12)' : 'scale(1)',
                  transformOrigin: '24px 18px',
                  transition: 'all 800ms ease-out 200ms',
                }}
              />

              {/* Antenas */}
              <line x1="15" y1="24" x2="15" y2="16" />
              <circle cx="15" cy="16" r="1.5" fill={activeStroke} />
              <line x1="33" y1="24" x2="33" y2="16" />
              <circle cx="33" cy="16" r="1.5" fill={activeStroke} />

              {/* Corpo do Roteador */}
              <rect x="8" y="24" width="32" height="15" rx="2" />
              {/* Portas e LEDs piscantes */}
              <line x1="12" y1="31.5" x2="16" y2="31.5" />
              <circle
                cx="21"
                cy="31.5"
                r="1.25"
                fill={isAnim ? activeStroke : 'transparent'}
                style={{ transition: 'fill 300ms ease' }}
              />
              <circle
                cx="25"
                cy="31.5"
                r="1.25"
                fill={isAnim ? activeStroke : 'transparent'}
                style={{ transition: 'fill 300ms ease 200ms' }}
              />
              <circle
                cx="29"
                cy="31.5"
                r="1.25"
                fill={isAnim ? activeStroke : 'transparent'}
                style={{ transition: 'fill 300ms ease 400ms' }}
              />
              <line x1="33" y1="31.5" x2="36" y2="31.5" />
            </svg>
          );

        case 'layers':
          return (
            <svg
              viewBox="0 0 48 48"
              fill="none"
              stroke={activeStroke}
              strokeWidth="1.35"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="w-full h-full"
              style={{ willChange: 'transform, opacity' }}
            >
              {/* Camada Superior (Prisma) */}
              <path
                d="M24 6L6 15L24 24L42 15L24 6Z"
                style={{
                  transform: isAnim ? 'translateY(-3px)' : 'translateY(0)',
                  transition: 'transform 800ms cubic-bezier(0.16, 1, 0.3, 1)',
                }}
              />
              {/* Camada Intermediária */}
              <path
                d="M6 23L24 32L42 23"
                style={{
                  transform: isAnim ? 'translateY(0)' : 'translateY(0)',
                  opacity: isAnim ? 1 : 0.7,
                  transition: 'all 600ms ease 150ms',
                }}
              />
              {/* Camada Inferior */}
              <path
                d="M6 31L24 40L42 31"
                style={{
                  transform: isAnim ? 'translateY(3px)' : 'translateY(0)',
                  transition: 'transform 800ms cubic-bezier(0.16, 1, 0.3, 1) 300ms',
                }}
              />
            </svg>
          );

        case 'gauge':
          return (
            <svg
              viewBox="0 0 48 48"
              fill="none"
              stroke={activeStroke}
              strokeWidth="1.35"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="w-full h-full"
              style={{ willChange: 'transform, opacity' }}
            >
              {/* Arco Principal */}
              <path d="M10 34C7.5 28 8.5 21 13 16C19 10 29 10 35 16C39.5 21 40.5 28 38 34" />
              {/* Marcadores */}
              <line x1="12" y1="28" x2="15" y2="27" />
              <line x1="17" y1="18" x2="19" y2="20" />
              <line x1="24" y1="14" x2="24" y2="17" />
              <line x1="31" y1="18" x2="29" y2="20" />
              <line x1="36" y1="28" x2="33" y2="27" />

              {/* Ponteiro Rotativo de Telemetria */}
              <g
                style={{
                  transformOrigin: '24px 30px',
                  transform: isAnim ? 'rotate(55deg)' : 'rotate(-45deg)',
                  transition: 'transform 1000ms cubic-bezier(0.34, 1.56, 0.64, 1)',
                }}
              >
                <circle cx="24" cy="30" r="3" fill={activeStroke} />
                <line x1="24" y1="30" x2="31" y2="17" strokeWidth="1.75" />
              </g>
              <line x1="14" y1="38" x2="34" y2="38" strokeDasharray="2 3" />
            </svg>
          );

        default:
          return null;
      }
    };

    return (
      <div
        ref={containerRef}
        className={`relative inline-flex items-center justify-center rounded-xl p-2 transition-all duration-300 ${className}`}
        style={{
          width: size,
          height: size,
          backgroundColor: colorConfig.bg,
          boxShadow: isAnim ? `0 0 16px ${colorConfig.glow}` : 'none',
        }}
        title={title || `Figura Técnica: ${type}`}
      >
        {renderContent()}
      </div>
    );
  }
);

HairlineAnimatedFigure.displayName = 'HairlineAnimatedFigure';
