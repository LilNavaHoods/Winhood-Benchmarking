import React, { useState } from 'react';
import { FileText, Lock, ShieldCheck, X } from 'lucide-react';

interface PrivacyAndTermsModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialTab?: 'PRIVACY' | 'TERMS' | 'SECURITY';
}

export const PrivacyAndTermsModal: React.FC<PrivacyAndTermsModalProps> = ({
  isOpen,
  onClose,
  initialTab = 'PRIVACY',
}) => {
  const [activeTab, setActiveTab] = useState<'PRIVACY' | 'TERMS' | 'SECURITY'>(initialTab);

  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="privacy-terms-modal-title"
      className="fixed inset-0 z-[70] flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4"
    >
      <div className="w-full max-w-2xl max-h-[88vh] flex flex-col rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0c1017] text-slate-900 dark:text-slate-100 shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between gap-3 px-5 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#080b10]">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="w-5 h-5 text-[#31d6c4] shrink-0" />
            <div>
              <h3 id="privacy-terms-modal-title" className="text-sm font-bold">
                Privacidade, Transparência de IA &amp; Termos Open Source
              </h3>
              <p className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                WinHood Benchmark Analyzer v4.4.0 · Licença MIT · Microsoft Store Seção 10.5
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Fechar janela de Privacidade e Termos"
            className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-500 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tabs */}
        <div className="grid grid-cols-3 border-b border-slate-200 dark:border-slate-800 bg-slate-100/60 dark:bg-[#090d14] text-xs font-semibold">
          <button
            type="button"
            onClick={() => setActiveTab('PRIVACY')}
            className={`py-2.5 px-3 flex items-center justify-center gap-1.5 border-b-2 transition-colors cursor-pointer ${
              activeTab === 'PRIVACY'
                ? 'border-[#31d6c4] text-[#0e9f8e] dark:text-[#31d6c4] bg-white dark:bg-[#0c1017]'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Privacidade &amp; IA (PRIVACY.md)</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('TERMS')}
            className={`py-2.5 px-3 flex items-center justify-center gap-1.5 border-b-2 transition-colors cursor-pointer ${
              activeTab === 'TERMS'
                ? 'border-[#31d6c4] text-[#0e9f8e] dark:text-[#31d6c4] bg-white dark:bg-[#0c1017]'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Termos &amp; Licença MIT</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('SECURITY')}
            className={`py-2.5 px-3 flex items-center justify-center gap-1.5 border-b-2 transition-colors cursor-pointer ${
              activeTab === 'SECURITY'
                ? 'border-[#31d6c4] text-[#0e9f8e] dark:text-[#31d6c4] bg-white dark:bg-[#0c1017]'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Segurança (SECURITY.md)</span>
          </button>
        </div>

        {/* Body */}
        <div className="p-5 overflow-y-auto space-y-4 text-xs leading-relaxed text-slate-700 dark:text-slate-300">
          {activeTab === 'PRIVACY' && (
            <>
              <div className="p-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200">
                <strong>1. Execução 100% Local e Soberania de Dados:</strong> Todos os projetos, códigos-fonte analisados, relatórios SARIF/HTML/JSON/PDF, chaves criptográficas e o cofre autenticado <code className="font-mono">whdb:enc:v2</code> (<code className="font-mono">AES-256-GCM</code>) permanecem exclusivamente na sua máquina (<code className="font-mono">%APPDATA%\WinHood</code> / <code className="font-mono">.winhood_data</code>). Zero telemetria externa, zero rastreamento e zero anúncios.
              </div>

              <div className="space-y-1.5">
                <h4 className="font-bold text-slate-900 dark:text-slate-100">
                  2. Cookies Estritamente Técnicos (TOTP 2FA Opcional)
                </h4>
                <p>
                  Por padrão o WinHood opera com acesso local livre sem necessidade de login ou cadastro. Quando você ativa voluntariamente a proteção <strong>2FA (TOTP RFC-6238)</strong>, o sistema utiliza apenas dois cookies locais técnicos (<code className="font-mono">winhood_totp_unlock</code> com <code className="font-mono">HttpOnly</code> e <code className="font-mono">winhood_csrf</code>) para manter o desbloqueio local e proteger contra ataques CSRF. Nenhum cookie é usado para publicidade ou rastreamento.
                </p>
              </div>

              <div className="space-y-1.5">
                <h4 className="font-bold text-slate-900 dark:text-slate-100">
                  3. Transparência sobre IA e Serviços Externos
                </h4>
                <p>
                  O motor principal de SAST, Taint Analysis, SCA, SBOM, Segredos e cálculo de pontuação MQR executa <strong>100% offline e localmente</strong>. Fragmentos de código ou métricas só são transmitidos para APIs externas (<code className="font-mono">@google/genai</code> Gemini, SonarQube Cloud/Server ou GitHub) <strong>quando você mesmo configura sua chave/token e autoriza a ação</strong>.
                </p>
              </div>

              <div className="space-y-1.5">
                <h4 className="font-bold text-slate-900 dark:text-slate-100">
                  4. Controle Total dos Dados Locais e 2FA Opcional
                </h4>
                <p>
                  Nenhuma conta ou senha é criada. Você pode desativar a proteção 2FA (TOTP Opcional) ou limpar o workspace local a qualquer momento, removendo imediatamente o segredo TOTP criptografado de <code className="font-mono">totp_config.json</code>.
                </p>
              </div>

              <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] font-mono text-[11px] space-y-1">
                <div><strong>Publicador:</strong> WinHood Engineering &amp; AppSec</div>
                <div>
                  <strong>Contato de Suporte / Relatórios / Reclamações:</strong> Enviar através do repositório oficial no GitHub (https://github.com/LilNavaHoods/Winhood-Benchmarking/issues)
                </div>
                <div><strong>Repositório Open Source:</strong> https://github.com/LilNavaHoods/Winhood-Benchmarking</div>
              </div>
            </>
          )}

          {activeTab === 'TERMS' && (
            <>
              <div className="space-y-1.5">
                <h4 className="font-bold text-slate-900 dark:text-slate-100">
                  Licença Open Source MIT (LICENSE &amp; TERMS.md)
                </h4>
                <p>
                  O WinHood Benchmark Analyzer é distribuído gratuitamente sob a licença <strong>MIT</strong>. Você tem liberdade para executar, inspecionar, modificar e distribuir o software conforme os termos da licença MIT.
                </p>
              </div>

              <div className="space-y-1.5">
                <h4 className="font-bold text-slate-900 dark:text-slate-100">
                  Responsabilidade pelas Chaves e Alvos Avaliados
                </h4>
                <p>
                  O usuário é responsável por possuir autorização sobre os repositórios e softwares submetidos à análise, bem como pela guarda e gerenciamento das chaves/tokens de API de terceiros (GitHub, SonarCloud, Gemini) configurados em sua instância local.
                </p>
              </div>

              <div className="space-y-1.5">
                <h4 className="font-bold text-slate-900 dark:text-slate-100">
                  Contato de Suporte, Relatórios e Reclamações
                </h4>
                <p>
                  Para suporte técnico, envio de relatórios de falhas/bugs, sugestões ou reclamações, registre diretamente através do canal oficial de Issues do projeto no GitHub:{' '}
                  <code className="font-mono text-[#0e9f8e] dark:text-[#31d6c4]">
                    https://github.com/LilNavaHoods/Winhood-Benchmarking/issues
                  </code>
                </p>
              </div>

              <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] font-mono text-[11px]">
                THE SOFTWARE IS PROVIDED &quot;AS IS&quot;, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
              </div>
            </>
          )}

          {activeTab === 'SECURITY' && (
            <>
              <div className="space-y-1.5">
                <h4 className="font-bold text-slate-900 dark:text-slate-100">
                  Controles de Segurança e Divulgação Responsável (SECURITY.md)
                </h4>
                <ul className="list-disc pl-5 space-y-1">
                  <li><strong>Criptografia em Repouso:</strong> AES-256-GCM (<code className="font-mono">whdb:enc:v2</code>) + rotação KMS.</li>
                  <li><strong>Acesso Local &amp; 2FA Opcional:</strong> Acesso local livre sem cadastro ou senha, com proteção opcional via <strong>TOTP 2FA (RFC-6238)</strong> armazenado com <code className="font-mono">AES-256-GCM</code>, códigos de recuperação em <code className="font-mono">SHA-256</code> com salt e comparação em tempo constante (<code className="font-mono">timingSafeEqual</code>).</li>
                  <li><strong>Isolamento Electron:</strong> <code className="font-mono">nodeIntegration: false</code>, <code className="font-mono">contextIsolation: true</code>, <code className="font-mono">sandbox: true</code>, <code className="font-mono">SsrfGuard</code> e proteção CSRF Double-Submit.</li>
                </ul>
              </div>
              <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] font-mono text-[11px]">
                Para relatar vulnerabilidades, problemas técnicos ou reclamações, utilize a aba <strong>Security Advisories</strong> (<code className="font-mono">https://github.com/LilNavaHoods/Winhood-Benchmarking/security/advisories</code>) ou <strong>GitHub Issues</strong> (<code className="font-mono">https://github.com/LilNavaHoods/Winhood-Benchmarking/issues</code>) no repositório oficial do projeto. Versão suportada: <strong>4.4.x</strong>.
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#080b10] flex items-center justify-between text-[11px]">
          <span className="font-mono text-slate-500">
            Documentos na raiz: LICENSE · PRIVACY.md · TERMS.md · SECURITY.md
          </span>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] cursor-pointer"
          >
            Fechar
          </button>
        </div>
      </div>
    </div>
  );
};
