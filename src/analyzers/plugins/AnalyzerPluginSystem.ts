import type {
  AnalyzerPlugin,
  AnalyzerPluginContext,
  AnalyzerPluginOutput,
  AstIssueCandidate,
} from '../types';
import { SecretScanner } from '../SecretsCatalog';

/**
 * IaC Native Analyzer Plugin
 * Supports Terraform (.tf), Kubernetes manifests (YAML), Dockerfile, and GitHub Actions workflows.
 */
export const IacAnalyzerPlugin: AnalyzerPlugin = {
  id: 'winhood-iac-plugin',
  name: 'WinHood Native IaC Security Plugin (Terraform / K8s / Dockerfile / GitHub Actions)',
  version: '1.0.0',
  supportedLanguages: ['Terraform', 'Kubernetes', 'Dockerfile', 'GitHubActions'],
  supportedExtensions: ['.tf', '.tfvars', '.yaml', '.yml', 'Dockerfile', '.dockerfile'],
  capabilities: ['IAC', 'SECRETS'],
  matchesFile: (filePath: string, content: string): boolean => {
    const lower = filePath.toLowerCase();
    const base = lower.split('/').pop() || '';
    if (lower.endsWith('.tf') || lower.endsWith('.tfvars')) return true;
    if (base === 'dockerfile' || lower.endsWith('.dockerfile')) return true;
    if (/\.github\/workflows\/.*\.(yml|yaml)$/i.test(filePath)) return true;
    if ((lower.endsWith('.yml') || lower.endsWith('.yaml')) && /\bkind:\s*(Deployment|Pod|DaemonSet|StatefulSet|Job|CronJob|Service|Ingress|Role|ClusterRole)\b/.test(content)) {
      return true;
    }
    return false;
  },
  analyze: (ctx: AnalyzerPluginContext): AnalyzerPluginOutput => {
    const t0 = performance.now();
    const candidates: AstIssueCandidate[] = [];
    const limitations: string[] = [];
    let filesScanned = 0;

    for (const { filePath, content } of ctx.files) {
      if (!IacAnalyzerPlugin.matchesFile(filePath, content)) continue;
      if (performance.now() - t0 > ctx.slaBudgetMs) {
        limitations.push(`SLA budget (${ctx.slaBudgetMs}ms) atingido no plugin IaC em ${filePath}.`);
        return {
          pluginId: IacAnalyzerPlugin.id,
          pluginVersion: IacAnalyzerPlugin.version,
          filesScanned,
          filesFailed: 0,
          candidates,
          limitations,
          timedOut: true,
          durationMs: Math.round(performance.now() - t0),
        };
      }
      filesScanned += 1;
      const lower = filePath.toLowerCase();
      const base = lower.split('/').pop() || '';
      const lines = content.split(/\r?\n/);

      // 1. Terraform (.tf)
      if (lower.endsWith('.tf') || lower.endsWith('.tfvars')) {
        lines.forEach((line, idx) => {
          const lineNo = idx + 1;
          if (/0\.0\.0\.0\/0/.test(line) && /cidr_blocks|source_ranges|ingress/i.test(content)) {
            candidates.push({
              ruleId: 'iac:TF-001',
              title: 'Regra de Firewall / Security Group Terraform exposta para 0.0.0.0/0',
              description: 'Bloco CIDR aberto irrestritamente (0.0.0.0/0) expõe portas internas à Internet pública.',
              category: 'IAC',
              severity: 'CRITICAL',
              cwe: 'CWE-284',
              filePath,
              lineNumber: lineNo,
              endLineNumber: lineNo,
              snippet: line.trim(),
              remediation: 'Restringir cidr_blocks às faixas corporativas ou VPN autorizadas.',
              detectionMethod: 'STATIC_PATTERN',
              confidence: 'HIGH',
              effortMinutes: 20,
            });
          }
          if (/acl\s*=\s*"public-read(-write)?"/i.test(line)) {
            candidates.push({
              ruleId: 'iac:TF-002',
              title: 'Bucket S3 / Storage Terraform configurado com ACL pública',
              description: `ACL pública "${line.trim()}" permite acesso anônimo ou exposição de dados em nuvem.`,
              category: 'IAC',
              severity: 'HIGH',
              cwe: 'CWE-311',
              filePath,
              lineNumber: lineNo,
              endLineNumber: lineNo,
              snippet: line.trim(),
              remediation: 'Definir acl = "private" e habilitar aws_s3_bucket_public_access_block.',
              detectionMethod: 'STATIC_PATTERN',
              confidence: 'HIGH',
              effortMinutes: 20,
            });
          }
        });
      }

      // 2. Kubernetes manifests
      if ((lower.endsWith('.yml') || lower.endsWith('.yaml')) && /\bkind:\s*(Deployment|Pod|DaemonSet|StatefulSet|Job|CronJob|Service|Ingress|Role|ClusterRole)\b/.test(content)) {
        lines.forEach((line, idx) => {
          const lineNo = idx + 1;
          if (/privileged:\s*true/i.test(line)) {
            candidates.push({
              ruleId: 'iac:K8S-001',
              title: 'Container Kubernetes configurado em modo privileged: true',
              description: 'Containers privilegiados contornam o isolamento de kernel e permitem escape para o nó host.',
              category: 'IAC',
              severity: 'CRITICAL',
              cwe: 'CWE-250',
              filePath,
              lineNumber: lineNo,
              endLineNumber: lineNo,
              snippet: line.trim(),
              remediation: 'Definir securityContext.privileged: false e runAsNonRoot: true.',
              detectionMethod: 'STATIC_PATTERN',
              confidence: 'HIGH',
              effortMinutes: 25,
            });
          }
          if (/allowPrivilegeEscalation:\s*true/i.test(line) || /runAsUser:\s*0\b/.test(line)) {
            candidates.push({
              ruleId: 'iac:K8S-001',
              title: 'Pod Kubernetes permite escalonamento de privilégios ou execução como UID 0 (root)',
              description: 'Execução como root ou allowPrivilegeEscalation: true amplia o impacto de comprometimento do container.',
              category: 'IAC',
              severity: 'HIGH',
              cwe: 'CWE-250',
              filePath,
              lineNumber: lineNo,
              endLineNumber: lineNo,
              snippet: line.trim(),
              remediation: 'Configurar runAsNonRoot: true, runAsUser >= 1000 e allowPrivilegeEscalation: false.',
              detectionMethod: 'STATIC_PATTERN',
              confidence: 'HIGH',
              effortMinutes: 20,
            });
          }
        });
      }

      // 3. Dockerfile
      if (base === 'dockerfile' || lower.endsWith('.dockerfile')) {
        const hasUserDirective = /^\s{0,16}USER\s+(?!root\b|0\b)\S+/im.test(content);
        lines.forEach((line, idx) => {
          const lineNo = idx + 1;
          const trimmedLine = line.trim();
          if (/^FROM\s+[a-zA-Z0-9._/-]{1,120}(?::latest)?$/i.test(trimmedLine)) {
            candidates.push({
              ruleId: 'iac:DOCKER-001',
              title: 'Dockerfile utiliza imagem base sem versão fixada (:latest ou sem tag)',
              description: 'Imagens mutáveis quebram reprodutibilidade de build e podem introduzir vulnerabilidades não auditadas.',
              category: 'IAC',
              severity: 'MEDIUM',
              cwe: 'CWE-1104',
              filePath,
              lineNumber: lineNo,
              endLineNumber: lineNo,
              snippet: line.trim(),
              remediation: 'Fixar tag semântica e digest SHA-256 na instrução FROM.',
              detectionMethod: 'STATIC_PATTERN',
              confidence: 'HIGH',
              effortMinutes: 15,
            });
          }
        });
        if (!hasUserDirective) {
          const fromIdx = lines.findIndex((l) => /^\s*FROM\s+/i.test(l));
          candidates.push({
            ruleId: 'iac:DOCKER-001',
            title: 'Dockerfile sem instrução USER não-privilegiada (execução padrão como root)',
            description: 'Sem instrução USER não-root, processos no container executam como root (UID 0).',
            category: 'IAC',
            severity: 'HIGH',
            cwe: 'CWE-250',
            filePath,
            lineNumber: fromIdx >= 0 ? fromIdx + 1 : 1,
            endLineNumber: fromIdx >= 0 ? fromIdx + 1 : 1,
            snippet: (lines[Math.max(0, fromIdx)] || '').trim(),
            remediation: 'Adicionar usuário dedicado e instrução USER appuser (ou USER 10001).',
            detectionMethod: 'STATIC_PATTERN',
            confidence: 'HIGH',
            effortMinutes: 15,
          });
        }
      }

      // 4. GitHub Actions Workflow
      if (/\.github\/workflows\/.*\.(yml|yaml)$/i.test(filePath)) {
        const jobsLineIdx = lines.findIndex((l) => /^jobs:\s*$/i.test(l));
        lines.forEach((line, idx) => {
          const lineNo = idx + 1;
          // githubactions:S8233 - workflow-level write permissions before jobs:
          if (
            (jobsLineIdx === -1 || idx < jobsLineIdx) &&
            /^\s+(?:security-events|pull-requests|packages|id-token|Statuses|checks|deployments|issues|discussions|actions):\s*write\b/i.test(
              line
            )
          ) {
            candidates.push({
              ruleId: 'githubactions:S8233',
              title: 'Permissão write declarada no nível raiz do workflow GitHub Actions',
              description:
                'Permissões de escrita (write) no topo do workflow concedem escopo elevado a todos os jobs; mova para o job específico.',
              category: 'IAC',
              severity: 'HIGH',
              cwe: 'CWE-250',
              filePath,
              lineNumber: lineNo,
              endLineNumber: lineNo,
              snippet: line.trim(),
              remediation:
                'Manter apenas contents: read no topo do workflow e declarar permissões write dentro do job específico.',
              detectionMethod: 'STATIC_PATTERN',
              confidence: 'HIGH',
              effortMinutes: 10,
            });
          }
          // githubactions:S8543 - npx without pinned version in workflow
          if (/\bnpx\s+(?!--yes\s+[^\s@]+@\d)[^\s@]+(?:\s|$)/.test(line) && !line.trim().startsWith('#')) {
            candidates.push({
              ruleId: 'githubactions:S8543',
              title: 'Execução de pacote via npx sem versão fixada em workflow CI/CD',
              description:
                'Invocar npx sem versão exata ou sem usar ./node_modules/.bin expõe a pipeline a releases não verificadas.',
              category: 'IAC',
              severity: 'HIGH',
              cwe: 'CWE-829',
              filePath,
              lineNumber: lineNo,
              endLineNumber: lineNo,
              snippet: line.trim(),
              remediation:
                'Utilizar o binário local ./node_modules/.bin/<tool> instalado via npm ci ou fixar versão exata pacote@x.y.z.',
              detectionMethod: 'STATIC_PATTERN',
              confidence: 'HIGH',
              effortMinutes: 10,
            });
          }
          if (/write-all/i.test(line)) {
            candidates.push({
              ruleId: 'iac:GHA-001',
              title: 'Workflow GitHub Actions solicita permissions: write-all',
              description: 'Permissão write-all concede token GITHUB_TOKEN com escopo excessivo em violações de menor privilégio.',
              category: 'IAC',
              severity: 'HIGH',
              cwe: 'CWE-250',
              filePath,
              lineNumber: lineNo,
              endLineNumber: lineNo,
              snippet: line.trim(),
              remediation: 'Restringir permissions para contents: read e conceder apenas escopos mínimos necessários.',
              detectionMethod: 'STATIC_PATTERN',
              confidence: 'HIGH',
              effortMinutes: 15,
            });
          }
          if (/\$\{\{\s*github\.event\.(?:issue|pull_request|comment|head_commit)\./.test(line)) {
            candidates.push({
              ruleId: 'iac:GHA-001',
              title: 'Injeção de script potencial em GitHub Actions via interpolação direta de github.event.*',
              description: 'Interpolar títulos/corpos de PR ou issue diretamente em run: permite execução arbitrária no runner.',
              category: 'IAC',
              severity: 'CRITICAL',
              cwe: 'CWE-94',
              filePath,
              lineNumber: lineNo,
              endLineNumber: lineNo,
              snippet: line.trim(),
              remediation: 'Passar o valor via env: intermediário e referenciar "$VAR" entre aspas no shell.',
              detectionMethod: 'STATIC_PATTERN',
              confidence: 'HIGH',
              effortMinutes: 20,
            });
          }
        });
      }
    }

    return {
      pluginId: IacAnalyzerPlugin.id,
      pluginVersion: IacAnalyzerPlugin.version,
      filesScanned,
      filesFailed: 0,
      candidates,
      limitations,
      durationMs: Math.max(1, Math.round(performance.now() - t0)),
    };
  },
};

/**
 * Secrets Catalog Scanner Plugin (Regex + Shannon Entropy + Documented FP Exclusions)
 */
export const SecretsCatalogPlugin: AnalyzerPlugin = {
  id: 'winhood-secrets-catalog-plugin',
  name: 'WinHood Native Secrets & Entropy Scanner Plugin',
  version: '1.2.0',
  supportedLanguages: [
    'TypeScript', 'JavaScript', 'Python', 'Java', 'C#', 'Go', 'Rust',
    'Terraform', 'Kubernetes', 'Dockerfile', 'GitHubActions', 'Other',
  ],
  supportedExtensions: ['*'],
  capabilities: ['SECRETS'],
  matchesFile: () => true,
  analyze: (ctx: AnalyzerPluginContext): AnalyzerPluginOutput => {
    const t0 = performance.now();
    const subsetMap: Record<string, string> = {};
    for (const f of ctx.files) {
      subsetMap[f.filePath] = f.content;
    }
    const candidates = SecretScanner.scanFiles(subsetMap);
    return {
      pluginId: SecretsCatalogPlugin.id,
      pluginVersion: SecretsCatalogPlugin.version,
      filesScanned: ctx.files.length,
      filesFailed: 0,
      candidates,
      limitations: [],
      durationMs: Math.max(1, Math.round(performance.now() - t0)),
    };
  },
};

export class AnalyzerPluginManager {
  private static readonly customPlugins = new Map<string, AnalyzerPlugin>();

  public static registerPlugin(plugin: AnalyzerPlugin): void {
    AnalyzerPluginManager.customPlugins.set(plugin.id, plugin);
  }

  public static unregisterPlugin(pluginId: string): void {
    AnalyzerPluginManager.customPlugins.delete(pluginId);
  }

  public static listPlugins(): AnalyzerPlugin[] {
    return [IacAnalyzerPlugin, SecretsCatalogPlugin, ...Array.from(AnalyzerPluginManager.customPlugins.values())];
  }

  public static executePlugins(
    ctx: AnalyzerPluginContext,
    enablePluginIds?: string[]
  ): {
    outputs: AnalyzerPluginOutput[];
    candidates: AstIssueCandidate[];
    limitations: string[];
  } {
    const plugins = AnalyzerPluginManager.listPlugins()
      .filter((p) => !enablePluginIds || enablePluginIds.includes(p.id))
      .sort((a, b) => a.id.localeCompare(b.id));

    const outputs: AnalyzerPluginOutput[] = [];
    const candidates: AstIssueCandidate[] = [];
    const limitations: string[] = [];

    for (const plugin of plugins) {
      try {
        const res = plugin.analyze(ctx);
        outputs.push(res);
        candidates.push(...res.candidates);
        limitations.push(...res.limitations);
      } catch (err: any) {
        limitations.push(`Plugin ${plugin.id} falhou de forma isolada: ${err?.message || String(err)}`);
      }
    }

    return { outputs, candidates, limitations };
  }
}
