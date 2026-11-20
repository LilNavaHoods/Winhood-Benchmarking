import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export interface DiffFindingLike {
  id?: string;
  ruleId?: string;
  filePath: string;
  lineNumber?: number;
  severity: 'BLOCKER' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | string;
  category?: string;
}

export interface NewCodeDiffMap {
  baseRef: string;
  headRef: string;
  mergeBaseSha: string;
  changedFiles: Record<string, Set<number>>;
  totalAddedOrModifiedLines: number;
}

export interface CleanAsYouCodeEvaluation<T extends DiffFindingLike> {
  passed: boolean;
  baseRef: string;
  mergeBaseSha: string;
  totalAddedOrModifiedLines: number;
  newCodeFindings: T[];
  overallOnlyFindings: T[];
  blockingNewFindings: T[];
  reasons: string[];
}

export function computeGitNewCodeDiffMap(params?: {
  cwd?: string;
  baseRef?: string;
  headRef?: string;
}): NewCodeDiffMap {
  const cwd = params?.cwd || process.cwd();
  const baseRef = params?.baseRef || 'origin/main';
  const headRef = params?.headRef || 'HEAD';

  const mergeBaseSha = execFileSync('git', ['merge-base', baseRef, headRef], {
    cwd,
    encoding: 'utf8',
    shell: false,
  }).trim();

  const rawDiff = execFileSync(
    'git',
    ['diff', '--unified=0', '--no-color', `${mergeBaseSha}..${headRef}`],
    { cwd, encoding: 'utf8', shell: false, maxBuffer: 25 * 1024 * 1024 }
  );

  const changedFiles: Record<string, Set<number>> = {};
  let currentFile: string | null = null;
  let totalAddedOrModifiedLines = 0;

  for (const line of rawDiff.split(/\r?\n/)) {
    if (line.startsWith('+++ b/')) {
      currentFile = line.slice(6).trim().replace(/\\/g, '/');
      if (!changedFiles[currentFile]) {
        changedFiles[currentFile] = new Set<number>();
      }
      continue;
    }
    if (currentFile && line.startsWith('@@ ')) {
      const match = /\+(\d+)(?:,(\d+))?/.exec(line);
      if (!match) continue;
      const startLine = Number.parseInt(match[1], 10);
      const count = match[2] !== undefined ? Number.parseInt(match[2], 10) : 1;
      for (let offset = 0; offset < count; offset += 1) {
        changedFiles[currentFile].add(startLine + offset);
        totalAddedOrModifiedLines += 1;
      }
    }
  }

  return { baseRef, headRef, mergeBaseSha, changedFiles, totalAddedOrModifiedLines };
}

export function evaluateCleanAsYouCodeGate<T extends DiffFindingLike>(
  findings: T[],
  diffMap: NewCodeDiffMap,
  options?: { blockOnSeverities?: ReadonlySet<string> }
): CleanAsYouCodeEvaluation<T> {
  const blockingSeverities =
    options?.blockOnSeverities || new Set(['BLOCKER', 'CRITICAL', 'HIGH']);

  const newCodeFindings: T[] = [];
  const overallOnlyFindings: T[] = [];

  for (const finding of findings) {
    const normPath = (finding.filePath || '').replace(/^\.\//, '').replace(/\\/g, '/');
    const changedLines = diffMap.changedFiles[normPath];
    const lineNo = finding.lineNumber ?? 0;

    if (changedLines && (lineNo === 0 || changedLines.has(lineNo))) {
      newCodeFindings.push(finding);
    } else {
      overallOnlyFindings.push(finding);
    }
  }

  const blockingNewFindings = newCodeFindings.filter((f) =>
    blockingSeverities.has(String(f.severity || '').toUpperCase())
  );

  const reasons: string[] = [];
  if (blockingNewFindings.length > 0) {
    reasons.push(
      `Quality Gate (New Code) reprovado: ${blockingNewFindings.length} achado(s) de severidade alta/crítica introduzidos no diff.`
    );
  }

  return {
    passed: blockingNewFindings.length === 0,
    baseRef: diffMap.baseRef,
    mergeBaseSha: diffMap.mergeBaseSha,
    totalAddedOrModifiedLines: diffMap.totalAddedOrModifiedLines,
    newCodeFindings,
    overallOnlyFindings,
    blockingNewFindings,
    reasons,
  };
}

const isDirectExecution =
  typeof process !== 'undefined' &&
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (isDirectExecution) {
  const baseRef = process.env.WINHOOD_NEW_CODE_BASE_REF || process.argv[2] || 'origin/main';
  const headRef = process.env.WINHOOD_NEW_CODE_HEAD_REF || process.argv[3] || 'HEAD';
  try {
    const diffMap = computeGitNewCodeDiffMap({ baseRef, headRef });
    const changedFilesSummary = Object.fromEntries(
      Object.entries(diffMap.changedFiles).map(([file, lines]) => [file, lines.size])
    );
    console.log(
      JSON.stringify(
        {
          baseRef: diffMap.baseRef,
          headRef: diffMap.headRef,
          mergeBaseSha: diffMap.mergeBaseSha,
          totalAddedOrModifiedLines: diffMap.totalAddedOrModifiedLines,
          changedFilesCount: Object.keys(diffMap.changedFiles).length,
          changedFilesLineCounts: changedFilesSummary,
        },
        null,
        2
      )
    );
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[WinHood NewCodeDiffEngine] Falha ao computar diff Git (${baseRef}..${headRef}): ${msg}`);
    process.exitCode = 1;
  }
}
