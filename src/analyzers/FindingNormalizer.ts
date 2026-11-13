import crypto from 'node:crypto';
import type { NormalizedFinding, Software } from '../types/benchmark';
import { enrichLegacyOrExternalFinding, maskSecretsInText } from '../engine/scoringEngine';
import type { AnalysisScope, AstIssueCandidate } from './types';

export class EvidenceCollector {
  public static computeCanonicalHash(payload: unknown): string {
    return crypto.createHash('sha256').update(JSON.stringify(payload), 'utf8').digest('hex');
  }

  public static extractContextLines(
    fileContent: string,
    lineNumber: number,
    radius = 2
  ): { contextBefore: string[]; contextAfter: string[]; snippet: string } {
    const lines = fileContent.split(/\r?\n/);
    const idx = Math.max(0, lineNumber - 1);
    const contextBefore = lines
      .slice(Math.max(0, idx - radius), idx)
      .map((l) => maskSecretsInText(l));
    const contextAfter = lines
      .slice(idx + 1, Math.min(lines.length, idx + 1 + radius))
      .map((l) => maskSecretsInText(l));
    const snippet = maskSecretsInText((lines[idx] || '').trim());
    return { contextBefore, contextAfter, snippet };
  }
}

export class FindingNormalizer {
  public static fromAstCandidate(params: {
    candidate: AstIssueCandidate;
    scope: AnalysisScope;
    toolName: string;
    toolVersion: string;
    filesMap: Record<string, string>;
    index: number;
  }): NormalizedFinding {
    const { candidate, scope, toolName, toolVersion, filesMap, index } = params;
    const content = filesMap[candidate.filePath] || '';
    const ctx = EvidenceCollector.extractContextLines(content, candidate.lineNumber);
    const maskedFlows = (candidate.executionFlows || []).map((step) => {
      const rawText = step.codeSnippet || step.snippet || '';
      const masked = maskSecretsInText(rawText);
      return {
        ...step,
        codeSnippet: masked,
        snippet: masked,
      };
    });

    return enrichLegacyOrExternalFinding({
      id: `f-${scope.runId}-${scope.softwareId}-${index}-${EvidenceCollector.computeCanonicalHash({
        rule: candidate.ruleId,
        file: candidate.filePath,
        line: candidate.lineNumber,
      }).slice(0, 8)}`,
      runId: scope.runId,
      softwareId: scope.softwareId,
      softwareName: scope.softwareName,
      softwareVersion: scope.softwareVersion,
      toolName,
      toolVersion,
      originType:
        candidate.detectionMethod === 'TAINT_ANALYSIS'
          ? 'WINHOOD_TAINT_AST'
          : 'WINHOOD_NATIVE_STATIC',
      detectionMethod: candidate.detectionMethod,
      originalRuleId: candidate.ruleId,
      category: candidate.category,
      cwe: candidate.cwe,
      severity: candidate.severity,
      confidence: candidate.confidence,
      validationStatus: 'VALIDATED',
      lifecycleState: 'CONFIRMED',
      title: candidate.title,
      description: candidate.description,
      filePath: candidate.filePath,
      lineNumber: candidate.lineNumber,
      endLineNumber: candidate.endLineNumber,
      snippet: ctx.snippet || maskSecretsInText(candidate.snippet),
      contextBefore: ctx.contextBefore,
      contextAfter: ctx.contextAfter,
      executionFlows: maskedFlows,
      remediation: candidate.remediation,
      remediationEffortMinutes: candidate.effortMinutes,
      collectedAt: new Date().toISOString(),
    });
  }

  public static buildScopeFromSoftware(runId: string, software: Software): AnalysisScope {
    return {
      runId,
      softwareId: software.id,
      softwareName: software.name,
      softwareVersion: software.version,
      commitHash: software.commitHash,
      filesMap: software.sourceFilesContent || {},
    };
  }
}
