import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const targetPath = process.env.INPUT_PATH || '.';
const gateId = process.env.INPUT_GATE || 'winhood-standard-v2';
const profile = process.env.INPUT_PROFILE || 'mqr-strict';
const failOn = (process.env['INPUT_FAIL-ON'] || 'BLOCKED').toUpperCase();
const sarifOut = process.env['INPUT_SARIF-OUTPUT'] || 'winhood-results.sarif';
const enforceGate = (process.env['INPUT_ENFORCE-GATE'] || 'true') === 'true';

const cliPath = path.resolve(process.cwd(), 'cli/winhood-cli.ts');
const args = [
  '--import',
  'tsx',
  cliPath,
  'report',
  '--path',
  targetPath,
  '--gate',
  gateId,
  '--profile',
  profile,
  '--format',
  'sarif',
  '--deterministic',
  '--ci-exit-codes',
  '--out',
  sarifOut,
];
if (enforceGate) args.push('--enforce-gate');

const res = spawnSync(process.execPath, args, { stdio: 'inherit', shell: false });
let exitCode = res.status ?? 4;
let decision = 'INCONCLUSIVE';

const resolvedReportPath = path.resolve(process.cwd(), sarifOut);

if (fs.existsSync(resolvedReportPath)) {
  try {
    const sarif = JSON.parse(fs.readFileSync(resolvedReportPath, 'utf8'));
    const props = sarif?.runs?.[0]?.properties || {};
    const results = sarif?.runs?.[0]?.results || [];
    decision = props.gateDecision || 'APPROVED';

    const prComment = [
      `### WinHood Independent Audit & Quality Gate (\`${profile}\`)`,
      `- **Quality Gate:** \`${gateId}\` -> **${decision}**`,
      `- **Total Findings:** \`${results.length}\``,
      `- **Report Artifact:** \`${sarifOut}\``,
      `- **Merge Policy (\`fail-on: ${failOn}\`):** ${decision === 'BLOCKED' || decision === 'REJECTED' ? 'MERGE BLOCKED' : 'MERGE ALLOWED'}`,
    ].join('\n');
    fs.writeFileSync(path.resolve(process.cwd(), 'winhood-pr-comment.md'), prComment, 'utf8');

    if (process.env.GITHUB_STEP_SUMMARY) {
      fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${prComment}\n`);
    }
    if (process.env.GITHUB_OUTPUT) {
      fs.appendFileSync(process.env.GITHUB_OUTPUT, `decision=${decision}\n`);
      fs.appendFileSync(process.env.GITHUB_OUTPUT, `gate-decision=${decision}\n`);
      fs.appendFileSync(process.env.GITHUB_OUTPUT, `exit-code=${exitCode}\n`);
      fs.appendFileSync(process.env.GITHUB_OUTPUT, `report-path=${resolvedReportPath}\n`);
    }
  } catch {
    exitCode = 4;
  }
}

if (enforceGate) {
  if (
    (failOn === 'BLOCKED' && (decision === 'BLOCKED' || decision === 'REJECTED')) ||
    (failOn === 'APPROVED_WITH_RESERVATIONS' && decision !== 'APPROVED') ||
    (failOn === 'INCONCLUSIVE' && decision === 'INCONCLUSIVE')
  ) {
    process.exit(exitCode > 0 ? exitCode : 2);
  }
}

process.exit(0);
