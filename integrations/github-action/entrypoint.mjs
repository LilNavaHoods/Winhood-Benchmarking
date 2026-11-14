import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const targetPath = process.env.INPUT_PATH || '.';
const gateId = process.env.INPUT_GATE || 'winhood-standard-v2';
const sarifOut = process.env['INPUT_SARIF-OUTPUT'] || 'winhood-results.sarif';
const enforceGate = (process.env['INPUT_ENFORCE-GATE'] || 'true') === 'true';

const cliPath = path.resolve(process.cwd(), 'cli/winhood-cli.ts');
const args = ['--import', 'tsx', cliPath, 'analyze', '--path', targetPath, '--gate', gateId, '--format', 'sarif', '--out', sarifOut];
if (enforceGate) args.push('--enforce-gate');

const res = spawnSync(process.execPath, args, { stdio: 'inherit', shell: false });
const exitCode = res.status ?? 3;

if (process.env.GITHUB_OUTPUT && fs.existsSync(sarifOut)) {
  try {
    const sarif = JSON.parse(fs.readFileSync(sarifOut, 'utf8'));
    const props = sarif?.runs?.[0]?.properties || {};
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `gate-decision=${props.gateDecision || 'UNKNOWN'}\n`);
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `exit-code=${exitCode}\n`);
  } catch {
    // Ignore output metadata write failure
  }
}

process.exit(exitCode);
