export const WINHOOD_SQLITE_SCHEMA_SQL = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  category TEXT,
  objective TEXT,
  default_quality_gate_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS softwares (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  version TEXT,
  encrypted_source_envelope TEXT,
  encryption_key_id TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS benchmark_runs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  branch_name TEXT DEFAULT 'main',
  commit_sha TEXT,
  status TEXT NOT NULL,
  quality_gate_passed INTEGER NOT NULL DEFAULT 0,
  new_code_gate_passed INTEGER,
  signed_manifest_json TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES benchmark_runs(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  cwe_id TEXT,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  file_path TEXT NOT NULL,
  line_number INTEGER NOT NULL DEFAULT 0,
  is_new_code INTEGER NOT NULL DEFAULT 0,
  triage_status TEXT NOT NULL DEFAULT 'OPEN',
  encrypted_snippet TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_runs_project_branch ON benchmark_runs(project_id, branch_name, completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_project_fp ON findings(project_id, fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_run_sev ON findings(run_id, severity, is_new_code);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  action TEXT NOT NULL,
  domain TEXT NOT NULL,
  actor_id TEXT,
  target TEXT,
  details TEXT
);
`;
