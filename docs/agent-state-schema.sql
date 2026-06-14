pragma foreign_keys = on;

create table if not exists agent_schema_migrations (
  version integer primary key,
  name text not null,
  applied_at text not null default (datetime('now'))
);

create table if not exists agent_memories (
  id text primary key,
  project_key text not null,
  scope text not null default 'project',
  memory_type text not null,
  title text not null,
  summary text not null default '',
  content text not null,
  tags_json text not null default '[]',
  source_ref text not null default '',
  confidence real not null default 1.0,
  status text not null default 'active',
  created_at text not null default (datetime('now')),
  updated_at text not null default (datetime('now')),
  last_used_at text,
  closed_at text
);

create index if not exists idx_agent_memories_project_status
  on agent_memories(project_key, status, memory_type);

create table if not exists agent_long_tasks (
  id text primary key,
  project_key text not null,
  title text not null,
  objective text not null,
  status text not null default 'init',
  priority integer not null default 100,
  owner text not null default 'codex',
  current_phase text not null default 'Init',
  context_summary text not null default '',
  constraints_json text not null default '[]',
  success_criteria_json text not null default '[]',
  risk_json text not null default '[]',
  created_at text not null default (datetime('now')),
  updated_at text not null default (datetime('now')),
  started_at text,
  resumed_at text,
  reviewed_at text,
  closed_at text
);

create index if not exists idx_agent_long_tasks_project_status
  on agent_long_tasks(project_key, status, priority);

create table if not exists agent_long_task_steps (
  id text primary key,
  task_id text not null references agent_long_tasks(id) on delete cascade,
  step_order integer not null default 0,
  phase text not null,
  title text not null,
  status text not null default 'pending',
  detail text not null default '',
  result_summary text not null default '',
  evidence_refs_json text not null default '[]',
  created_at text not null default (datetime('now')),
  updated_at text not null default (datetime('now')),
  completed_at text
);

create index if not exists idx_agent_long_task_steps_task
  on agent_long_task_steps(task_id, status, step_order);

create table if not exists agent_issues (
  id text primary key,
  task_id text references agent_long_tasks(id) on delete cascade,
  project_key text not null,
  issue_type text not null,
  severity text not null default 'normal',
  title text not null,
  detail text not null default '',
  status text not null default 'open',
  blocker boolean not null default 0,
  evidence_refs_json text not null default '[]',
  created_at text not null default (datetime('now')),
  updated_at text not null default (datetime('now')),
  resolved_at text
);

create table if not exists agent_sessions (
  id text primary key,
  project_key text not null,
  task_id text references agent_long_tasks(id) on delete set null,
  session_kind text not null default 'work',
  status text not null default 'active',
  started_at text not null default (datetime('now')),
  ended_at text,
  start_summary text not null default '',
  end_summary text not null default '',
  git_head_start text not null default '',
  git_head_end text not null default '',
  changed_files_json text not null default '[]'
);

create table if not exists agent_events (
  id text primary key,
  project_key text not null,
  task_id text references agent_long_tasks(id) on delete cascade,
  session_id text references agent_sessions(id) on delete set null,
  event_type text not null,
  phase text not null default '',
  summary text not null,
  payload_json text not null default '{}',
  created_at text not null default (datetime('now'))
);

create table if not exists agent_artifacts (
  id text primary key,
  task_id text references agent_long_tasks(id) on delete cascade,
  project_key text not null,
  artifact_type text not null,
  path text not null,
  description text not null default '',
  status text not null default 'active',
  created_at text not null default (datetime('now')),
  updated_at text not null default (datetime('now'))
);

insert or ignore into agent_schema_migrations(version, name)
values (1, 'agent memory and long task base schema');
