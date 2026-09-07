CREATE TABLE benchmark_rows (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE benchmark_rows ENABLE ROW LEVEL SECURITY;
CREATE POLICY benchmark_workspace_scope ON benchmark_rows
  USING (workspace_id = current_setting('app.workspace_id', true)::uuid);
