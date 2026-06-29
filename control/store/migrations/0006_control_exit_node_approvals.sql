CREATE TABLE IF NOT EXISTS control_exit_node_approvals (
	user_id     TEXT NOT NULL,
	device_id   TEXT NOT NULL,
	approved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	approved_by TEXT NOT NULL DEFAULT '',
	revoked_at  TIMESTAMPTZ NULL,
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (user_id, device_id)
);

CREATE INDEX IF NOT EXISTS control_exit_node_approvals_active_idx
	ON control_exit_node_approvals (user_id, device_id)
	WHERE revoked_at IS NULL;
