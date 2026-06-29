package store

import "testing"

func TestLatestMigrationVersionControlIncludesExitNodeApprovals(t *testing.T) {
	version, err := LatestMigrationVersion("control")
	if err != nil {
		t.Fatalf("LatestMigrationVersion failed: %v", err)
	}
	if version != "0006_control_exit_node_approvals" {
		t.Fatalf("unexpected latest control migration %q", version)
	}
}
