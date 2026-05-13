package collector

import "testing"

func TestDecideWebLogResumePlanAppendsFromLastOffset(t *testing.T) {
	source := webLogSourceCandidate{ID: "sha256:source", Path: `C:\inetpub\logs\LogFiles\W3SVC1\u_ex260421.log`}
	current := webLogFileState{
		FileIdentity: "vol:1-file:2",
		Size:         4096,
		ModifiedAt:   "2026-04-21T12:02:00Z",
		TailHash:     "tail:new",
	}
	previous := webLogResumeState{
		SourceID:     "sha256:source",
		FileIdentity: "vol:1-file:2",
		Size:         1024,
		LastOffset:   1024,
		TailHash:     "tail:old",
	}

	plan := decideWebLogResumePlan(source, current, previous, 10*1024*1024)

	if plan.Mode != webLogResumeModeAppend {
		t.Fatalf("expected append mode, got %#v", plan)
	}
	if plan.StartOffset != 1024 {
		t.Fatalf("expected start offset 1024, got %#v", plan)
	}
}

func TestDecideWebLogResumePlanFallsBackToTailOnShrink(t *testing.T) {
	source := webLogSourceCandidate{ID: "sha256:source", Path: `C:\inetpub\logs\LogFiles\W3SVC1\u_ex260421.log`}
	current := webLogFileState{
		FileIdentity: "vol:1-file:2",
		Size:         512,
		ModifiedAt:   "2026-04-21T12:02:00Z",
		TailHash:     "tail:new",
	}
	previous := webLogResumeState{
		SourceID:     "sha256:source",
		FileIdentity: "vol:1-file:2",
		Size:         1024,
		LastOffset:   1024,
		TailHash:     "tail:old",
	}

	plan := decideWebLogResumePlan(source, current, previous, 256)

	if plan.Mode != webLogResumeModeTail {
		t.Fatalf("expected tail mode, got %#v", plan)
	}
	if plan.Reason != "file_shrunk" {
		t.Fatalf("expected file_shrunk reason, got %#v", plan)
	}
	if plan.StartOffset != 256 {
		t.Fatalf("expected tail start offset 256, got %#v", plan.StartOffset)
	}
}

func TestDecideWebLogResumePlanFallsBackToTailOnIdentityChange(t *testing.T) {
	source := webLogSourceCandidate{ID: "sha256:source", Path: `C:\inetpub\logs\LogFiles\W3SVC1\u_ex260421.log`}
	current := webLogFileState{
		FileIdentity: "vol:1-file:9",
		Size:         4096,
		ModifiedAt:   "2026-04-21T12:02:00Z",
		TailHash:     "tail:new",
	}
	previous := webLogResumeState{
		SourceID:     "sha256:source",
		FileIdentity: "vol:1-file:2",
		Size:         1024,
		LastOffset:   1024,
		TailHash:     "tail:old",
	}

	plan := decideWebLogResumePlan(source, current, previous, 512)

	if plan.Mode != webLogResumeModeTail {
		t.Fatalf("expected tail mode, got %#v", plan)
	}
	if plan.Reason != "file_identity_changed" {
		t.Fatalf("expected file_identity_changed reason, got %#v", plan)
	}
	if plan.StartOffset != 3584 {
		t.Fatalf("expected tail start offset 3584, got %#v", plan.StartOffset)
	}
}

func TestDecideWebLogResumePlanUsesTailWhenStateMissing(t *testing.T) {
	source := webLogSourceCandidate{ID: "sha256:source", Path: `C:\inetpub\logs\LogFiles\W3SVC1\u_ex260421.log`}
	current := webLogFileState{
		FileIdentity: "vol:1-file:2",
		Size:         4096,
		ModifiedAt:   "2026-04-21T12:02:00Z",
		TailHash:     "tail:new",
	}

	plan := decideWebLogResumePlan(source, current, webLogResumeState{}, 512)

	if plan.Mode != webLogResumeModeTail {
		t.Fatalf("expected tail mode, got %#v", plan)
	}
	if plan.Reason != "missing_state" {
		t.Fatalf("expected missing_state reason, got %#v", plan)
	}
}
