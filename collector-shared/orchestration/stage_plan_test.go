package orchestration

import (
	"strings"
	"testing"
)

func TestScopeSetAllowsAllWhenEmpty(t *testing.T) {
	scope := NewScopeSet(nil)
	if !scope.Allows("host") || !scope.Allows("process") {
		t.Fatalf("empty scope must allow all modules")
	}
}

func TestScopeSetCanonicalizesRequestedModules(t *testing.T) {
	scope := NewScopeSet([]string{" process ", "", "host", "process"})
	if scope.Allows("network") {
		t.Fatalf("explicit scope must not allow unlisted module")
	}
	if !scope.Allows("host") || !scope.Allows("process") {
		t.Fatalf("explicit scope must allow listed modules")
	}
	if strings.Join(scope.List(), ",") != "host,process" {
		t.Fatalf("expected sorted scope list, got %#v", scope.List())
	}
}

func TestStageEnabledByScopeUsesStageModules(t *testing.T) {
	plan := StagePlan{
		Stages: []StageDefinition{
			{Key: "system", ScopeModules: []string{"host"}},
			{Key: "event_logs", ScopeModules: []string{"logs"}},
		},
	}
	scope := NewScopeSet([]string{"host"})
	if !plan.StageEnabled(scope, "system") {
		t.Fatalf("system should be enabled by host scope")
	}
	if plan.StageEnabled(scope, "event_logs") {
		t.Fatalf("event_logs should not be enabled without logs scope")
	}
	if plan.StageEnabled(scope, "missing") {
		t.Fatalf("unknown stage should not be enabled")
	}
}

func TestStageShouldRunIncludesDependencies(t *testing.T) {
	plan := StagePlan{
		Stages: []StageDefinition{
			{Key: "network", ScopeModules: []string{"network"}},
			{Key: "browser_history", ScopeModules: []string{"user_traces"}},
		},
		Dependencies: map[string][]string{
			"network": {"browser_history"},
		},
	}
	scope := NewScopeSet([]string{"network"})
	if !plan.ShouldRunStage(scope, "network") {
		t.Fatalf("network should run when directly enabled")
	}
	if !plan.ShouldRunStage(scope, "browser_history") {
		t.Fatalf("browser_history should run as network dependency")
	}
}
