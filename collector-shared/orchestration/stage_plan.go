package orchestration

import (
	"sort"
	"strings"
)

type ScopeSet struct {
	all     bool
	allowed map[string]struct{}
}

func NewScopeSet(scope []string) ScopeSet {
	if len(scope) == 0 {
		return ScopeSet{all: true}
	}
	allowed := make(map[string]struct{}, len(scope))
	for _, module := range scope {
		trimmed := strings.TrimSpace(module)
		if trimmed == "" {
			continue
		}
		allowed[trimmed] = struct{}{}
	}
	if len(allowed) == 0 {
		return ScopeSet{all: true}
	}
	return ScopeSet{allowed: allowed}
}

func (s ScopeSet) Allows(module string) bool {
	if s.all {
		return true
	}
	_, ok := s.allowed[strings.TrimSpace(module)]
	return ok
}

func (s ScopeSet) Empty() bool {
	return s.all || len(s.allowed) == 0
}

func (s ScopeSet) List() []string {
	if s.all {
		return nil
	}
	result := make([]string, 0, len(s.allowed))
	for module := range s.allowed {
		result = append(result, module)
	}
	sort.Strings(result)
	return result
}

type StageDefinition struct {
	Key          string
	ScopeModules []string
}

type StagePlan struct {
	Stages       []StageDefinition
	Dependencies map[string][]string
}

func (p StagePlan) StageEnabled(scope ScopeSet, stageKey string) bool {
	if scope.Empty() {
		return true
	}
	stage, ok := p.stage(stageKey)
	if !ok {
		return false
	}
	for _, module := range stage.ScopeModules {
		if scope.Allows(module) {
			return true
		}
	}
	return false
}

func (p StagePlan) ShouldRunStage(scope ScopeSet, stageKey string) bool {
	if p.StageEnabled(scope, stageKey) {
		return true
	}
	for dependentStageKey, dependencyStageKeys := range p.Dependencies {
		if !p.StageEnabled(scope, dependentStageKey) {
			continue
		}
		for _, dependencyStageKey := range dependencyStageKeys {
			if dependencyStageKey == stageKey {
				return true
			}
		}
	}
	return false
}

func (p StagePlan) stage(stageKey string) (StageDefinition, bool) {
	for _, stage := range p.Stages {
		if stage.Key == stageKey {
			return stage, true
		}
	}
	return StageDefinition{}, false
}
