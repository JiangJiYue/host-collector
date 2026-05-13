package localcli

import (
	"reflect"
	"testing"
)

func TestResolveScopeAppliesExcludeAfterInclude(t *testing.T) {
	options := Options{
		Include: "host,process,network",
		Exclude: "network",
		Days:    14,
	}

	resolved, err := Resolve(options)
	if err != nil {
		t.Fatalf("resolve options: %v", err)
	}

	if !reflect.DeepEqual(resolved.Include, []string{"host", "process", "network"}) {
		t.Fatalf("unexpected include: %#v", resolved.Include)
	}
	if !reflect.DeepEqual(resolved.Exclude, []string{"network"}) {
		t.Fatalf("unexpected exclude: %#v", resolved.Exclude)
	}
	if !reflect.DeepEqual(resolved.Scope, []string{"host", "process"}) {
		t.Fatalf("unexpected effective scope: %#v", resolved.Scope)
	}
	if resolved.Days != 14 {
		t.Fatalf("unexpected days: %d", resolved.Days)
	}
}

func TestResolveDefaultsDaysToSevenAndRejectsUnsupportedDays(t *testing.T) {
	resolved, err := Resolve(Options{})
	if err != nil {
		t.Fatalf("resolve defaults: %v", err)
	}
	if resolved.Days != 7 {
		t.Fatalf("expected default days=7, got %d", resolved.Days)
	}

	for _, days := range []int{1, 15, 60} {
		if _, err := Resolve(Options{Days: days}); err == nil {
			t.Fatalf("expected days=%d to fail", days)
		}
	}
}
