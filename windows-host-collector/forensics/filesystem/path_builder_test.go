package filesystem

import "testing"

func TestRebuildPathsBuildsHierarchy(t *testing.T) {
	rows := []RawEntry{
		{VolumeID: "vol-1", MFTEntry: 5, ParentMFTEntry: 5, Name: "", IsDirectory: true},
		{VolumeID: "vol-1", MFTEntry: 10, ParentMFTEntry: 5, Name: "Users", IsDirectory: true},
		{VolumeID: "vol-1", MFTEntry: 11, ParentMFTEntry: 10, Name: "alice", IsDirectory: true},
		{VolumeID: "vol-1", MFTEntry: 12, ParentMFTEntry: 11, Name: "note.txt", IsDirectory: false},
	}

	got := RebuildPaths(rows)
	if len(got) != 4 {
		t.Fatalf("expected 4 rows, got %d", len(got))
	}

	file := got[3]
	if file.Path != `\Users\alice\note.txt` {
		t.Fatalf("expected reconstructed file path, got %q", file.Path)
	}
	if file.ParentPath != `\Users\alice` {
		t.Fatalf("expected reconstructed parent path, got %q", file.ParentPath)
	}
	if file.Extension != ".txt" {
		t.Fatalf("expected .txt extension, got %q", file.Extension)
	}
	if file.IsOrphan {
		t.Fatal("expected non-orphan entry")
	}
}

func TestRebuildPathMarksOrphanWhenParentMissing(t *testing.T) {
	rows := []RawEntry{
		{VolumeID: "vol-1", MFTEntry: 42, ParentMFTEntry: 777, Name: "orphan.txt", IsDirectory: false},
	}

	got := RebuildPaths(rows)
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if !got[0].IsOrphan {
		t.Fatalf("expected orphan flag to be true")
	}
	if got[0].Path == "" {
		t.Fatal("expected orphan path to be reconstructed")
	}
}

func TestRebuildPathsKeepsUniqueKeysWithoutVolumeID(t *testing.T) {
	rows := []RawEntry{
		{MFTEntry: 1, ParentMFTEntry: 1, Name: "", IsDirectory: true},
		{MFTEntry: 2, ParentMFTEntry: 1, Name: "alpha.txt", IsDirectory: false},
		{MFTEntry: 3, ParentMFTEntry: 1, Name: "beta.txt", IsDirectory: false},
	}

	got := RebuildPaths(rows)
	if len(got) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(got))
	}
	if got[1].EntryID == got[2].EntryID {
		t.Fatalf("expected unique entry ids, got %q", got[1].EntryID)
	}
	if got[1].Path != `\alpha.txt` {
		t.Fatalf("expected alpha path, got %q", got[1].Path)
	}
	if got[2].Path != `\beta.txt` {
		t.Fatalf("expected beta path, got %q", got[2].Path)
	}
}

func TestBuildPathMarksInternalNTFSObjectsWithoutTreatingThemAsOrphan(t *testing.T) {
	rows := []RawEntry{
		{VolumeID: "vol:c", MFTEntry: 5, ParentMFTEntry: 5, Name: "", IsDirectory: true},
		{VolumeID: "vol:c", MFTEntry: 24, ParentMFTEntry: 5, Name: ".", IsDirectory: true},
		{VolumeID: "vol:c", MFTEntry: 42, ParentMFTEntry: 24, Name: "$Extend", IsDirectory: true},
		{VolumeID: "vol:c", MFTEntry: 43, ParentMFTEntry: 42, Name: "$UsnJrnl", IsDirectory: false},
	}

	got := RebuildPaths(rows)
	if len(got) != 4 {
		t.Fatalf("expected 4 rows, got %d", len(got))
	}

	internal := got[2]
	if internal.Path != `\.\$Extend` {
		t.Fatalf("expected internal ntfs path, got %q", internal.Path)
	}
	if internal.IsOrphan {
		t.Fatalf("internal ntfs objects should not be orphan just for being internal: %#v", internal)
	}
	if !internal.IsInternalNTFSObject {
		t.Fatalf("expected internal ntfs object flag for %#v", internal)
	}

	stream := got[3]
	if stream.IsOrphan {
		t.Fatalf("expected nested internal ntfs object not to be orphan: %#v", stream)
	}
	if !stream.IsInternalNTFSObject {
		t.Fatalf("expected nested internal ntfs object flag for %#v", stream)
	}
}

func TestBuildPathStillMarksTrulyUnresolvedRowsAsOrphan(t *testing.T) {
	rows := []RawEntry{
		{VolumeID: "vol:c", MFTEntry: 42, ParentMFTEntry: 777, Name: "$Extend", IsDirectory: true},
	}

	got := RebuildPaths(rows)
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if !got[0].IsOrphan {
		t.Fatalf("expected unresolved row to remain orphan: %#v", got[0])
	}
	if !got[0].PathReconstructionFailed {
		t.Fatalf("expected unresolved row to report path reconstruction failure: %#v", got[0])
	}
}
