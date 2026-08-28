package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParsePolicyConfigRejectsMalformedJSON(t *testing.T) {
	tests := []string{
		`{"protected_paths":[]`,
		`{"protected_paths":[]} trailing`,
		`{"protected_paths":[],}`,
		`{"unknown":"\q"}`,
		`{"unknown":01}`,
	}
	for _, input := range tests {
		if _, ok := parsePolicyConfig([]byte(input)); ok {
			t.Fatalf("parsePolicyConfig(%q) succeeded, want failure", input)
		}
	}
}

func TestParsePolicyConfigPreservesExplicitEmptySlice(t *testing.T) {
	overlay, ok := parsePolicyConfig([]byte(`{"protected_paths":[]}`))
	if !ok {
		t.Fatal("parsePolicyConfig rejected valid overlay")
	}
	if overlay.ProtectedPaths == nil || len(overlay.ProtectedPaths) != 0 {
		t.Fatalf("ProtectedPaths = %#v, want non-nil empty slice", overlay.ProtectedPaths)
	}
}

func TestLoadMergedPolicyConfigRejectsPartialOverlay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"protected_paths":[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ACG_POLICY_CONFIG", path)

	config, protectedPaths := loadMergedPolicyConfig()
	if len(config.ProtectedPaths) == 0 {
		t.Fatal("malformed overlay cleared embedded protected paths")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	abs = filepath.Clean(abs)
	canonical, err := filepath.EvalSymlinks(abs)
	expected := []string{abs}
	if err == nil {
		canonical = filepath.Clean(canonical)
		if canonical != abs {
			expected = append(expected, canonical)
		}
	}
	if !reflect.DeepEqual(protectedPaths, expected) {
		t.Fatalf("protected paths = %#v, want %#v", protectedPaths, expected)
	}
}

func TestOverlaySymlinkAliasAndTargetAreProtected(t *testing.T) {
	tempDir := t.TempDir()
	target := filepath.Join(tempDir, "policy.json")
	alias := filepath.Join(tempDir, "policy-link.json")
	if err := os.WriteFile(target, []byte(`{"protected_paths":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ACG_POLICY_CONFIG", alias)

	config, protectedPaths := loadMergedPolicyConfig()
	aliasAbs, err := filepath.Abs(alias)
	if err != nil {
		t.Fatalf("Abs alias: %v", err)
	}
	aliasAbs = filepath.Clean(aliasAbs)
	canonical, err := filepath.EvalSymlinks(aliasAbs)
	expected := []string{aliasAbs}
	if err == nil {
		canonical = filepath.Clean(canonical)
		if canonical != aliasAbs {
			expected = append(expected, canonical)
		}
	}
	if !reflect.DeepEqual(protectedPaths, expected) {
		t.Fatalf("protected paths = %#v, want %#v", protectedPaths, expected)
	}
	originalPolicy := policy
	policy = buildPolicySets(config, protectedPaths...)
	t.Cleanup(func() { policy = originalPolicy })

	for _, path := range protectedPaths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if reason := evaluateShellCommandInCwd("cat > "+path, "/tmp/other-project"); !strings.Contains(reason, "policy configuration") {
				t.Fatalf("shell write to %q reason = %q", path, reason)
			}
			patch := "*** Update File: " + path + "\n"
			if reason := detectPatchDeleteReasonInCwd(patch, "/tmp/other-project"); !strings.Contains(reason, "policy configuration") {
				t.Fatalf("patch write to %q reason = %q", path, reason)
			}
		})
	}
}
