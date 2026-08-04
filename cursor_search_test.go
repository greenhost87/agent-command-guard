package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func decodeCursorPermission(t *testing.T, stdout []byte) (permission, message string) {
	t.Helper()
	var response struct {
		Permission   string `json:"permission"`
		UserMessage  string `json:"user_message"`
		AgentMessage string `json:"agent_message"`
	}
	if err := json.Unmarshal(stdout, &response); err != nil {
		t.Fatalf("invalid cursor hook response %q: %v", stdout, err)
	}
	if response.AgentMessage != response.UserMessage {
		t.Fatalf("agent_message = %q, want same as user_message %q", response.AgentMessage, response.UserMessage)
	}
	return response.Permission, response.UserMessage
}

func TestCursorPreToolUseDeniesLanguageWideGrepWithoutPath(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"preToolUse",
		"tool_name":"grep",
		"cwd":"/Users/me/project",
		"workspace_roots":["/Users/me/project"],
		"tool_input":{"pattern":"events","glob":"*.{md,ts,sql}","headLimit":50}
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	permission, message := decodeCursorPermission(t, stdout)
	if permission != "deny" {
		t.Fatalf("permission = %q, want deny", permission)
	}
	if message != broadWorkspaceSearchReason {
		t.Fatalf("user_message = %q, want %q", message, broadWorkspaceSearchReason)
	}
}

func TestCursorPreToolUseDeniesRepoWideGrepWithoutGlob(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"preToolUse",
		"tool_name":"Grep",
		"cwd":"/Users/me/project",
		"tool_input":{"pattern":"JSONB|jsonb","head_limit":40}
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	permission, message := decodeCursorPermission(t, stdout)
	if permission != "deny" {
		t.Fatalf("permission = %q, want deny", permission)
	}
	if !strings.Contains(message, "unconstrained workspace search") {
		t.Fatalf("user_message = %q, want unconstrained search denial", message)
	}
}

func TestCursorPreToolUseDeniesExtensionOnlyGlob(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"preToolUse",
		"tool_name":"glob",
		"cwd":"/Users/me/project",
		"tool_input":{"globPattern":"**/*.{ts,js}"}
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	permission, _ := decodeCursorPermission(t, stdout)
	if permission != "deny" {
		t.Fatalf("permission = %q, want deny", permission)
	}
}

func TestCursorPreToolUseDeniesGrepWhenPathIsWorkspaceRoot(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"preToolUse",
		"tool_name":"grep",
		"cwd":"/Users/me/project",
		"workspace_roots":["/Users/me/project"],
		"tool_input":{"pattern":"events","path":"/Users/me/project","glob":"*.ts"}
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	permission, _ := decodeCursorPermission(t, stdout)
	if permission != "deny" {
		t.Fatalf("permission = %q, want deny", permission)
	}
}

func TestCursorPreToolUseAllowsNamedFileGlob(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"preToolUse",
		"tool_name":"Glob",
		"cwd":"/Users/me/project",
		"tool_input":{"globPattern":"architecture.md"}
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	permission, _ := decodeCursorPermission(t, stdout)
	if permission != "allow" {
		t.Fatalf("permission = %q, want allow", permission)
	}
}

func TestCursorPreToolUseAllowsDirectoryPrefixedGrepGlob(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"preToolUse",
		"tool_name":"grep",
		"cwd":"/Users/me/project",
		"tool_input":{"pattern":"sessionHistory","glob":"system/agents/**/*.ts"}
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	permission, _ := decodeCursorPermission(t, stdout)
	if permission != "allow" {
		t.Fatalf("permission = %q, want allow", permission)
	}
}

func TestCursorPreToolUseAllowsGrepInSpecificPath(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"preToolUse",
		"tool_name":"grep",
		"cwd":"/Users/me/project",
		"tool_input":{"pattern":"events","path":"architecture.md"}
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	permission, _ := decodeCursorPermission(t, stdout)
	if permission != "allow" {
		t.Fatalf("permission = %q, want allow", permission)
	}
}

func TestCursorPreToolUseAllowsGlobInTargetDirectory(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"preToolUse",
		"tool_name":"glob",
		"cwd":"/Users/me/project",
		"tool_input":{"glob_pattern":"*.ts","target_directory":"system/agents"}
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	permission, _ := decodeCursorPermission(t, stdout)
	if permission != "allow" {
		t.Fatalf("permission = %q, want allow", permission)
	}
}

func TestCursorPreToolUseAllowsGrepWhenFilePathIsSpecificFile(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"preToolUse",
		"tool_name":"Grep",
		"cwd":"/Users/me/project",
		"workspace_roots":["/Users/me/project"],
		"tool_input":{"pattern":"evaluateCursorSearch","file_path":"/Users/me/project/cursor.go"}
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	permission, _ := decodeCursorPermission(t, stdout)
	if permission != "allow" {
		t.Fatalf("permission = %q, want allow", permission)
	}
}

func TestCursorPreToolUseAllowsGlobEmittedAsGrepWithFilePath(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"preToolUse",
		"tool_name":"Grep",
		"cwd":"/Users/me/project",
		"workspace_roots":["/Users/me/project"],
		"tool_input":{"pattern":"","file_path":"/Users/me/project/scripts","glob":"**/*.sh","output_mode":"files_with_matches"}
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	permission, _ := decodeCursorPermission(t, stdout)
	if permission != "allow" {
		t.Fatalf("permission = %q, want allow", permission)
	}
}

func TestCursorPreToolUseDeniesGrepWhenFilePathIsWorkspaceRoot(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"preToolUse",
		"tool_name":"Grep",
		"cwd":"/Users/me/project",
		"workspace_roots":["/Users/me/project"],
		"tool_input":{"pattern":"events","file_path":"/Users/me/project","glob":"*.ts"}
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	permission, _ := decodeCursorPermission(t, stdout)
	if permission != "deny" {
		t.Fatalf("permission = %q, want deny", permission)
	}
}
