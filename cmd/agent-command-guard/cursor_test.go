package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCursorBeforeShellExecutionDeniesInlineInterpreter(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"beforeShellExecution",
		"command":"node -e \"console.log(1)\"",
		"cwd":"/tmp",
		"workspace_roots":["/tmp"]
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	var response struct {
		Permission   string `json:"permission"`
		UserMessage  string `json:"user_message"`
		AgentMessage string `json:"agent_message"`
		HookSpecific any    `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(stdout, &response); err != nil {
		t.Fatalf("invalid cursor hook response %q: %v", stdout, err)
	}
	if response.Permission != "deny" {
		t.Fatalf("permission = %q, want deny", response.Permission)
	}
	if response.HookSpecific != nil {
		t.Fatalf("hookSpecificOutput should be absent for Cursor responses, got %#v", response.HookSpecific)
	}
	if !strings.Contains(response.UserMessage, "Blocked inline interpreter code") {
		t.Fatalf("user_message = %q, want inline interpreter denial", response.UserMessage)
	}
	if response.AgentMessage != response.UserMessage {
		t.Fatalf("agent_message = %q, want same as user_message %q", response.AgentMessage, response.UserMessage)
	}
}

func TestCursorBeforeShellExecutionAllowsSafeCommand(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"beforeShellExecution",
		"command":"true",
		"cwd":"/tmp"
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	var response struct {
		Permission string `json:"permission"`
	}
	if err := json.Unmarshal(stdout, &response); err != nil {
		t.Fatalf("invalid cursor allow response %q: %v", stdout, err)
	}
	if response.Permission != "allow" {
		t.Fatalf("permission = %q, want allow", response.Permission)
	}
}

func TestParseCursorShellHookReadsBeforeShellExecution(t *testing.T) {
	body := []byte(`{
		"hook_event_name":"beforeShellExecution",
		"command":"python3 -c 'print(1)'",
		"cwd":"/workspace"
	}`)
	fields := parseCursorHook(body)
	if fields.eventName != "beforeShellExecution" {
		t.Fatalf("eventName = %q, want beforeShellExecution", fields.eventName)
	}
	if fields.command != "python3 -c 'print(1)'" {
		t.Fatalf("command = %q, want cursor top-level command", fields.command)
	}
	if fields.filePath != "" {
		t.Fatalf("filePath = %q, want empty", fields.filePath)
	}
	if len(fields.toolInput) != 0 {
		t.Fatalf("toolInput = %q, want empty", fields.toolInput)
	}
}

func TestCursorBeforeShellExecutionDeniesAgentTranscriptsSubstring(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"beforeShellExecution",
		"command":"cat /Users/me/.cursor/projects/x/agent-transcripts/abc.jsonl",
		"cwd":"/tmp"
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	var response struct {
		Permission   string `json:"permission"`
		UserMessage  string `json:"user_message"`
		AgentMessage string `json:"agent_message"`
	}
	if err := json.Unmarshal(stdout, &response); err != nil {
		t.Fatalf("invalid cursor hook response %q: %v", stdout, err)
	}
	if response.Permission != "deny" {
		t.Fatalf("permission = %q, want deny", response.Permission)
	}
	if !strings.Contains(response.UserMessage, agentTranscriptsReason) {
		t.Fatalf("user_message = %q, want agent-transcripts denial", response.UserMessage)
	}
	if response.AgentMessage != response.UserMessage {
		t.Fatalf("agent_message = %q, want same as user_message %q", response.AgentMessage, response.UserMessage)
	}
}

func TestCursorBeforeReadFileDeniesAgentTranscriptsPath(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"beforeReadFile",
		"file_path":"/Users/me/.cursor/projects/x/agent-transcripts/abc.jsonl",
		"content":"secret"
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	var response struct {
		Permission   string `json:"permission"`
		UserMessage  string `json:"user_message"`
		AgentMessage string `json:"agent_message"`
	}
	if err := json.Unmarshal(stdout, &response); err != nil {
		t.Fatalf("invalid cursor read hook response %q: %v", stdout, err)
	}
	if response.Permission != "deny" {
		t.Fatalf("permission = %q, want deny", response.Permission)
	}
	if response.UserMessage != agentTranscriptsReason {
		t.Fatalf("user_message = %q, want %q", response.UserMessage, agentTranscriptsReason)
	}
	if response.AgentMessage != agentTranscriptsReason {
		t.Fatalf("agent_message = %q, want %q", response.AgentMessage, agentTranscriptsReason)
	}
}

func TestCursorBeforeReadFileAllowsOtherPath(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"beforeReadFile",
		"file_path":"/Users/me/project/main.go",
		"content":"package main"
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	var response struct {
		Permission string `json:"permission"`
	}
	if err := json.Unmarshal(stdout, &response); err != nil {
		t.Fatalf("invalid cursor allow read response %q: %v", stdout, err)
	}
	if response.Permission != "allow" {
		t.Fatalf("permission = %q, want allow", response.Permission)
	}
}

func TestCursorBeforeTabFileReadDeniesAgentTranscriptsPath(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"beforeTabFileRead",
		"file_path":"/tmp/agent-transcripts/note.md",
		"content":"x"
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	var response struct {
		Permission string `json:"permission"`
	}
	if err := json.Unmarshal(stdout, &response); err != nil {
		t.Fatalf("invalid cursor tab read response %q: %v", stdout, err)
	}
	if response.Permission != "deny" {
		t.Fatalf("permission = %q, want deny", response.Permission)
	}
}

func TestCursorPreToolUseDeniesAgentTranscriptsInToolInput(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"preToolUse",
		"tool_name":"Read",
		"tool_input":{"path":"/Users/me/.cursor/projects/x/agent-transcripts/abc.jsonl"},
		"transcript_path":"/Users/me/.cursor/projects/x/agent-transcripts/session.jsonl"
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	var response struct {
		Permission  string `json:"permission"`
		UserMessage string `json:"user_message"`
	}
	if err := json.Unmarshal(stdout, &response); err != nil {
		t.Fatalf("invalid preToolUse deny response %q: %v", stdout, err)
	}
	if response.Permission != "deny" {
		t.Fatalf("permission = %q, want deny", response.Permission)
	}
	if response.UserMessage != agentTranscriptsReason {
		t.Fatalf("user_message = %q, want %q", response.UserMessage, agentTranscriptsReason)
	}
}

func TestCursorPreToolUseIgnoresEnvelopeTranscriptPath(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"preToolUse",
		"tool_name":"Read",
		"tool_input":{"path":"/Users/me/project/main.go"},
		"transcript_path":"/Users/me/.cursor/projects/x/agent-transcripts/session.jsonl"
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	var response struct {
		Permission string `json:"permission"`
	}
	if err := json.Unmarshal(stdout, &response); err != nil {
		t.Fatalf("invalid preToolUse allow response %q: %v", stdout, err)
	}
	if response.Permission != "allow" {
		t.Fatalf("permission = %q, want allow when only transcript_path mentions the folder", response.Permission)
	}
}

func TestCursorPreToolUseDeniesGrepAgentTranscripts(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"preToolUse",
		"tool_name":"Grep",
		"tool_input":{"pattern":"secret","path":"agent-transcripts"},
		"transcript_path":null
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	var response struct {
		Permission string `json:"permission"`
	}
	if err := json.Unmarshal(stdout, &response); err != nil {
		t.Fatalf("invalid preToolUse grep response %q: %v", stdout, err)
	}
	if response.Permission != "deny" {
		t.Fatalf("permission = %q, want deny", response.Permission)
	}
}
