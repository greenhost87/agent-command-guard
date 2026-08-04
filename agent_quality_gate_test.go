package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvaluateAgentQualityGateAccess(t *testing.T) {
	tests := []struct {
		name string
		text string
		cwd  string
		want string
	}{
		{
			name: "tilde path outside project",
			text: "cat ~/.agent-quality-gate/config.json",
			cwd:  "/tmp/other",
			want: agentQualityGateReason,
		},
		{
			name: "absolute home path outside project",
			text: "cat /Users/me/.agent-quality-gate/state.db",
			cwd:  "/Users/me/develop/ai/other",
			want: agentQualityGateReason,
		},
		{
			name: "allowed inside project cwd",
			text: "cat ~/.agent-quality-gate/config.json",
			cwd:  "/Users/me/develop/ai/agent-quality-gate",
			want: "",
		},
		{
			name: "project path without home dir is fine",
			text: "cat /Users/me/develop/ai/agent-quality-gate/README.md",
			cwd:  "/tmp",
			want: "",
		},
		{
			name: "empty cwd blocks home dir access",
			text: "ls /Users/me/.agent-quality-gate",
			cwd:  "",
			want: agentQualityGateReason,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateAgentQualityGateAccess(tt.text, tt.cwd)
			if got != tt.want {
				t.Fatalf("evaluateAgentQualityGateAccess(%q, %q) = %q, want %q", tt.text, tt.cwd, got, tt.want)
			}
		})
	}
}

func TestEvaluateShellCommandBlocksAgentQualityGateWithoutCwd(t *testing.T) {
	got := evaluateShellCommand("cat ~/.agent-quality-gate/config.json")
	if got != agentQualityGateReason {
		t.Fatalf("evaluateShellCommand = %q, want %q", got, agentQualityGateReason)
	}
	got = evaluateShellCommandInCwd("cat ~/.agent-quality-gate/config.json", "/repo/agent-quality-gate")
	if got != "" {
		t.Fatalf("evaluateShellCommandInCwd allowed cwd = %q, want empty", got)
	}
}

func TestCursorBeforeShellExecutionDeniesAgentQualityGateOutsideProject(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"beforeShellExecution",
		"command":"cat ~/.agent-quality-gate/config.json",
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
	if !strings.Contains(response.UserMessage, agentQualityGateReason) {
		t.Fatalf("user_message = %q, want agent-quality-gate denial", response.UserMessage)
	}
	if response.AgentMessage != response.UserMessage {
		t.Fatalf("agent_message = %q, want same as user_message %q", response.AgentMessage, response.UserMessage)
	}
}

func TestCursorBeforeShellExecutionAllowsAgentQualityGateInsideProject(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"beforeShellExecution",
		"command":"cat ~/.agent-quality-gate/config.json",
		"cwd":"/Users/me/develop/ai/agent-quality-gate"
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

func TestCursorBeforeReadFileDeniesAgentQualityGateOutsideProject(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"beforeReadFile",
		"file_path":"/Users/me/.agent-quality-gate/config.json",
		"cwd":"/tmp"
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
		t.Fatalf("invalid cursor hook response %q: %v", stdout, err)
	}
	if response.Permission != "deny" {
		t.Fatalf("permission = %q, want deny", response.Permission)
	}
	if response.UserMessage != agentQualityGateReason {
		t.Fatalf("user_message = %q, want %q", response.UserMessage, agentQualityGateReason)
	}
}

func TestCursorBeforeReadFileAllowsAgentQualityGateInsideProject(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"beforeReadFile",
		"file_path":"/Users/me/.agent-quality-gate/config.json",
		"cwd":"/Users/me/develop/ai/agent-quality-gate"
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

func TestCursorPreToolUseDeniesAgentQualityGateOutsideProject(t *testing.T) {
	payload := []byte(`{
		"hook_event_name":"preToolUse",
		"tool_name":"Read",
		"cwd":"/tmp",
		"tool_input":{"path":"/Users/me/.agent-quality-gate/config.json"}
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
	if response.UserMessage != agentQualityGateReason {
		t.Fatalf("user_message = %q, want %q", response.UserMessage, agentQualityGateReason)
	}
}

func TestCodexPreToolUseDeniesAgentQualityGateOutsideProject(t *testing.T) {
	payload := []byte(`{
		"cwd":"/tmp/other",
		"tool_name":"Bash",
		"tool_input":{"command":"cat ~/.agent-quality-gate/config.json"}
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	var response struct {
		HookSpecificOutput struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(stdout, &response); err != nil {
		t.Fatalf("invalid codex deny response %q: %v", stdout, err)
	}
	if response.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("permissionDecision = %q, want deny", response.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(response.HookSpecificOutput.PermissionDecisionReason, agentQualityGateReason) {
		t.Fatalf("permissionDecisionReason = %q, want agent-quality-gate denial", response.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestCodexPreToolUseAllowsAgentQualityGateInsideProject(t *testing.T) {
	payload := []byte(`{
		"cwd":"/Users/me/develop/ai/agent-quality-gate",
		"tool_name":"Bash",
		"tool_input":{"command":"cat ~/.agent-quality-gate/config.json"}
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	if len(stdout) != 0 {
		t.Fatalf("stdout = %q, want empty allow", stdout)
	}
}

func TestExtractPayloadReadsCwd(t *testing.T) {
	body := []byte(`{"cwd":"/repo/agent-quality-gate","tool_name":"Bash","tool_input":{"command":"true"}}`)
	got := extractPayload(body)
	if got.Cwd != "/repo/agent-quality-gate" {
		t.Fatalf("Cwd = %q, want /repo/agent-quality-gate", got.Cwd)
	}
	if got.ToolName != "Bash" {
		t.Fatalf("ToolName = %q, want Bash", got.ToolName)
	}
}
