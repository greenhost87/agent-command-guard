package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCodexPreToolUseDenyShapeUnchanged(t *testing.T) {
	payload := []byte(`{
		"tool_name":"functions.exec_command",
		"tool_input":{"cmd":"node -e \"console.log(1)\""}
	}`)
	stdout, exitCode := runGuard(t, payload)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	var response struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
		Permission string `json:"permission"`
	}
	if err := json.Unmarshal(stdout, &response); err != nil {
		t.Fatalf("invalid codex hook response %q: %v", stdout, err)
	}
	if response.Permission != "" {
		t.Fatalf("top-level permission = %q, want empty for Codex shape", response.Permission)
	}
	if response.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Fatalf("hookEventName = %q, want PreToolUse", response.HookSpecificOutput.HookEventName)
	}
	if response.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("permissionDecision = %q, want deny", response.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(response.HookSpecificOutput.PermissionDecisionReason, "Blocked inline interpreter code") {
		t.Fatalf("permissionDecisionReason = %q", response.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestDetectBlockReasonBlocksCommandSubstitution(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		wantSubstr string
	}{
		{name: "backtick python", command: "echo `python3 -c 'print(1)'`", wantSubstr: "Blocked inline interpreter code"},
		{name: "dollar-paren node", command: `echo $(node -e "console.log(1)")`, wantSubstr: "Blocked inline interpreter code"},
		{name: "backticks inside double quotes", command: "echo \"pre `python3 -c 'print(1)'` post\"", wantSubstr: "Blocked inline interpreter code"},
		{name: "dollar-paren inside double quotes", command: `echo "x=$(python3 -c 'print(1)') y"`, wantSubstr: "Blocked inline interpreter code"},
		{name: "nested dollar-paren", command: "echo $(echo $(node -e 'console.log(1)'))", wantSubstr: "Blocked inline interpreter code"},
		{name: "backtick inside dollar-paren", command: "echo $(echo `python3 -c 'print(1)'`)", wantSubstr: "Blocked inline interpreter code"},
		{name: "dollar-paren inside backticks", command: "echo `$(node -e 'console.log(1)')`", wantSubstr: "Blocked inline interpreter code"},
		{name: "substitution mid-command", command: "git commit -m \"bump $(python3 -c 'print(1)')\"", wantSubstr: "Blocked inline interpreter code"},

		{name: "backticks in single quotes are literal", command: "echo '`python3 -c \"print(1)\"`'", wantSubstr: ""},
		{name: "escaped backticks", command: "echo \"use \\`rm\\` carefully\"", wantSubstr: ""},
		{name: "empty backticks", command: "echo ``", wantSubstr: ""},
		{name: "benign dollar-paren", command: `echo "$(git log -1)"`, wantSubstr: ""},
		{name: "benign backtick date", command: "echo \"built at `date +%Y`\"", wantSubstr: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertBlockReason(t, tt.command, tt.wantSubstr)
		})
	}
}

func assertBlockReason(t *testing.T, command, wantSubstr string) {
	t.Helper()
	got := detectBlockReason(command)
	if wantSubstr == "" {
		if got != "" {
			t.Fatalf("detectBlockReason(%q) = %q, want empty", command, got)
		}
		return
	}
	if !strings.Contains(got, wantSubstr) {
		t.Fatalf("detectBlockReason(%q) = %q, want substring %q", command, got, wantSubstr)
	}
}

func TestDetectBlockReasonDeepSubstitutionNestingTerminates(_ *testing.T) {
	// 64 levels exceeds maxSubstitutionDepth (32) — must terminate quickly via depth cap.
	command := strings.Repeat("$(", 64) + "true" + strings.Repeat(")", 64)
	_ = detectBlockReason(command)
}

func TestTouchesExternalPathParentTraversal(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{name: "bare dotdot", token: "..", want: true},
		{name: "dotdot slash prefix", token: "../secrets", want: true},
		{name: "embedded dotdot", token: "foo/../bar", want: true},
		{name: "trailing dotdot", token: "foo/..", want: true},
		{name: "double traversal", token: "foo/../..", want: true},
		{name: "plain relative path", token: "src/main.go", want: false},
		{name: "filename containing dots", token: "...", want: false},
		{name: "single dot", token: ".", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := touchesExternalPath(tt.token); got != tt.want {
				t.Fatalf("touchesExternalPath(%q) = %v, want %v", tt.token, got, tt.want)
			}
		})
	}
}

func TestProtectedConfigPathPatchAndShell(t *testing.T) {
	outside := "/tmp/other-project"
	inside := "/Users/me/develop/ai/agent-command-guard"
	tests := []struct {
		name    string
		command string
		cwd     string
		want    bool
	}{
		{name: "rm outside", command: "rm config/policy.json", cwd: outside, want: true},
		{name: "rm inside", command: "rm config/policy.json", cwd: inside, want: false},
		{name: "add file outside", command: "*** Add File: config/policy.json\n+x\n", cwd: outside, want: true},
		{name: "add file inside", command: "*** Add File: config/policy.json\n+x\n", cwd: inside, want: false},
		{name: "update file outside", command: "*** Update File: config/policy.json\n", cwd: outside, want: true},
		{name: "delete file outside", command: "*** Delete File: config/policy.json\n", cwd: outside, want: true},
		{name: "add unrelated outside", command: "*** Add File: README.md\n+x\n", cwd: outside, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			if strings.HasPrefix(strings.TrimSpace(tt.command), "***") {
				got = detectPatchDeleteReasonInCwd(tt.command, tt.cwd)
			} else {
				got = evaluateShellCommandInCwd(tt.command, tt.cwd)
			}
			blocked := got != ""
			if blocked != tt.want {
				t.Fatalf("cwd=%q cmd=%q blocked=%v reason=%q wantBlocked=%v", tt.cwd, tt.command, blocked, got, tt.want)
			}
			if tt.want && !strings.Contains(got, "policy configuration") {
				t.Fatalf("reason %q missing policy configuration marker", got)
			}
		})
	}
}

func TestCwdMatchesProjectRoot(t *testing.T) {
	tests := []struct {
		cwd      string
		rootName string
		want     bool
	}{
		{cwd: "/repo/agent-command-guard", rootName: "agent-command-guard", want: true},
		{cwd: "/repo/agent-command-guard-copy", rootName: "agent-command-guard", want: false},
		{cwd: "/repo/prefix-agent-quality-gate", rootName: "agent-quality-gate", want: false},
		{cwd: "/repo/agent-quality-gate/subdir", rootName: "agent-quality-gate", want: false},
		{cwd: "agent-command-guard", rootName: "agent-command-guard", want: false},
	}
	for _, tt := range tests {
		if got := cwdMatchesProjectRoot(tt.cwd, tt.rootName); got != tt.want {
			t.Errorf("cwdMatchesProjectRoot(%q, %q) = %v, want %v", tt.cwd, tt.rootName, got, tt.want)
		}
	}
}
