package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

var (
	guardBinaryOnce   sync.Once
	guardBinaryPath   string
	guardBinaryErr    error
	guardBinaryOutput string
)

func builtGuardBinary(t *testing.T) string {
	t.Helper()
	guardBinaryOnce.Do(func() {
		tempDir, err := os.MkdirTemp("", "agent-command-guard-bin-*")
		if err != nil {
			guardBinaryErr = err
			return
		}
		guardBinaryPath = filepath.Join(tempDir, "agent-command-guard")
		cmd := exec.Command("go", "build", "-o", guardBinaryPath, ".")
		output, err := cmd.CombinedOutput()
		if err != nil {
			guardBinaryErr = err
			guardBinaryOutput = string(output)
			return
		}
	})
	if guardBinaryErr != nil {
		t.Fatalf("build agent-command-guard: %v\n%s", guardBinaryErr, guardBinaryOutput)
	}
	return guardBinaryPath
}

func runGuard(t *testing.T, stdin []byte) (stdout []byte, exitCode int) {
	t.Helper()
	cmd := exec.Command(builtGuardBinary(t))
	cmd.Env = append(os.Environ(), "ACG_LOG=0")
	cmd.Stdin = bytes.NewReader(stdin)
	var stdoutBuffer, stderrBuffer bytes.Buffer
	cmd.Stdout = &stdoutBuffer
	cmd.Stderr = &stderrBuffer
	err := cmd.Run()
	if err == nil {
		return stdoutBuffer.Bytes(), 0
	}
	exitError, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("run guard: %v stderr=%q", err, stderrBuffer.String())
	}
	return stdoutBuffer.Bytes(), exitError.ExitCode()
}

func TestDenyEmitsOneMessageWithFiftyCharacterCommandPreview(t *testing.T) {
	commandPrefix := strings.Repeat("a", 49) + "я"
	command := commandPrefix + "tail"
	reason := "Blocked inline interpreter code."

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStdout := os.Stdout
	os.Stdout = writer
	deny(command, reason)
	os.Stdout = originalStdout
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	responseBody, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}

	var response struct {
		SystemMessage      *string `json:"systemMessage"`
		HookSpecificOutput struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("invalid hook response %q: %v", responseBody, err)
	}
	if response.SystemMessage != nil {
		t.Fatalf("systemMessage duplicates permissionDecisionReason: %q", *response.SystemMessage)
	}
	if response.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("permissionDecision = %q, want deny", response.HookSpecificOutput.PermissionDecision)
	}
	wantReason := "Blocked shell command: " + commandPrefix + "...\n" + reason
	if response.HookSpecificOutput.PermissionDecisionReason != wantReason {
		t.Fatalf("permissionDecisionReason = %q, want %q", response.HookSpecificOutput.PermissionDecisionReason, wantReason)
	}
}

func TestShellTokensPreserveShellLikeTokenValues(t *testing.T) {
	command := "printf foo\\ bar | A=1 python3.11 -c \"print('é')\"\u00a0&& rm -rf .codex/tmp-scripts"
	var tokenBuffer [16]shellToken
	tokens := shellTokens(command, tokenBuffer[:0])
	got := make([]string, 0, len(tokens))
	for _, token := range tokens {
		got = append(got, token.value(command))
	}

	want := []string{
		"printf",
		"foo bar",
		"|",
		"A=1",
		"python3.11",
		"-c",
		"print('é')",
		"&&",
		"rm",
		"-rf",
		".codex/tmp-scripts",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shellTokens(%q) = %#v, want %#v", command, got, want)
	}
}

func BenchmarkDetectBlockReasonAllowedSimple(b *testing.B) {
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		if reason := detectBlockReason("true"); reason != "" {
			b.Fatalf("detectBlockReason returned %q", reason)
		}
	}
}

func BenchmarkDetectBlockReasonAllowedTypical(b *testing.B) {
	b.ReportAllocs()
	command := "sed -n '1,120p' /tmp/example.txt"
	for index := 0; index < b.N; index++ {
		if reason := detectBlockReason(command); reason != "" {
			b.Fatalf("detectBlockReason returned %q", reason)
		}
	}
}

func BenchmarkDetectBlockReasonDeniedNodeEval(b *testing.B) {
	b.ReportAllocs()
	command := `node -e "console.log(1)"`
	for index := 0; index < b.N; index++ {
		if reason := detectBlockReason(command); reason == "" {
			b.Fatal("detectBlockReason returned empty reason")
		}
	}
}

func BenchmarkDetectPatchDeleteReasonAllowedMention(b *testing.B) {
	b.ReportAllocs()
	command := strings.Join([]string{
		"*** Begin Patch",
		"*** Add File: .codex/tmp-scripts/example.txt",
		"+rm -rf .codex/tmp-scripts",
		"*** End Patch",
	}, "\n")
	for index := 0; index < b.N; index++ {
		if reason := detectPatchDeleteReason(command); reason != "" {
			b.Fatalf("detectPatchDeleteReason returned %q", reason)
		}
	}
}

func BenchmarkExtractCommandIgnoredNonShell(b *testing.B) {
	b.ReportAllocs()
	body := []byte(`{
		"tool_name":"web.run",
		"tool_input":{
			"open":[{"ref_id":"turn0search0"}]
		}
	}`)
	for index := 0; index < b.N; index++ {
		data := extractPayload(body)
		if data.ToolName != "web.run" {
			b.Fatalf("tool name = %q", data.ToolName)
		}
	}
}

func TestExtractCommandPreservesLegacyFieldOrder(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "command wins over cmd",
			input: `{"command":"first","cmd":"second"}`,
			want:  "first",
		},
		{
			name:  "empty command wins over cmd",
			input: `{"command":"","cmd":"second"}`,
			want:  "",
		},
		{
			name:  "non string command falls through",
			input: `{"command":1,"cmd":"second"}`,
			want:  "second",
		},
		{
			name:  "shell command fallback",
			input: `{"shell_command":"third"}`,
			want:  "third",
		},
		{
			name:  "escaped command string",
			input: `{"command":"printf \"hello\""}`,
			want:  `printf "hello"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractCommand([]byte(tt.input)); got != tt.want {
				t.Fatalf("extractCommand(%s) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsAssignmentMatchesShellEnvTokenShape(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{name: "letter", token: "A=1", want: true},
		{name: "underscore", token: "_=1", want: true},
		{name: "digits after first", token: "A1_b=two", want: true},
		{name: "empty value", token: "NAME=", want: true},
		{name: "equals inside value", token: "NAME=a=b", want: true},
		{name: "empty", token: "", want: false},
		{name: "starts with digit", token: "1A=1", want: false},
		{name: "missing equals", token: "NAME", want: false},
		{name: "invalid name char", token: "A-B=1", want: false},
		{name: "non ascii name", token: "é=1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAssignment(tt.token); got != tt.want {
				t.Fatalf("isAssignment(%q) = %v, want %v", tt.token, got, tt.want)
			}
		})
	}
}

func TestIsPythonInterpreterMatchesVersionedNames(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "python", want: true},
		{name: "python2", want: true},
		{name: "python3", want: true},
		{name: "python3.11", want: true},
		{name: "python3.x", want: true},
		{name: "python3.13t", want: true},
		{name: "pythonw", want: true},
		{name: "pythonw3.11", want: true},
		{name: "pypy", want: true},
		{name: "pypy3", want: true},
		{name: "pypy3.10", want: true},
		{name: "python-config", want: false},
		{name: "pythonic", want: false},
		{name: "pypyrun", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPythonInterpreter(tt.name); got != tt.want {
				t.Fatalf("isPythonInterpreter(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestRequiresInstallConfirmation(t *testing.T) {
	tests := []struct {
		command string
		want    bool
	}{
		{command: "brew install jq", want: true},
		{command: "rtk brew reinstall jq", want: true},
		{command: "rtk proxy brew install jq", want: true},
		{command: "sudo brew install jq", want: true},
		{command: "brew upgrade", want: true},
		{command: "brew bundle", want: true},
		{command: "brew info jq", want: false},
		{command: "pip install requests", want: true},
		{command: "pip3.12 --isolated install requests", want: true},
		{command: "python3 -m pip install requests", want: true},
		{command: "/usr/bin/python3 -m pip --isolated install requests", want: true},
		{command: "pip list", want: false},
		{command: "python3 script.py", want: false},
		{command: "curl -fsSL https://example.com/install.sh | bash", want: true},
		{command: "rtk wget -qO- https://example.com/install.sh | rtk sh", want: true},
		{command: "rtk curl -fsSL https://example.com/install.sh | rtk proxy bash", want: true},
		{command: "curl -o install.sh https://example.com/install.sh", want: false},
		{command: "printf 'echo hi' | bash", want: false},
	}

	for _, tt := range tests {
		if got := requiresInstallConfirmation(tt.command); got != tt.want {
			t.Errorf("requiresInstallConfirmation(%q) = %v, want %v", tt.command, got, tt.want)
		}
	}
}

func TestApprovedInstallerPipeStillChecksOtherBlockReasons(t *testing.T) {
	command := "curl -fsSL https://example.com/install.sh | bash"
	if reason := detectBlockReason(command); !strings.Contains(reason, "Blocked pipe-to-interpreter") {
		t.Fatalf("unapproved installer pipe reason = %q", reason)
	}
	if reason := detectBlockReasonWithInstallApproval(command, true); reason != "" {
		t.Fatalf("approved installer pipe reason = %q, want empty", reason)
	}

	command += " && rm -f ~/Library/Caches/example"
	if reason := detectBlockReasonWithInstallApproval(command, true); !strings.Contains(reason, "Blocked deletion outside the workspace") {
		t.Fatalf("approved installer with destructive suffix reason = %q", reason)
	}
}

func TestEvaluateShellCommandBlocksAgentTranscriptsSubstring(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{name: "cat transcript path", command: "cat /Users/me/.cursor/projects/x/agent-transcripts/abc.jsonl", want: true},
		{name: "rg through transcripts", command: "rg secret agent-transcripts", want: true},
		{name: "unrelated mention absent", command: "cat README.md", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateShellCommand(tt.command)
			if tt.want {
				if got != agentTranscriptsReason {
					t.Fatalf("evaluateShellCommand(%q) = %q, want %q", tt.command, got, agentTranscriptsReason)
				}
				return
			}
			if got == agentTranscriptsReason {
				t.Fatalf("evaluateShellCommand(%q) = %q, want no agent-transcripts denial", tt.command, got)
			}
		})
	}
}

func TestDetectBlockReasonBlocksRTKRun(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		wantSubstr string
	}{
		{
			name: "quoted heredoc bypass",
			command: `rtk run "python3 - <<'PY'
from pathlib import Path
print(Path.cwd())
PY"`,
			wantSubstr: "Blocked `rtk run`",
		},
		{name: "absolute executable", command: "/opt/homebrew/bin/rtk run 'printf ok'", wantSubstr: "Blocked `rtk run`"},
		{name: "shell wrapper", command: "sudo rtk run 'printf ok'", wantSubstr: "Blocked `rtk run`"},
		{name: "rtk proxy wrapper", command: "rtk proxy rtk run 'printf ok'", wantSubstr: "Blocked `rtk run`"},
		{name: "text argument", command: "printf '%s\\n' 'rtk run'", wantSubstr: ""},
		{name: "normal rtk proxy", command: "rtk proxy python3 script.py", wantSubstr: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectBlockReason(tt.command)
			if tt.wantSubstr == "" {
				if got != "" {
					t.Fatalf("detectBlockReason(%q) = %q, want empty", tt.command, got)
				}
				return
			}
			if !strings.Contains(got, tt.wantSubstr) {
				t.Fatalf("detectBlockReason(%q) = %q, want substring %q", tt.command, got, tt.wantSubstr)
			}
		})
	}
}

func TestDetectBlockReasonBlocksCaseInsensitiveCommandsThroughProxy(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		wantSubstr string
	}{
		{name: "upper rm through proxy", command: "rtk proxy RM -rf .codex/tmp-scripts", wantSubstr: "Blocked deletion of `.codex/tmp-scripts` audit scripts"},
		{name: "mixed case wrapper and rm", command: "RtK ProXY rM -rf .codex/tmp-scripts", wantSubstr: "Blocked deletion of `.codex/tmp-scripts` audit scripts"},
		{name: "pure uppercase rm", command: "RM -rf /tmp/example", wantSubstr: "Blocked deletion outside the workspace"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectBlockReason(tt.command)
			if !strings.Contains(got, tt.wantSubstr) {
				t.Fatalf("detectBlockReason(%q) = %q, want substring %q", tt.command, got, tt.wantSubstr)
			}
		})
	}
}

func TestDetectBlockReasonBlocksDestructiveGitCommands(t *testing.T) {
	tests := []struct {
		command    string
		wantSubstr string
	}{
		{command: "git reset --hard", wantSubstr: "Blocked `git reset --hard`"},
		{command: "git reset HEAD --hard", wantSubstr: "Blocked `git reset --hard`"},
		{command: "git checkout -- README.md", wantSubstr: "Blocked `git checkout --`"},
		{command: "rtk git checkout -- .", wantSubstr: "Blocked `git checkout --`"},
		{command: "printf ok && git reset --hard HEAD", wantSubstr: "Blocked `git reset --hard`"},
		{command: "git reset --soft HEAD", wantSubstr: ""},
		{command: "git checkout feature", wantSubstr: ""},
		{command: "printf '%s\\n' 'git checkout -- README.md'", wantSubstr: ""},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := detectBlockReason(tt.command)
			if tt.wantSubstr == "" {
				if got != "" {
					t.Fatalf("detectBlockReason(%q) = %q, want empty", tt.command, got)
				}
				return
			}
			if !strings.Contains(got, tt.wantSubstr) {
				t.Fatalf("detectBlockReason(%q) = %q, want substring %q", tt.command, got, tt.wantSubstr)
			}
		})
	}
}

func TestDetectBlockReasonPythonVersionAndEnvAssignments(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		wantSubstr string
	}{
		{
			name:       "python minor version inline eval",
			command:    "python3.11 -c 'print(1)'",
			wantSubstr: "Blocked inline interpreter code",
		},
		{
			name:       "python minor version through env assignment",
			command:    "env A=1 python3.11 -c 'print(1)'",
			wantSubstr: "Blocked inline interpreter code",
		},
		{
			name:       "pipe to python minor version after assignment",
			command:    "printf x | A=1 python3.11",
			wantSubstr: "Blocked pipe-to-interpreter (`| python3.11`)",
		},
		{
			name:       "non numeric python version is treated as python interpreter",
			command:    "python3.x -c 'print(1)'",
			wantSubstr: "Blocked inline interpreter code",
		},
		{
			name:       "perl combined eval flag",
			command:    "perl -we 'print 1'",
			wantSubstr: "Blocked inline interpreter code",
		},
		{
			name:       "ruby combined eval flag",
			command:    "ruby -we 'puts 1'",
			wantSubstr: "Blocked inline interpreter code",
		},
		{
			name:       "node stdin",
			command:    "node -",
			wantSubstr: "Blocked interpreter code from stdin/heredoc",
		},
		{
			name:       "git clean",
			command:    "git clean -fdx",
			wantSubstr: "Blocked `git clean`",
		},
		{
			name: "grouped rm home cache",
			command: strings.Join([]string{
				"log_file=/tmp/cleanup-colima-library.log",
				"{",
				"  rm -f ~/Library/Caches/Homebrew/api/formula/colima.json",
				"} > \"$log_file\" 2>&1",
			}, "\n"),
			wantSubstr: "Blocked deletion outside the workspace",
		},
		{
			name:       "relative rm is allowed",
			command:    "rm -f build/cache.json",
			wantSubstr: "",
		},
		{
			name:       "python combined inline flag",
			command:    "python3 -Ic 'print(1)'",
			wantSubstr: "Blocked inline interpreter code",
		},
		{
			name:       "bash combined inline flag",
			command:    "bash -lc 'echo hi'",
			wantSubstr: "Blocked inline interpreter code",
		},
		{
			name:       "pipe to perl",
			command:    "printf 'print 1\\n' | perl",
			wantSubstr: "Blocked pipe-to-interpreter (`| perl`)",
		},
		{
			name:       "pipe to ruby",
			command:    "printf 'print 1\\n' | ruby",
			wantSubstr: "Blocked pipe-to-interpreter (`| ruby`)",
		},
		{
			name:       "pipe through env to python",
			command:    "printf 'print(1)\\n' | env python3",
			wantSubstr: "Blocked pipe-to-interpreter (`| python3`)",
		},
		{
			name:       "pipe through command wrapper to python",
			command:    "printf 'print(1)\\n' | command python3",
			wantSubstr: "Blocked pipe-to-interpreter (`| python3`)",
		},
		{
			name:       "env split string inline python",
			command:    "env -S 'python3 -c print(1)'",
			wantSubstr: "Blocked `env -S` split-string",
		},
		{
			name:       "shell eval",
			command:    "eval 'python3 -c \"print(1)\"'",
			wantSubstr: "Blocked shell `eval`",
		},
		{
			name:       "nodejs inline eval",
			command:    "nodejs -e 'console.log(1)'",
			wantSubstr: "Blocked inline interpreter code",
		},
		{
			name:       "pypy inline eval",
			command:    "pypy3 -c 'print(1)'",
			wantSubstr: "Blocked inline interpreter code",
		},
		{
			name:       "deno eval",
			command:    "deno eval 'console.log(1)'",
			wantSubstr: "Blocked inline interpreter code",
		},
		{
			name:       "bun inline eval",
			command:    "bun -e 'console.log(1)'",
			wantSubstr: "Blocked inline interpreter code",
		},
		{
			name:       "php stdin",
			command:    "php <<'PHP'\n<?php echo 1;\nPHP",
			wantSubstr: "Blocked interpreter code from stdin/heredoc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectBlockReason(tt.command)
			if tt.wantSubstr == "" {
				if got != "" {
					t.Fatalf("detectBlockReason(%q) = %q, want empty", tt.command, got)
				}
				return
			}
			if !strings.Contains(got, tt.wantSubstr) {
				t.Fatalf("detectBlockReason(%q) = %q, want substring %q", tt.command, got, tt.wantSubstr)
			}
		})
	}
}

func TestDetectBlockReasonBlocksSSHAndSCP(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		wantSubstr string
	}{
		{name: "ssh", command: "ssh example.com", wantSubstr: "Blocked `ssh`"},
		{name: "scp", command: "scp artifact.tar example.com:/tmp/", wantSubstr: "Blocked `scp`"},
		{name: "absolute path", command: "/usr/bin/ssh example.com", wantSubstr: "Blocked `ssh`"},
		{name: "rtk wrapper", command: "rtk scp artifact.tar example.com:/tmp/", wantSubstr: "Blocked `scp`"},
		{name: "env wrapper", command: "env SSH_AUTH_SOCK=/tmp/agent ssh example.com", wantSubstr: "Blocked `ssh`"},
		{name: "chained command", command: "printf ok && scp artifact.tar example.com:/tmp/", wantSubstr: "Blocked `scp`"},
		{name: "text argument", command: "printf '%s\\n' 'ssh example.com'", wantSubstr: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectBlockReason(tt.command)
			if tt.wantSubstr == "" {
				if got != "" {
					t.Fatalf("detectBlockReason(%q) = %q, want empty", tt.command, got)
				}
				return
			}
			if !strings.Contains(got, tt.wantSubstr) {
				t.Fatalf("detectBlockReason(%q) = %q, want substring %q", tt.command, got, tt.wantSubstr)
			}
		})
	}
}

func TestDetectBlockReasonBlocksInteractiveInterpreters(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		wantSubstr string
	}{
		{name: "bare python PTY entry", command: "rtk python3", wantSubstr: "Blocked interactive interpreter session"},
		{name: "bare python through env", command: "env A=1 python3", wantSubstr: "Blocked interactive interpreter session"},
		{name: "python interactive flag", command: "python3 -qi", wantSubstr: "Blocked interactive interpreter session"},
		{name: "bare shell PTY entry", command: "rtk bash", wantSubstr: "Blocked interactive interpreter session"},
		{name: "bare sh", command: "sh", wantSubstr: "Blocked interactive interpreter session"},
		{name: "sh interactive flag", command: "sh -i", wantSubstr: "Blocked interactive interpreter session"},
		{name: "node interactive flag", command: "node --interactive", wantSubstr: "Blocked interactive interpreter session"},
		{name: "php interactive flag", command: "php -a", wantSubstr: "Blocked interactive interpreter session"},
		{name: "deno repl", command: "deno repl", wantSubstr: "Blocked interactive interpreter session"},
		{name: "workspace python script", command: "python3 .codex/tmp-scripts/check.py", wantSubstr: ""},
		{name: "python version", command: "python3 --version", wantSubstr: ""},
		{name: "shell script", command: "bash .codex/tmp-scripts/check.sh", wantSubstr: ""},
		{name: "sh workspace script", command: "sh .codex/tmp-scripts/check.sh", wantSubstr: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectBlockReason(tt.command)
			if tt.wantSubstr == "" {
				if got != "" {
					t.Fatalf("detectBlockReason(%q) = %q, want empty", tt.command, got)
				}
				return
			}
			if !strings.Contains(got, tt.wantSubstr) {
				t.Fatalf("detectBlockReason(%q) = %q, want substring %q", tt.command, got, tt.wantSubstr)
			}
		})
	}
}

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
			got := detectBlockReason(tt.command)
			if tt.wantSubstr == "" {
				if got != "" {
					t.Fatalf("detectBlockReason(%q) = %q, want empty", tt.command, got)
				}
				return
			}
			if !strings.Contains(got, tt.wantSubstr) {
				t.Fatalf("detectBlockReason(%q) = %q, want substring %q", tt.command, got, tt.wantSubstr)
			}
		})
	}
}

func TestDetectBlockReasonDeepSubstitutionNestingTerminates(t *testing.T) {
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
