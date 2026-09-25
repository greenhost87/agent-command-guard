package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type stagingCase struct {
	Name     string  `json:"name"`
	Command  string  `json:"command"`
	WantCode *string `json:"want_code"`
}

func TestInlineStagingFixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/inline_script_staging.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Cases []stagingCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures.Cases) == 0 {
		t.Fatal("empty fixtures")
	}
	for _, tc := range fixtures.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			code, ext, ok := extractInlineScript(tc.Command)
			if !ok {
				code, ext, ok = extractStdinHeredoc(tc.Command)
			}
			cwd := stagingWorkspace(t)
			path := stageInlineScript(tc.Command, cwd)
			if tc.WantCode == nil {
				if ok || path != "" {
					t.Fatalf("unexpected staged program %q (%s) at %q", code, ext, path)
				}
				if entries, err := os.ReadDir(cwd); err != nil || len(entries) != 0 {
					t.Fatalf("unexpected files: %v, %v", entries, err)
				}
				return
			}
			if !ok || code != *tc.WantCode {
				t.Fatalf("extracted (%q, %v), want %q", code, ok, *tc.WantCode)
			}
			if ext != ".py" && ext != ".js" && ext != ".ts" || !strings.HasSuffix(path, ext) {
				t.Fatalf("extension = %q, path = %q", ext, path)
			}
			assertStaged(t, tc.Command, cwd, "original command was not run; Saved inline code to "+path, *tc.WantCode)
		})
	}
}

var stagedPathPattern = regexp.MustCompile(`\.codex/tmp-scripts/inline-[0-9a-f]{32}\.(js|py|ts)`)

func assertStaged(t *testing.T, command, cwd, message, code string) string {
	t.Helper()
	path := stagedPathPattern.FindString(message)
	if path == "" || !strings.Contains(message, "original command was not run") {
		t.Fatalf("missing staged path in denial: %q", message)
	}
	if strings.Contains(message, command) || strings.Contains(message, code) {
		t.Fatalf("denial repeats inline code: %q", message)
	}
	absolute := filepath.Join(cwd, path)
	info, err := os.Stat(absolute)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %o, want 600", info.Mode().Perm())
	}
	data, err := os.ReadFile(absolute)
	if err != nil || string(data) != code {
		t.Fatalf("file content = %q, err = %v, want %q", data, err, code)
	}
	return path
}

func stagingWorkspace(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCodexStagesInlineScriptAndPreservesDenial(t *testing.T) {
	cwd := stagingWorkspace(t)
	command := `node -e 'require("fs").writeFileSync("sentinel", "unexpected")'`
	body, err := json.Marshal(map[string]any{"tool_name": "functions.exec_command", "tool_input": map[string]string{"cmd": command}, "cwd": cwd})
	if err != nil {
		t.Fatal(err)
	}
	out, code := runGuard(t, body)
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	var response struct {
		HookSpecificOutput struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out, &response); err != nil {
		t.Fatal(err)
	}
	if response.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("decision = %q", response.HookSpecificOutput.PermissionDecision)
	}
	assertStaged(t, command, cwd, response.HookSpecificOutput.PermissionDecisionReason, `require("fs").writeFileSync("sentinel", "unexpected")`)
	if _, err := os.Stat(filepath.Join(cwd, "sentinel")); !os.IsNotExist(err) {
		t.Fatalf("inline program was executed: %v", err)
	}
}

func TestPythonHeredocIsStagedAndStillDenied(t *testing.T) {
	cwd := stagingWorkspace(t)
	command := "python3 - <<'PY'\nfrom pathlib import Path\nprint(Path.cwd())\nPY"
	reason := evaluateShellCommandInCwd(command, cwd)
	if reason != stdinInterpreterReason {
		t.Fatalf("reason = %q, want stdin interpreter denial", reason)
	}
	message := shellDenialMessage(command, cwd, reason)
	path := assertStaged(t, command, cwd, message, "from pathlib import Path\nprint(Path.cwd())\n")
	if !strings.Contains(message, "Saved interpreter code to "+path) {
		t.Fatalf("missing staged-file guidance: %q", message)
	}
}

func TestBunAndRtkInterpreterCodeIsStagedAndDenied(t *testing.T) {
	cwd := stagingWorkspace(t)
	for _, tc := range []struct {
		command, wantCode string
	}{
		{command: `rtk bun -e 'console.log("ok")'`, wantCode: `console.log("ok")`},
		{command: "rtk proxy bun - <<'TS'\nconsole.log(1)\nTS", wantCode: "console.log(1)\n"},
	} {
		reason := evaluateShellCommandInCwd(tc.command, cwd)
		if reason == "" {
			t.Fatalf("expected denial for %q", tc.command)
		}
		message := shellDenialMessage(tc.command, cwd, reason)
		assertStaged(t, tc.command, cwd, message, tc.wantCode)
	}
}

func TestPythonHeredocStagingRejectsUnsafeOrUnclearCommands(t *testing.T) {
	cwd := stagingWorkspace(t)
	for _, command := range []string{
		"python3 - <<PY\nprint(1)\nPY",
		"python3 - <<'PY'\nprint(1)\nPY\nrm -rf /",
		"python3 - <<-'PY'\nprint(1)\nPY",
		"python3 - <<'PY'\nprint(1)",
		"python3 script.py <<'PY'\nprint(1)\nPY",
	} {
		if path := stageInlineScript(command, cwd); path != "" {
			t.Errorf("unsafe or unclear heredoc staged at %q: %q", path, command)
		}
	}
}

func TestCursorStagesInlineScript(t *testing.T) {
	cwd := stagingWorkspace(t)
	command := `python3 -c 'print(1)'`
	body, err := json.Marshal(map[string]string{"hook_event_name": "beforeShellExecution", "command": command, "cwd": cwd})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := runGuard(t, body)
	var response struct {
		Permission   string `json:"permission"`
		UserMessage  string `json:"user_message"`
		AgentMessage string `json:"agent_message"`
	}
	if err := json.Unmarshal(out, &response); err != nil {
		t.Fatal(err)
	}
	if response.Permission != "deny" || response.AgentMessage != response.UserMessage {
		t.Fatalf("unexpected cursor response: %s", out)
	}
	assertStaged(t, command, cwd, response.AgentMessage, "print(1)")
}

func TestInlineStagingFailsClosed(t *testing.T) {
	for _, tt := range []struct {
		name, setup, cwd string
	}{
		{name: "empty cwd"},
		{name: "relative cwd", cwd: "workspace"},
		{name: "missing workspace", cwd: filepath.Join(stagingWorkspace(t), "missing")},
		{name: "symlink workspace", setup: "workspace"},
		{name: "symlink audit parent", setup: "codex"},
		{name: "symlink audit directory", setup: "tmp-scripts"},
		{name: "audit directory is file", setup: "file"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cwd := tt.cwd
			if cwd == "" && tt.setup != "" {
				cwd = filepath.Join(stagingWorkspace(t), "workspace")
				switch tt.setup {
				case "workspace":
					if err := os.Symlink(t.TempDir(), cwd); err != nil {
						t.Fatal(err)
					}
				case "codex":
					if err := os.Mkdir(cwd, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(t.TempDir(), filepath.Join(cwd, ".codex")); err != nil {
						t.Fatal(err)
					}
				case "tmp-scripts", "file":
					if err := os.MkdirAll(filepath.Join(cwd, ".codex"), 0o700); err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(cwd, ".codex", "tmp-scripts")
					if tt.setup == "file" {
						if err := os.WriteFile(path, nil, 0o600); err != nil {
							t.Fatal(err)
						}
					} else if err := os.Symlink(t.TempDir(), path); err != nil {
						t.Fatal(err)
					}
				}
			}
			if path := stageInlineScript(`node -e 'console.log(1)'`, cwd); path != "" {
				t.Fatalf("unexpected staged path %q", path)
			}
		})
	}
}

func TestInlineStagingRejectsNUL(t *testing.T) {
	if _, _, ok := extractInlineScript("node -e 'console.log(1)\x00'"); ok {
		t.Fatal("NUL-containing shell command cannot be staged")
	}
}

func TestInlineStagingUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write to read-only directories")
	}
	cwd := stagingWorkspace(t)
	dir := filepath.Join(cwd, ".codex", "tmp-scripts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	command := `node -e 'console.log(1)'`
	if path := stageInlineScript(command, cwd); path != "" {
		t.Fatalf("staged into read-only directory: %q", path)
	}
	if message := shellDenialMessage(command, cwd, inlineInterpreterReason); strings.Contains(message, "Saved inline code") {
		t.Fatalf("false success in denial: %q", message)
	}
}

func TestInlineStagingRetainsUniqueAuditFiles(t *testing.T) {
	cwd := stagingWorkspace(t)
	first := stageInlineScript(`node -e 'console.log(1)'`, cwd)
	second := stageInlineScript(`node -e 'console.log(1)'`, cwd)
	if first == "" || second == "" || first == second {
		t.Fatalf("staged paths = %q, %q; want distinct files", first, second)
	}
	for _, path := range []string{first, second} {
		data, err := os.ReadFile(filepath.Join(cwd, path))
		if err != nil || string(data) != "console.log(1)" {
			t.Fatalf("file %s = %q, %v", path, data, err)
		}
	}
}

func TestInlineStagingSkipsOtherDenials(t *testing.T) {
	cwd := stagingWorkspace(t)
	for _, command := range []string{`node -p '1+1'`, `node -e "$CODE"`, `python3 -c 'print(1)' && true`, `node -e 'console.log("agent-transcripts")'`} {
		reason := evaluateShellCommandInCwd(command, cwd)
		if reason == "" {
			t.Fatalf("expected denial for %q", command)
		}
		if strings.Contains(shellDenialMessage(command, cwd, reason), "Saved inline code to") {
			t.Fatalf("staged unsupported command %q", command)
		}
	}
	if entries, err := os.ReadDir(cwd); err != nil || len(entries) != 0 {
		t.Fatalf("unexpected files for unsupported denials: %v, %v", entries, err)
	}
}
