package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runGuardWithLog(t *testing.T, stdin []byte, env ...string) (stdout []byte, exitCode int) {
	t.Helper()
	cmd := exec.Command(builtGuardBinary(t))
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = strings.NewReader(string(stdin))
	var stdoutBuffer, stderrBuffer strings.Builder
	cmd.Stdout = &stdoutBuffer
	cmd.Stderr = &stderrBuffer
	err := cmd.Run()
	if err == nil {
		return []byte(stdoutBuffer.String()), 0
	}
	exitError, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("run guard: %v stderr=%q", err, stderrBuffer.String())
	}
	return []byte(stdoutBuffer.String()), exitError.ExitCode()
}

func TestDailyLogFileName(t *testing.T) {
	now := time.Date(2026, 8, 22, 23, 59, 0, 0, time.FixedZone("CET", 2*3600))
	if got := dailyLogFileName(now); got != "2026-08-22-acg.jsonl" {
		t.Fatalf("dailyLogFileName() = %q, want 2026-08-22-acg.jsonl", got)
	}
}

func TestLogHookDecisionAppendsJSONLRecord(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "acg.jsonl")
	payload := []byte(`{
		"tool_name":"functions.exec_command",
		"tool_input":{"cmd":"true"}
	}`)

	_, exitCode := runGuardWithLog(t, payload, "ACG_LOG_PATH="+logPath)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	lines, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.HasSuffix(string(lines), "\n") {
		t.Fatalf("log line must end with newline: %q", lines)
	}

	var record struct {
		T int64           `json:"t"`
		S string          `json:"s"`
		C string          `json:"c"`
		D json.RawMessage `json:"d"`
	}
	if err := json.Unmarshal(bytesTrimLine(lines), &record); err != nil {
		t.Fatalf("invalid log record %q: %v", lines, err)
	}
	if record.T <= 0 {
		t.Fatalf("t = %d, want positive unix milliseconds", record.T)
	}
	if record.C != "codex" {
		t.Fatalf("c = %q, want codex", record.C)
	}
	if record.S != "+" {
		t.Fatalf("s = %q, want +", record.S)
	}

	var data map[string]any
	if err := json.Unmarshal(record.D, &data); err != nil {
		t.Fatalf("invalid d payload: %v", err)
	}
	if data["tool_name"] != "functions.exec_command" {
		t.Fatalf("d.tool_name = %#v, want functions.exec_command", data["tool_name"])
	}
}

func TestLogHookDecisionUsesIntegrationOverride(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "acg.jsonl")
	payload := []byte(`{
		"tool_name":"Bash",
		"tool_input":{"command":"true"}
	}`)

	_, exitCode := runGuardWithLog(t, payload, "ACG_LOG_PATH="+logPath, "ACG_INTEGRATION=pi")
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	lines, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	var record struct {
		C string `json:"c"`
		S string `json:"s"`
	}
	if err := json.Unmarshal(bytesTrimLine(lines), &record); err != nil {
		t.Fatalf("invalid log record %q: %v", lines, err)
	}
	if record.C != "pi" {
		t.Fatalf("c = %q, want pi", record.C)
	}
	if record.S != "+" {
		t.Fatalf("s = %q, want +", record.S)
	}
}

func TestCursorLogHookDecisionRecordsDeny(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "acg.jsonl")
	payload := []byte(`{
		"hook_event_name":"beforeShellExecution",
		"command":"node -e \"console.log(1)\"",
		"cwd":"/tmp/workspace"
	}`)

	_, exitCode := runGuardWithLog(t, payload, "ACG_LOG_PATH="+logPath)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	lines, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	var record struct {
		C string          `json:"c"`
		S string          `json:"s"`
		D json.RawMessage `json:"d"`
	}
	if err := json.Unmarshal(bytesTrimLine(lines), &record); err != nil {
		t.Fatalf("invalid log record %q: %v", lines, err)
	}
	if record.C != "cursor" {
		t.Fatalf("c = %q, want cursor", record.C)
	}
	if record.S != "-" {
		t.Fatalf("s = %q, want -", record.S)
	}

	var data map[string]any
	if err := json.Unmarshal(record.D, &data); err != nil {
		t.Fatalf("invalid d payload: %v", err)
	}
	if data["hook_event_name"] != "beforeShellExecution" {
		t.Fatalf("d.hook_event_name = %#v", data["hook_event_name"])
	}
}

func TestLogHookDecisionSkipsIgnoredNonShellTool(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "acg.jsonl")
	payload := []byte(`{
		"tool_name":"functions.read_file",
		"tool_input":{"path":"README.md"}
	}`)

	_, exitCode := runGuardWithLog(t, payload, "ACG_LOG_PATH="+logPath)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	if _, err := os.Stat(logPath); err == nil {
		t.Fatalf("log file should not be created for ignored non-shell tools")
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat log: %v", err)
	}
}

func bytesTrimLine(data []byte) []byte {
	return []byte(strings.TrimSpace(string(data)))
}
