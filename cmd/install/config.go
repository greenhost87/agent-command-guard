// Command install installs and configures agent-command-guard hooks.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const usage = `Usage: install.sh [options]

Install agent-command-guard hooks for Codex / Cursor / Pi.

Options:
  --codex         Wire Codex (~/.codex/hooks.json -> ~/.agent-command-guard/agent-command-guard)
  --cursor        Wire Cursor (~/.cursor/hooks.json -> ~/.agent-command-guard/agent-command-guard)
  --pi            Install Pi adapter to ~/.agent-command-guard/pi and wire ~/.pi/agent/settings.json
  --prefix <path> Ignored (compat with bootstrap)
  --version <ver> Ignored unless used via curl|bash bootstrap
  --wire-only     Only wire hooks (requires existing build/agent-command-guard)
  --local-build   Alias for default source build
  -h, --help      Show this help

When no harness flag is given: wire all (non-TTY) or prompt (TTY).
Canonical binary is always ~/.agent-command-guard/agent-command-guard (where logs live).
Codex/Cursor hooks point there; Pi extension resolves binary via that path.
`

type args struct {
	codex    bool
	cursor   bool
	pi       bool
	wireOnly bool
	help     bool
}

func parseArgs(argv []string) (args, error) {
	var out args
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch a {
		case "--codex":
			out.codex = true
		case "--cursor":
			out.cursor = true
		case "--pi":
			out.pi = true
		case "--wire-only":
			out.wireOnly = true
		case "--local-build":
		case "--prefix":
			i++
		case "--version":
			i++
		case "-h", "--help":
			out.help = true
		default:
			return out, fmt.Errorf("unexpected argument %q", a)
		}
	}
	return out, nil
}

func isTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func promptHarness() (args, error) {
	fmt.Print("Wire which harnesses? [all/codex/cursor/pi] (default: all): ")
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return args{}, err
	}
	v := strings.TrimSpace(strings.ToLower(line))
	switch v {
	case "codex":
		return args{codex: true}, nil
	case "cursor":
		return args{cursor: true}, nil
	case "pi":
		return args{pi: true}, nil
	default:
		return args{codex: true, cursor: true, pi: true}, nil
	}
}

func findRepoRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return wd
		}
		dir = parent
	}
}

func runBuild(repoRoot string) error {
	cmd := exec.Command("sh", "./scripts/build.sh")
	cmd.Dir = repoRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func buildBinary(repoRoot string, wireOnly bool) (string, error) {
	out := filepath.Join(repoRoot, "build/agent-command-guard")
	if wireOnly {
		if _, err := os.Stat(out); err != nil {
			return "", fmt.Errorf("wire-only requires existing %s (run ./scripts/build.sh first)", out)
		}
		return out, nil
	}
	if err := runBuild(repoRoot); err != nil {
		return "", err
	}
	if _, err := os.Stat(out); err != nil {
		return "", fmt.Errorf("build did not produce %s", out)
	}
	return out, nil
}

func installHook(src, destDir string) (string, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(destDir, "agent-command-guard")
	data, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(dest, data, 0o755); err != nil {
		return "", err
	}
	_ = os.Chmod(dest, 0o755)
	fmt.Printf("Installed hook: %s\n", dest)
	return dest, nil
}

func readJSON(path string) map[string]interface{} {
	b, err := os.ReadFile(path)
	if err != nil {
		return map[string]interface{}{}
	}
	var v map[string]interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return map[string]interface{}{}
	}
	if v == nil {
		return map[string]interface{}{}
	}
	return v
}

func writeJSONAtomic(path string, data map[string]interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	existing, err := os.ReadFile(path)
	hasExisting := err == nil
	nextBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	next := string(nextBytes) + "\n"
	if hasExisting && string(existing) == next {
		_ = os.Remove(tmp)
		fmt.Printf("Unchanged %s\n", path)
		return nil
	}
	if hasExisting {
		now := time.Now()
		date := now.Format("20060102")
		millis := now.UnixMilli()
		bak := fmt.Sprintf("%s.bak.%s%d.%d", path, date, millis, os.Getpid())
		if b, err := os.ReadFile(path); err == nil {
			_ = os.WriteFile(bak, b, 0o644)
		}
	}
	if err := os.WriteFile(tmp, []byte(next), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	fmt.Printf("Configured %s\n", path)
	return nil
}
