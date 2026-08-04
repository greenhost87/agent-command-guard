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

func readJson(path string) map[string]interface{} {
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

func writeJsonAtomic(path string, data map[string]interface{}) error {
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

func wireCodex(installedPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	hooksJSON := filepath.Join(home, ".codex/hooks.json")
	data := readJson(hooksJSON)
	hooksRaw, ok := data["hooks"]
	var hooks map[string]interface{}
	if ok {
		if m, ok := hooksRaw.(map[string]interface{}); ok {
			hooks = m
		}
	}
	if hooks == nil {
		hooks = map[string]interface{}{}
		data["hooks"] = hooks
	}
	var lst []interface{}
	if raw, ok := hooks["PreToolUse"]; ok {
		if arr, ok := raw.([]interface{}); ok {
			lst = arr
		}
	}
	// drop any previous agent-command-guard hook (canonical or legacy tilde path)
	filtered := make([]interface{}, 0, len(lst))
	for _, e := range lst {
		em, ok := e.(map[string]interface{})
		if !ok {
			filtered = append(filtered, e)
			continue
		}
		hooksArr, ok := em["hooks"].([]interface{})
		if !ok {
			filtered = append(filtered, e)
			continue
		}
		skip := false
		for _, h := range hooksArr {
			if hm, ok := h.(map[string]interface{}); ok {
				if cmd, ok := hm["command"].(string); ok && strings.Contains(cmd, "agent-command-guard") {
					skip = true
					break
				}
			}
		}
		if !skip {
			filtered = append(filtered, e)
		}
	}
	filtered = append(filtered, map[string]interface{}{
		"matcher": "*",
		"hooks": []interface{}{
			map[string]interface{}{
				"type":          "command",
				"command":       installedPath,
				"timeout":       5,
				"statusMessage": "Checking shell command policy",
			},
		},
	})
	hooks["PreToolUse"] = filtered
	return writeJsonAtomic(hooksJSON, data)
}

func wireCursor(installedPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	hooksJSON := filepath.Join(home, ".cursor/hooks.json")
	data := readJson(hooksJSON)
	if data == nil {
		return fmt.Errorf("cursor hooks.json invalid")
	}
	if _, ok := data["version"]; !ok {
		data["version"] = 1
	}
	hooksRaw, ok := data["hooks"]
	var hooks map[string]interface{}
	if ok {
		if m, ok := hooksRaw.(map[string]interface{}); ok {
			hooks = m
		}
	}
	if hooks == nil {
		hooks = map[string]interface{}{}
		data["hooks"] = hooks
	}
	entry := map[string]interface{}{
		"command":    installedPath,
		"failClosed": true,
	}
	for _, key := range []string{"beforeShellExecution", "preToolUse", "beforeReadFile", "beforeTabFileRead"} {
		var lst []interface{}
		if raw, ok := hooks[key]; ok {
			if arr, ok := raw.([]interface{}); ok {
				lst = arr
			}
		}
		filtered := make([]interface{}, 0, len(lst))
		for _, e := range lst {
			if em, ok := e.(map[string]interface{}); ok {
				if cmd, ok := em["command"].(string); ok && strings.Contains(cmd, "agent-command-guard") {
					continue
				}
			}
			filtered = append(filtered, e)
		}
		filtered = append(filtered, entry)
		hooks[key] = filtered
	}
	return writeJsonAtomic(hooksJSON, data)
}

func installCanonicalHook(bin string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return installHook(bin, filepath.Join(home, ".agent-command-guard"))
}

func installPiAdapter(repoRoot string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	piDir := filepath.Join(home, ".agent-command-guard/pi")
	if err := os.MkdirAll(piDir, 0o755); err != nil {
		return "", err
	}
	for _, name := range []string{"extension.ts", "package.json"} {
		src := filepath.Join(repoRoot, "adapters/pi", name)
		dst := filepath.Join(piDir, name)
		data, err := os.ReadFile(src)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", src, err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return "", err
		}
	}
	fmt.Printf("Installed Pi adapter: %s\n", piDir)
	return piDir, nil
}

func wirePi(piDir string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	settingsPath := filepath.Join(home, ".pi/agent/settings.json")
	data := readJson(settingsPath)
	// Ensure packages is a slice
	raw, hasPackages := data["packages"]
	var pkgs []interface{}
	if hasPackages {
		if arr, ok := raw.([]interface{}); ok {
			pkgs = arr
		}
	}
	// Remove legacy dev entries that pointed at agent-command-guard source
	filtered := make([]interface{}, 0, len(pkgs))
	for _, p := range pkgs {
		s, ok := p.(string)
		if !ok {
			filtered = append(filtered, p)
			continue
		}
		if s == piDir {
			filtered = append(filtered, p)
			continue
		}
		if strings.Contains(s, "agent-command-guard") {
			// drop legacy dev paths; will re-add canonical
			continue
		}
		filtered = append(filtered, p)
	}
	// Add canonical piDir if missing
	hasCanonical := false
	for _, p := range filtered {
		if s, ok := p.(string); ok && s == piDir {
			hasCanonical = true
			break
		}
	}
	if !hasCanonical {
		filtered = append(filtered, piDir)
	}
	data["packages"] = filtered
	return writeJsonAtomic(settingsPath, data)
}

func printPiInstructions(bin, repoRoot string) {
	home, _ := os.UserHomeDir()
	piDir := filepath.Join(home, ".agent-command-guard/pi")
	fmt.Printf("Pi: extension -> %s (spawns %s)\n", filepath.Join(piDir, "extension.ts"), bin)
	fmt.Printf("  dev fallback: %s\n", filepath.Join(repoRoot, "adapters/pi/extension.ts"))
}

func main() {
	a, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "install: %v\n", err)
		os.Exit(1)
	}
	if a.help {
		fmt.Print(usage)
		return
	}
	selected := a
	noFlag := !a.codex && !a.cursor && !a.pi
	if noFlag && isTTY() {
		sel, err := promptHarness()
		if err != nil {
			fmt.Fprintf(os.Stderr, "install: %v\n", err)
			os.Exit(1)
		}
		sel.wireOnly = a.wireOnly
		selected = sel
	} else if noFlag {
		selected = args{codex: true, cursor: true, pi: true, wireOnly: a.wireOnly}
	}

	repoRoot := findRepoRoot()
	bin, err := buildBinary(repoRoot, selected.wireOnly)
	if err != nil {
		fmt.Fprintf(os.Stderr, "install: %v\n", err)
		os.Exit(1)
	}

	didAny := false

	// Canonical binary is the source of truth (same dir as logs)
	canonical, err := installCanonicalHook(bin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "install: canonical hook: %v\n", err)
		os.Exit(1)
	}
	if selected.codex {
		if err := wireCodex(canonical); err != nil {
			fmt.Fprintf(os.Stderr, "install: %v\n", err)
			os.Exit(1)
		}
		didAny = true
	}
	if selected.cursor {
		if err := wireCursor(canonical); err != nil {
			fmt.Fprintf(os.Stderr, "install: %v\n", err)
			os.Exit(1)
		}
		didAny = true
	}
	if selected.pi {
		piDir, err := installPiAdapter(repoRoot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "install: pi adapter: %v\n", err)
			os.Exit(1)
		}
		if err := wirePi(piDir); err != nil {
			fmt.Fprintf(os.Stderr, "install: wire pi: %v\n", err)
			os.Exit(1)
		}
		printPiInstructions(canonical, repoRoot)
		fmt.Printf("Pi wired: %s -> %s\n", piDir, canonical)
		didAny = true
	}
	if !didAny {
		fmt.Println("Nothing wired. Use --codex / --cursor / --pi")
	}
	fmt.Printf("\nVerify: printf '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"true\"}}' | %s; echo $?\n", canonical)
	fmt.Println("Uninstall: rm ~/.agent-command-guard/agent-command-guard; rm -rf ~/.agent-command-guard/pi (and edit ~/.codex/hooks.json ~/.cursor/hooks.json ~/.pi/agent/settings.json)")
}
