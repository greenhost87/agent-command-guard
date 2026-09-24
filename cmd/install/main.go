package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func printPiInstructions(bin, repoRoot string) {
	home, _ := os.UserHomeDir()
	piDir := filepath.Join(home, ".agent-command-guard/pi")
	fmt.Printf("Pi: extension -> %s (spawns %s)\n", filepath.Join(piDir, "extension.ts"), bin)
	fmt.Printf("  dev fallback: %s\n", filepath.Join(repoRoot, "adapters/pi/extension.ts"))
}

func selectedArgs(a args) (args, error) {
	if a.codex || a.cursor || a.pi {
		return a, nil
	}
	if !isTTY() {
		return args{codex: true, cursor: true, pi: true, wireOnly: a.wireOnly}, nil
	}
	selected, err := promptHarness()
	selected.wireOnly = a.wireOnly
	return selected, err
}

func wireSelected(selected args, canonical, repoRoot string) (bool, error) {
	didAny := false
	if selected.codex {
		if err := wireCodex(canonical); err != nil {
			return false, err
		}
		didAny = true
	}
	if selected.cursor {
		if err := wireCursor(canonical); err != nil {
			return false, err
		}
		didAny = true
	}
	if selected.pi {
		piDir, err := installPiAdapter(repoRoot)
		if err != nil {
			return false, fmt.Errorf("pi adapter: %w", err)
		}
		if err := wirePi(piDir); err != nil {
			return false, fmt.Errorf("wire pi: %w", err)
		}
		printPiInstructions(canonical, repoRoot)
		fmt.Printf("Pi wired: %s -> %s\n", piDir, canonical)
		didAny = true
	}
	return didAny, nil
}

func runInstall() error {
	a, err := parseArgs(os.Args[1:])
	if err != nil {
		return err
	}
	if a.help {
		fmt.Print(usage)
		return nil
	}
	selected, err := selectedArgs(a)
	if err != nil {
		return err
	}
	repoRoot := findRepoRoot()
	bin, err := buildBinary(repoRoot, selected.wireOnly)
	if err != nil {
		return err
	}
	canonical, err := installCanonicalHook(bin)
	if err != nil {
		return fmt.Errorf("canonical hook: %w", err)
	}
	didAny, err := wireSelected(selected, canonical, repoRoot)
	if err != nil {
		return err
	}
	if !didAny {
		fmt.Println("Nothing wired. Use --codex / --cursor / --pi")
	}
	fmt.Printf("\nVerify: printf '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"true\"}}' | %s; echo $?\n", canonical)
	fmt.Println("Uninstall: rm ~/.agent-command-guard/agent-command-guard; rm -rf ~/.agent-command-guard/pi (and edit ~/.codex/hooks.json ~/.cursor/hooks.json ~/.pi/agent/settings.json)")
	return nil
}

func main() {
	if err := runInstall(); err != nil {
		fmt.Fprintf(os.Stderr, "install: %v\n", err)
		os.Exit(1)
	}
}
