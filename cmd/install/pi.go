package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
	data := readJSON(settingsPath)
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
	return writeJSONAtomic(settingsPath, data)
}
