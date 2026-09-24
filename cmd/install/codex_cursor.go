package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func codexHookEntryContainsGuard(entry interface{}) bool {
	mapped, ok := entry.(map[string]interface{})
	if !ok {
		return false
	}
	hooks, ok := mapped["hooks"].([]interface{})
	if !ok {
		return false
	}
	for _, hook := range hooks {
		mappedHook, ok := hook.(map[string]interface{})
		if !ok {
			continue
		}
		command, ok := mappedHook["command"].(string)
		if ok && strings.Contains(command, "agent-command-guard") {
			return true
		}
	}
	return false
}

func wireCodex(installedPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	hooksJSON := filepath.Join(home, ".codex/hooks.json")
	data := readJSON(hooksJSON)
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
	filtered := make([]interface{}, 0, len(lst))
	for _, entry := range lst {
		if !codexHookEntryContainsGuard(entry) {
			filtered = append(filtered, entry)
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
	return writeJSONAtomic(hooksJSON, data)
}

func wireCursor(installedPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	hooksJSON := filepath.Join(home, ".cursor/hooks.json")
	data := readJSON(hooksJSON)
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
	return writeJSONAtomic(hooksJSON, data)
}
