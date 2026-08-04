package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

const broadWorkspaceSearchReason = "Blocked unconstrained workspace search. Set path to a specific file or directory, or use a glob that includes a directory or filename. Language-wide globs such as `*.ts` or `*.{ts,js}` over the whole repository are not allowed."

type cursorHookFields struct {
	eventName      string
	command        string
	filePath       string
	toolName       string
	cwd            string
	workspaceRoots []string
	toolInput      []byte
}

type cursorSearchInput struct {
	path            string
	glob            string
	globPattern     string
	targetDirectory string
}

func handleCursor(body []byte) bool {
	fields := parseCursorHook(body)
	switch fields.eventName {
	case "beforeShellExecution":
		if fields.command != "" {
			if reason := evaluateShellCommandInCwd(fields.command, fields.cwd); reason != "" {
				denyCursor(fields.command, reason)
				logHookDecision(body, "cursor", false)
				return true
			}
		}
		allowCursor()
		logHookDecision(body, "cursor", true)
		return true
	case "beforeReadFile", "beforeTabFileRead":
		if strings.Contains(fields.filePath, agentTranscriptsMarker) {
			denyCursorMessage(agentTranscriptsReason)
			logHookDecision(body, "cursor", false)
			return true
		}
		if reason := evaluateAgentQualityGateAccess(fields.filePath, fields.cwd); reason != "" {
			denyCursorMessage(reason)
			logHookDecision(body, "cursor", false)
			return true
		}
		allowCursor()
		logHookDecision(body, "cursor", true)
		return true
	case "preToolUse":
		if bytesContainAgentTranscripts(fields.toolInput) {
			denyCursorMessage(agentTranscriptsReason)
			logHookDecision(body, "cursor", false)
			return true
		}
		if reason := evaluateAgentQualityGateAccess(string(fields.toolInput), fields.cwd); reason != "" {
			denyCursorMessage(reason)
			logHookDecision(body, "cursor", false)
			return true
		}
		if reason := evaluateCursorSearch(fields.toolName, parseCursorSearchInput(fields.toolInput), fields.cwd, fields.workspaceRoots); reason != "" {
			denyCursorMessage(reason)
			logHookDecision(body, "cursor", false)
			return true
		}
		allowCursor()
		logHookDecision(body, "cursor", true)
		return true
	default:
		return false
	}
}

func cursorToolBaseName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if index := strings.LastIndex(lower, "."); index >= 0 {
		return lower[index+1:]
	}
	return lower
}

func isCursorSearchTool(name string) bool {
	switch cursorToolBaseName(name) {
	case "grep", "glob":
		return true
	default:
		return false
	}
}

func isBroadGlob(glob string) bool {
	normalized := strings.TrimSpace(strings.ReplaceAll(glob, "\\", "/"))
	if normalized == "" {
		return true
	}
	for strings.HasPrefix(normalized, "**/") {
		normalized = strings.TrimPrefix(normalized, "**/")
	}
	if normalized == "*" || normalized == "**" || normalized == "" {
		return true
	}
	return strings.HasPrefix(normalized, "*.") && !strings.Contains(normalized, "/")
}

func isUnconstrainedSearchRoot(path, cwd string, workspaceRoots []string) bool {
	trimmed := strings.TrimSpace(strings.ReplaceAll(path, "\\", "/"))
	if trimmed == "" || trimmed == "." || trimmed == "./" || trimmed == "/" {
		return true
	}
	cleaned := filepath.Clean(trimmed)
	if cwd != "" && cleaned == filepath.Clean(cwd) {
		return true
	}
	for _, root := range workspaceRoots {
		if root != "" && cleaned == filepath.Clean(root) {
			return true
		}
	}
	return false
}

func evaluateCursorSearch(toolName string, input cursorSearchInput, cwd string, workspaceRoots []string) string {
	if !isCursorSearchTool(toolName) {
		return ""
	}
	selector := input.globPattern
	if selector == "" {
		selector = input.glob
	}
	root := input.path
	if root == "" {
		root = input.targetDirectory
	}
	if !isUnconstrainedSearchRoot(root, cwd, workspaceRoots) {
		return ""
	}
	if isBroadGlob(selector) {
		return broadWorkspaceSearchReason
	}
	return ""
}

func bytesContainAgentTranscripts(data []byte) bool {
	return bytes.Contains(data, []byte(agentTranscriptsMarker))
}

func parseCursorHook(data []byte) cursorHookFields {
	var fields cursorHookFields
	index := skipJSONSpace(data, 0)
	if index >= len(data) || data[index] != '{' {
		return fields
	}
	index++
	for {
		index = skipJSONSpace(data, index)
		if index >= len(data) || data[index] == '}' {
			return fields
		}
		key, next, ok := scanJSONString(data, index)
		if !ok {
			return cursorHookFields{}
		}
		index = skipJSONSpace(data, next)
		if index >= len(data) || data[index] != ':' {
			return cursorHookFields{}
		}
		valueStart := skipJSONSpace(data, index+1)
		valueEnd, ok := skipJSONValue(data, valueStart)
		if !ok {
			return cursorHookFields{}
		}
		switch key {
		case "hook_event_name":
			if value, _, ok := scanJSONString(data, valueStart); ok {
				fields.eventName = value
			}
		case "command":
			if value, _, ok := scanJSONString(data, valueStart); ok {
				fields.command = value
			}
		case "file_path":
			if value, _, ok := scanJSONString(data, valueStart); ok {
				fields.filePath = value
			}
		case "tool_name":
			if value, _, ok := scanJSONString(data, valueStart); ok {
				fields.toolName = value
			}
		case "cwd":
			if value, _, ok := scanJSONString(data, valueStart); ok {
				fields.cwd = value
			}
		case "workspace_roots":
			if values, _, ok := scanJSONStringArray(data, valueStart); ok {
				fields.workspaceRoots = values
			}
		case "tool_input":
			fields.toolInput = data[valueStart:valueEnd]
		}
		index = skipJSONSpace(data, valueEnd)
		if index < len(data) && data[index] == ',' {
			index++
			continue
		}
		if index < len(data) && data[index] == '}' {
			return fields
		}
		return cursorHookFields{}
	}
}

func parseCursorSearchInput(data []byte) cursorSearchInput {
	var fields cursorSearchInput
	index := skipJSONSpace(data, 0)
	if index >= len(data) || data[index] != '{' {
		return fields
	}
	index++
	for {
		index = skipJSONSpace(data, index)
		if index >= len(data) || data[index] == '}' {
			return fields
		}
		key, next, ok := scanJSONString(data, index)
		if !ok {
			return cursorSearchInput{}
		}
		index = skipJSONSpace(data, next)
		if index >= len(data) || data[index] != ':' {
			return cursorSearchInput{}
		}
		valueStart := skipJSONSpace(data, index+1)
		valueEnd, ok := skipJSONValue(data, valueStart)
		if !ok {
			return cursorSearchInput{}
		}
		switch key {
		case "path", "file_path":
			if value, _, ok := scanJSONString(data, valueStart); ok {
				fields.path = value
			}
		case "glob":
			if value, _, ok := scanJSONString(data, valueStart); ok {
				fields.glob = value
			}
		case "globPattern", "glob_pattern":
			if value, _, ok := scanJSONString(data, valueStart); ok {
				fields.globPattern = value
			}
		case "target_directory", "targetDirectory":
			if value, _, ok := scanJSONString(data, valueStart); ok {
				fields.targetDirectory = value
			}
		}
		index = skipJSONSpace(data, valueEnd)
		if index < len(data) && data[index] == ',' {
			index++
			continue
		}
		if index < len(data) && data[index] == '}' {
			return fields
		}
		return cursorSearchInput{}
	}
}

func scanJSONStringArray(data []byte, index int) ([]string, int, bool) {
	index = skipJSONSpace(data, index)
	if index >= len(data) || data[index] != '[' {
		return nil, index, false
	}
	index++
	var values []string
	for {
		index = skipJSONSpace(data, index)
		if index >= len(data) {
			return nil, index, false
		}
		if data[index] == ']' {
			return values, index + 1, true
		}
		value, next, ok := scanJSONString(data, index)
		if !ok {
			return nil, index, false
		}
		values = append(values, value)
		index = skipJSONSpace(data, next)
		if index < len(data) && data[index] == ',' {
			index++
			continue
		}
		if index < len(data) && data[index] == ']' {
			return values, index + 1, true
		}
		return nil, index, false
	}
}

func allowCursor() {
	_, _ = os.Stdout.WriteString(`{"permission":"allow"}` + "\n")
}

func denyCursor(commandText, reason string) {
	denyCursorMessage(denialMessage(commandText, reason))
}

func denyCursorMessage(message string) {
	encoded := make([]byte, 0, len(message)*2+80)
	encoded = append(encoded, `{"permission":"deny","user_message":`...)
	encoded = appendJSONString(encoded, message)
	encoded = append(encoded, `,"agent_message":`...)
	encoded = appendJSONString(encoded, message)
	encoded = append(encoded, "}\n"...)
	_, _ = os.Stdout.Write(encoded)
}
