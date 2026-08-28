package main

import (
	_ "embed"
	"os"
	"path/filepath"
	"strings"
)

//go:embed config/policy.json
var defaultPolicyJSON []byte

type interpreterPolicy struct {
	Pipe           []string `json:"pipe"`
	Node           []string `json:"node"`
	PythonPrefixes []string `json:"python_prefixes"`
	Shell          []string `json:"shell"`
}

type messagePolicy struct {
	ScriptDir               string `json:"script_dir"`
	ScriptGuidance          string `json:"script_guidance"`
	TranscriptsMarker       string `json:"transcripts_marker"`
	TranscriptsReason       string `json:"transcripts_reason"`
	QualityGateMarker       string `json:"quality_gate_marker"`
	QualityGateToken        string `json:"quality_gate_token"`
	QualityGateReason       string `json:"quality_gate_reason"`
	InteractiveReasonPrefix string `json:"interactive_reason_prefix"`
	ProtectedReason         string `json:"protected_reason"`
}

type policyConfig struct {
	Separators     []string          `json:"separators"`
	ShellKeywords  []string          `json:"shell_keywords"`
	Wrappers       []string          `json:"wrappers"`
	ShellToolNames []string          `json:"shell_tool_names"`
	PatchToolNames []string          `json:"patch_tool_names"`
	RemoteCommands []string          `json:"remote_commands"`
	Interpreters   interpreterPolicy `json:"interpreters"`
	Messages       messagePolicy     `json:"messages"`
	ScanTriggers   []string          `json:"scan_triggers"`
	ProtectedPaths []string          `json:"protected_paths"`
}

type stringSet map[string]struct{}

func (set stringSet) has(value string) bool {
	_, ok := set[value]
	return ok
}

func toStringSet(values []string) stringSet {
	set := make(stringSet, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

type policySets struct {
	separators          stringSet
	keywords            stringSet
	wrappers            stringSet
	shellTools          stringSet
	patchTools          stringSet
	remote              stringSet
	pipe                stringSet
	node                stringSet
	shell               stringSet
	pythonPrefixes      []string
	scanTriggers        []string
	protectedPaths      []string
	protectedPathsLower []string
	protectedReason     string

	scriptDir               string
	scriptGuidance          string
	inlineInterpreterReason string
	stdinInterpreterReason  string
	interactiveInterpreterR string
	transcriptsMarker       string
	transcriptsReason       string
	qualityGateMarker       string
	qualityGateToken        string
	qualityGateReason       string
}

func buildPolicySets(config *policyConfig, runtimeProtectedPaths ...string) *policySets {
	messages := config.Messages
	protectedPaths := append([]string{}, config.ProtectedPaths...)
	protectedPaths = append(protectedPaths, runtimeProtectedPaths...)
	protectedPathsLower := make([]string, len(protectedPaths))
	for index, path := range protectedPaths {
		protectedPathsLower[index] = strings.ToLower(path)
	}
	sets := &policySets{
		separators:          toStringSet(config.Separators),
		keywords:            toStringSet(config.ShellKeywords),
		wrappers:            toStringSet(config.Wrappers),
		shellTools:          toStringSet(config.ShellToolNames),
		patchTools:          toStringSet(config.PatchToolNames),
		remote:              toStringSet(config.RemoteCommands),
		pipe:                toStringSet(config.Interpreters.Pipe),
		node:                toStringSet(config.Interpreters.Node),
		shell:               toStringSet(config.Interpreters.Shell),
		pythonPrefixes:      config.Interpreters.PythonPrefixes,
		scanTriggers:        config.ScanTriggers,
		protectedPaths:      protectedPaths,
		protectedPathsLower: protectedPathsLower,
		protectedReason:     firstNonEmpty(messages.ProtectedReason, "Blocked modification of the agent-command-guard policy configuration. Enforcement policy must stay under explicit review; edit this file manually outside agent tools if needed."),

		scriptDir:         firstNonEmpty(messages.ScriptDir, ".codex/tmp-scripts"),
		scriptGuidance:    firstNonEmpty(messages.ScriptGuidance, "If temporary code is needed, create a readable script under `.codex/tmp-scripts/` in the current project/workspace, run it as a file, and leave it in place for audit."),
		transcriptsMarker: firstNonEmpty(messages.TranscriptsMarker, "agent-transcripts"),
		transcriptsReason: firstNonEmpty(messages.TranscriptsReason, "Blocked access to agent-transcripts."),
		qualityGateMarker: firstNonEmpty(messages.QualityGateMarker, "/.agent-quality-gate"),
		qualityGateToken:  firstNonEmpty(messages.QualityGateToken, "agent-quality-gate"),
		qualityGateReason: firstNonEmpty(messages.QualityGateReason, "Blocked access to ~/.agent-quality-gate/ outside the agent-quality-gate project."),
	}
	if prefix := messages.InteractiveReasonPrefix; prefix != "" {
		sets.interactiveInterpreterR = prefix + sets.scriptGuidance
	} else {
		sets.interactiveInterpreterR = "Blocked interactive interpreter session. PTY input bypasses PreToolUse inspection. " + sets.scriptGuidance
	}
	sets.inlineInterpreterReason = "Blocked inline interpreter code. " + sets.scriptGuidance
	sets.stdinInterpreterReason = "Blocked interpreter code from stdin/heredoc. " + sets.scriptGuidance
	return sets
}

// loadMergedPolicyConfig is the production policy load path: parse the embedded
// defaults, then union/override from ACG_POLICY_CONFIG when that file is readable.
// The second return contains the lexical and canonical overlay paths to protect.
func loadMergedPolicyConfig() (*policyConfig, []string) {
	base, ok := parsePolicyConfig(defaultPolicyJSON)
	if !ok {
		panic("embedded policy configuration is invalid")
	}
	if path := os.Getenv("ACG_POLICY_CONFIG"); path != "" {
		absolutePath, err := filepath.Abs(path)
		if err != nil {
			return base, nil
		}
		absolutePath = filepath.Clean(absolutePath)
		canonicalPath, err := filepath.EvalSymlinks(absolutePath)
		if err != nil {
			return base, nil
		}
		canonicalPath = filepath.Clean(canonicalPath)
		protectedPaths := []string{absolutePath}
		if canonicalPath != absolutePath {
			protectedPaths = append(protectedPaths, canonicalPath)
		}
		if raw, err := os.ReadFile(canonicalPath); err == nil {
			if overlay, valid := parsePolicyConfig(raw); valid {
				return mergePolicyConfig(base, overlay), protectedPaths
			}
			return base, protectedPaths
		}
	}
	return base, nil
}

// Package-level policy strings are declared in main.go and populated by the
// policy initializer below from config/policy.json (or ACG_POLICY_CONFIG overlay).
var policy = func() *policySets {
	base, protectedPaths := loadMergedPolicyConfig()
	sets := buildPolicySets(base, protectedPaths...)
	scriptDir = sets.scriptDir
	scriptGuidance = sets.scriptGuidance
	inlineInterpreterReason = sets.inlineInterpreterReason
	stdinInterpreterReason = sets.stdinInterpreterReason
	interactiveInterpreterRe = sets.interactiveInterpreterR
	agentTranscriptsMarker = sets.transcriptsMarker
	agentTranscriptsReason = sets.transcriptsReason
	agentQualityGateMarker = sets.qualityGateMarker
	agentQualityGateCwdToken = sets.qualityGateToken
	agentQualityGateReason = sets.qualityGateReason
	protectedConfigReason = sets.protectedReason
	return sets
}()

func mergeStringSlice(base, overlay []string) []string {
	if overlay == nil {
		return base
	}
	if len(overlay) == 0 {
		return []string{}
	}
	result := append([]string{}, base...)
	exists := func(value string) int {
		for index, element := range result {
			if element == value {
				return index
			}
		}
		return -1
	}
	for _, entry := range overlay {
		if len(entry) > 1 && entry[0] == '-' {
			target := entry[1:]
			if index := exists(target); index >= 0 {
				result = append(result[:index], result[index+1:]...)
			}
			continue
		}
		if exists(entry) < 0 {
			result = append(result, entry)
		}
	}
	return result
}

func mergePolicyConfig(base, overlay *policyConfig) *policyConfig {
	merged := *base
	if overlay.Separators != nil {
		merged.Separators = mergeStringSlice(base.Separators, overlay.Separators)
	}
	if overlay.ShellKeywords != nil {
		merged.ShellKeywords = mergeStringSlice(base.ShellKeywords, overlay.ShellKeywords)
	}
	if overlay.Wrappers != nil {
		merged.Wrappers = mergeStringSlice(base.Wrappers, overlay.Wrappers)
	}
	if overlay.ShellToolNames != nil {
		merged.ShellToolNames = mergeStringSlice(base.ShellToolNames, overlay.ShellToolNames)
	}
	if overlay.PatchToolNames != nil {
		merged.PatchToolNames = mergeStringSlice(base.PatchToolNames, overlay.PatchToolNames)
	}
	if overlay.RemoteCommands != nil {
		merged.RemoteCommands = mergeStringSlice(base.RemoteCommands, overlay.RemoteCommands)
	}
	if overlay.Interpreters.Pipe != nil {
		merged.Interpreters.Pipe = mergeStringSlice(base.Interpreters.Pipe, overlay.Interpreters.Pipe)
	}
	if overlay.Interpreters.Node != nil {
		merged.Interpreters.Node = mergeStringSlice(base.Interpreters.Node, overlay.Interpreters.Node)
	}
	if overlay.Interpreters.PythonPrefixes != nil {
		merged.Interpreters.PythonPrefixes = mergeStringSlice(base.Interpreters.PythonPrefixes, overlay.Interpreters.PythonPrefixes)
	}
	if overlay.Interpreters.Shell != nil {
		merged.Interpreters.Shell = mergeStringSlice(base.Interpreters.Shell, overlay.Interpreters.Shell)
	}
	if overlay.ScanTriggers != nil {
		merged.ScanTriggers = mergeStringSlice(base.ScanTriggers, overlay.ScanTriggers)
	}
	if overlay.ProtectedPaths != nil {
		merged.ProtectedPaths = mergeStringSlice(base.ProtectedPaths, overlay.ProtectedPaths)
	}
	if overlay.Messages.ScriptDir != "" {
		merged.Messages.ScriptDir = overlay.Messages.ScriptDir
	}
	if overlay.Messages.ScriptGuidance != "" {
		merged.Messages.ScriptGuidance = overlay.Messages.ScriptGuidance
	}
	if overlay.Messages.TranscriptsMarker != "" {
		merged.Messages.TranscriptsMarker = overlay.Messages.TranscriptsMarker
	}
	if overlay.Messages.TranscriptsReason != "" {
		merged.Messages.TranscriptsReason = overlay.Messages.TranscriptsReason
	}
	if overlay.Messages.QualityGateMarker != "" {
		merged.Messages.QualityGateMarker = overlay.Messages.QualityGateMarker
	}
	if overlay.Messages.QualityGateToken != "" {
		merged.Messages.QualityGateToken = overlay.Messages.QualityGateToken
	}
	if overlay.Messages.QualityGateReason != "" {
		merged.Messages.QualityGateReason = overlay.Messages.QualityGateReason
	}
	if overlay.Messages.InteractiveReasonPrefix != "" {
		merged.Messages.InteractiveReasonPrefix = overlay.Messages.InteractiveReasonPrefix
	}
	if overlay.Messages.ProtectedReason != "" {
		merged.Messages.ProtectedReason = overlay.Messages.ProtectedReason
	}
	return &merged
}

func parseStringArray(data []byte, index int) ([]string, bool) {
	index = skipJSONSpace(data, index)
	if index >= len(data) || data[index] != '[' {
		return nil, false
	}
	index++
	values := []string{}
	for {
		index = skipJSONSpace(data, index)
		if index >= len(data) {
			return nil, false
		}
		if data[index] == ']' {
			return values, true
		}
		value, next, ok := scanJSONString(data, index)
		if !ok {
			return nil, false
		}
		values = append(values, value)
		index = skipJSONSpace(data, next)
		if index < len(data) && data[index] == ',' {
			index++
			continue
		}
		if index < len(data) && data[index] == ']' {
			return values, true
		}
		return nil, false
	}
}

// parsePolicyInto is a minimal parser for config/policy.json. It reuses the
// hand-rolled JSON scanners so encoding/json stays out of the binary.
func parsePolicyInto(data []byte, config *policyConfig) {
	index := skipJSONSpace(data, 0)
	if index >= len(data) || data[index] != '{' {
		return
	}
	index++
	for {
		index = skipJSONSpace(data, index)
		if index >= len(data) || data[index] == '}' {
			return
		}
		key, next, ok := scanJSONString(data, index)
		if !ok {
			return
		}
		index = skipJSONSpace(data, next)
		if index >= len(data) || data[index] != ':' {
			return
		}
		valueStart := skipJSONSpace(data, index+1)
		switch key {
		case "separators":
			if values, ok := parseStringArray(data, valueStart); ok {
				config.Separators = values
			}
		case "shell_keywords":
			if values, ok := parseStringArray(data, valueStart); ok {
				config.ShellKeywords = values
			}
		case "wrappers":
			if values, ok := parseStringArray(data, valueStart); ok {
				config.Wrappers = values
			}
		case "shell_tool_names":
			if values, ok := parseStringArray(data, valueStart); ok {
				config.ShellToolNames = values
			}
		case "patch_tool_names":
			if values, ok := parseStringArray(data, valueStart); ok {
				config.PatchToolNames = values
			}
		case "remote_commands":
			if values, ok := parseStringArray(data, valueStart); ok {
				config.RemoteCommands = values
			}
		case "interpreters":
			parseInterpreterPolicy(data, valueStart, &config.Interpreters)
		case "messages":
			parseMessagePolicy(data, valueStart, &config.Messages)
		case "scan_triggers":
			if values, ok := parseStringArray(data, valueStart); ok {
				config.ScanTriggers = values
			}
		case "protected_paths":
			if values, ok := parseStringArray(data, valueStart); ok {
				config.ProtectedPaths = values
			}
		}
		index, _ = skipJSONValue(data, valueStart)
		index = skipJSONSpace(data, index)
		if index < len(data) && data[index] == ',' {
			index++
			continue
		}
		if index < len(data) && data[index] == '}' {
			return
		}
		return
	}
}

func parseMessagePolicy(data []byte, start int, target *messagePolicy) {
	index := skipJSONSpace(data, start)
	if index >= len(data) || data[index] != '{' {
		return
	}
	index++
	for {
		index = skipJSONSpace(data, index)
		if index >= len(data) || data[index] == '}' {
			return
		}
		key, next, ok := scanJSONString(data, index)
		if !ok {
			return
		}
		index = skipJSONSpace(data, next)
		if index >= len(data) || data[index] != ':' {
			return
		}
		valueStart := skipJSONSpace(data, index+1)
		if value, _, ok := scanJSONString(data, valueStart); ok {
			switch key {
			case "script_dir":
				target.ScriptDir = value
			case "script_guidance":
				target.ScriptGuidance = value
			case "transcripts_marker":
				target.TranscriptsMarker = value
			case "transcripts_reason":
				target.TranscriptsReason = value
			case "quality_gate_marker":
				target.QualityGateMarker = value
			case "quality_gate_token":
				target.QualityGateToken = value
			case "quality_gate_reason":
				target.QualityGateReason = value
			case "interactive_reason_prefix":
				target.InteractiveReasonPrefix = value
			case "protected_reason":
				target.ProtectedReason = value
			}
		}
		index, _ = skipJSONValue(data, valueStart)
		index = skipJSONSpace(data, index)
		if index < len(data) && data[index] == ',' {
			index++
			continue
		}
		if index < len(data) && data[index] == '}' {
			return
		}
		return
	}
}

func parseInterpreterPolicy(data []byte, start int, target *interpreterPolicy) {
	index := skipJSONSpace(data, start)
	if index >= len(data) || data[index] != '{' {
		return
	}
	index++
	for {
		index = skipJSONSpace(data, index)
		if index >= len(data) || data[index] == '}' {
			return
		}
		key, next, ok := scanJSONString(data, index)
		if !ok {
			return
		}
		index = skipJSONSpace(data, next)
		if index >= len(data) || data[index] != ':' {
			return
		}
		valueStart := skipJSONSpace(data, index+1)
		switch key {
		case "pipe":
			if values, ok := parseStringArray(data, valueStart); ok {
				target.Pipe = values
			}
		case "node":
			if values, ok := parseStringArray(data, valueStart); ok {
				target.Node = values
			}
		case "python_prefixes":
			if values, ok := parseStringArray(data, valueStart); ok {
				target.PythonPrefixes = values
			}
		case "shell":
			if values, ok := parseStringArray(data, valueStart); ok {
				target.Shell = values
			}
		}
		index, _ = skipJSONValue(data, valueStart)
		index = skipJSONSpace(data, index)
		if index < len(data) && data[index] == ',' {
			index++
			continue
		}
		if index < len(data) && data[index] == '}' {
			return
		}
		return
	}
}

func parsePolicyConfig(data []byte) (*policyConfig, bool) {
	start := skipJSONSpace(data, 0)
	if start >= len(data) || data[start] != '{' {
		return nil, false
	}
	end, ok := skipJSONValue(data, start)
	if !ok || skipJSONSpace(data, end) != len(data) {
		return nil, false
	}
	var config policyConfig
	parsePolicyInto(data, &config)
	return &config, true
}
