package main

import (
	"os"
	"path/filepath"
)

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
// policy initializer below from generated defaults or ACG_POLICY_CONFIG overlay.
var policy = func() *policySets {
	var sets *policySets
	if os.Getenv("ACG_POLICY_CONFIG") == "" {
		sets = buildDefaultPolicySets()
	} else {
		base, protectedPaths := loadMergedPolicyConfig()
		sets = buildPolicySets(base, protectedPaths...)
	}
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

func mergeOptionalSlice(target *[]string, base, overlay []string) {
	if overlay != nil {
		*target = mergeStringSlice(base, overlay)
	}
}

func mergeMessages(base, overlay messagePolicy) messagePolicy {
	merged := base
	pairs := []struct {
		target *string
		value  string
	}{
		{&merged.ScriptDir, overlay.ScriptDir}, {&merged.ScriptGuidance, overlay.ScriptGuidance},
		{&merged.TranscriptsMarker, overlay.TranscriptsMarker}, {&merged.TranscriptsReason, overlay.TranscriptsReason},
		{&merged.QualityGateMarker, overlay.QualityGateMarker}, {&merged.QualityGateToken, overlay.QualityGateToken},
		{&merged.QualityGateReason, overlay.QualityGateReason}, {&merged.InteractiveReasonPrefix, overlay.InteractiveReasonPrefix},
		{&merged.ProtectedReason, overlay.ProtectedReason},
	}
	for _, pair := range pairs {
		if pair.value != "" {
			*pair.target = pair.value
		}
	}
	return merged
}

func mergePolicyConfig(base, overlay *policyConfig) *policyConfig {
	merged := *base
	pairs := []struct {
		target        *[]string
		base, overlay []string
	}{
		{&merged.Separators, base.Separators, overlay.Separators}, {&merged.ShellKeywords, base.ShellKeywords, overlay.ShellKeywords},
		{&merged.Wrappers, base.Wrappers, overlay.Wrappers}, {&merged.ShellToolNames, base.ShellToolNames, overlay.ShellToolNames},
		{&merged.PatchToolNames, base.PatchToolNames, overlay.PatchToolNames}, {&merged.RemoteCommands, base.RemoteCommands, overlay.RemoteCommands},
		{&merged.Interpreters.Pipe, base.Interpreters.Pipe, overlay.Interpreters.Pipe}, {&merged.Interpreters.Node, base.Interpreters.Node, overlay.Interpreters.Node},
		{&merged.Interpreters.PythonPrefixes, base.Interpreters.PythonPrefixes, overlay.Interpreters.PythonPrefixes}, {&merged.Interpreters.Shell, base.Interpreters.Shell, overlay.Interpreters.Shell},
		{&merged.ScanTriggers, base.ScanTriggers, overlay.ScanTriggers}, {&merged.ProtectedPaths, base.ProtectedPaths, overlay.ProtectedPaths},
	}
	for _, pair := range pairs {
		mergeOptionalSlice(pair.target, pair.base, pair.overlay)
	}
	merged.Messages = mergeMessages(base.Messages, overlay.Messages)
	return &merged
}
