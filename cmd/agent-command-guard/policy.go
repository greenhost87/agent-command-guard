package main

import (
	_ "embed"
	"strings"
)

//go:generate go run ../policygen

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

func buildDefaultPolicySets() *policySets {
	return &policySets{
		separators:              toStringSet(generatedSeparators),
		keywords:                toStringSet(generatedKeywords),
		wrappers:                toStringSet(generatedWrappers),
		shellTools:              toStringSet(generatedShellTools),
		patchTools:              toStringSet(generatedPatchTools),
		remote:                  toStringSet(generatedRemote),
		pipe:                    toStringSet(generatedPipe),
		node:                    toStringSet(generatedNode),
		shell:                   toStringSet(generatedShellInterpreters),
		pythonPrefixes:          generatedPythonPrefixes,
		scanTriggers:            generatedScanTriggers,
		protectedPaths:          generatedProtectedPaths,
		protectedPathsLower:     generatedProtectedPathsLower,
		protectedReason:         generatedProtectedReason,
		scriptDir:               generatedScriptDir,
		scriptGuidance:          generatedScriptGuidance,
		inlineInterpreterReason: generatedInlineInterpreterReason,
		stdinInterpreterReason:  generatedStdinInterpreterReason,
		interactiveInterpreterR: generatedInteractiveInterpreterReason,
		transcriptsMarker:       generatedTranscriptsMarker,
		transcriptsReason:       generatedTranscriptsReason,
		qualityGateMarker:       generatedQualityGateMarker,
		qualityGateToken:        generatedQualityGateToken,
		qualityGateReason:       generatedQualityGateReason,
	}
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
