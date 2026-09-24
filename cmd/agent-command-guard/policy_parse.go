package main

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

func assignStringArray(data []byte, start int, target *[]string) {
	if values, ok := parseStringArray(data, start); ok {
		*target = values
	}
}

// parsePolicyInto is a minimal parser for config/policy.json. It reuses the
// hand-rolled JSON scanners so encoding/json stays out of the binary.
func parsePolicyInto(data []byte, config *policyConfig) {
	scanJSONObject(data, func(key string, start, _ int) {
		switch key {
		case "separators":
			assignStringArray(data, start, &config.Separators)
		case "shell_keywords":
			assignStringArray(data, start, &config.ShellKeywords)
		case "wrappers":
			assignStringArray(data, start, &config.Wrappers)
		case "shell_tool_names":
			assignStringArray(data, start, &config.ShellToolNames)
		case "patch_tool_names":
			assignStringArray(data, start, &config.PatchToolNames)
		case "remote_commands":
			assignStringArray(data, start, &config.RemoteCommands)
		case "interpreters":
			parseInterpreterPolicy(data[start:], &config.Interpreters)
		case "messages":
			parseMessagePolicy(data[start:], &config.Messages)
		case "scan_triggers":
			assignStringArray(data, start, &config.ScanTriggers)
		case "protected_paths":
			assignStringArray(data, start, &config.ProtectedPaths)
		}
	})
}

func parseMessagePolicy(data []byte, target *messagePolicy) {
	scanJSONObject(data, func(key string, start, _ int) {
		value, _, ok := scanJSONString(data, start)
		if !ok {
			return
		}
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
	})
}

func parseInterpreterPolicy(data []byte, target *interpreterPolicy) {
	scanJSONObject(data, func(key string, start, _ int) {
		switch key {
		case "pipe":
			assignStringArray(data, start, &target.Pipe)
		case "node":
			assignStringArray(data, start, &target.Node)
		case "python_prefixes":
			assignStringArray(data, start, &target.PythonPrefixes)
		case "shell":
			assignStringArray(data, start, &target.Shell)
		}
	})
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
