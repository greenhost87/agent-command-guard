package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func splitCommand(commandText string) ([]string, error) {
	var fields []string
	var current strings.Builder
	quote := byte(0)
	escaped := false
	hasCurrent := false

	flush := func() {
		if hasCurrent {
			fields = append(fields, current.String())
			current.Reset()
			hasCurrent = false
		}
	}

	for index := 0; index < len(commandText); index++ {
		character := commandText[index]
		if escaped {
			current.WriteByte(character)
			hasCurrent = true
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			hasCurrent = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
				continue
			}
			current.WriteByte(character)
			hasCurrent = true
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			hasCurrent = true
			continue
		}
		if character == ' ' || character == '\t' || character == '\n' || character == '\r' {
			flush()
			continue
		}
		current.WriteByte(character)
		hasCurrent = true
	}
	if escaped {
		current.WriteByte('\\')
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in hook command")
	}
	flush()
	return fields, nil
}

func selectedCaseNames(selected caseList) []string {
	if len(selected) > 0 {
		return selected
	}
	return append([]string(nil), orderedCases...)
}

func sortedCaseNames() []string {
	names := make([]string, 0, len(payloads))
	for name := range payloads {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func defaultHookCommand() string {
	executablePath, err := os.Executable()
	if err != nil {
		return "build/agent-command-guard"
	}
	return filepath.Join(filepath.Dir(executablePath), "agent-command-guard")
}

func resultFloat(summary result, key string) float64 {
	value, ok := summary[key].(float64)
	if !ok {
		return 0
	}
	return value
}

func resultInt(summary result, key string) int {
	value, ok := summary[key].(int)
	if !ok {
		return 0
	}
	return value
}

func formatMS(value float64) string {
	return fmt.Sprintf("%.3f", value)
}

func formatReturnCodes(summary result) string {
	value, ok := summary["return_codes"]
	if !ok {
		return "-"
	}
	returnCodes, ok := value.([]int)
	if !ok || len(returnCodes) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(returnCodes))
	for _, returnCode := range returnCodes {
		parts = append(parts, fmt.Sprintf("%d", returnCode))
	}
	return strings.Join(parts, ",")
}

func formatByteCount(summary result, key string) string {
	if _, ok := summary[key]; !ok {
		return "-"
	}
	return fmt.Sprintf("%d", resultInt(summary, key))
}
