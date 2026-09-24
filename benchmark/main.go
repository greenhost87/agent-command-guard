// Command benchmark measures agent-command-guard execution.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const scriptDir = ".codex/tmp-scripts"
const benchmarkIterations = 300
const benchmarkWarmup = 20

type payload struct {
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
}

type result map[string]any

type caseList []string

func (cases *caseList) String() string {
	return strings.Join(*cases, ",")
}

func (cases *caseList) Set(value string) error {
	if _, ok := payloads[value]; !ok {
		return fmt.Errorf("unknown case %q", value)
	}
	*cases = append(*cases, value)
	return nil
}

var orderedCases = []string{
	"ignored_non_shell_tool",
	"allowed_simple_shell",
	"allowed_typical_shell",
	"allowed_workspace_script",
	"denied_node_eval",
	"denied_tmp_script_cleanup",
	"allowed_patch_text_mentions_cleanup",
	"denied_patch_delete_tmp_script",
}

var payloads = map[string]payload{
	"ignored_non_shell_tool": {
		ToolName: "web.run",
		ToolInput: map[string]any{
			"open": []map[string]string{{"ref_id": "turn0search0"}},
		},
	},
	"allowed_simple_shell": {
		ToolName:  "functions.exec_command",
		ToolInput: map[string]any{"cmd": "true"},
	},
	"allowed_typical_shell": {
		ToolName:  "functions.exec_command",
		ToolInput: map[string]any{"cmd": "sed -n '1,120p' /tmp/example.txt"},
	},
	"allowed_workspace_script": {
		ToolName:  "functions.exec_command",
		ToolInput: map[string]any{"cmd": "node " + scriptDir + "/check.mjs"},
	},
	"denied_node_eval": {
		ToolName:  "functions.exec_command",
		ToolInput: map[string]any{"cmd": `node -e "console.log(1)"`},
	},
	"denied_tmp_script_cleanup": {
		ToolName:  "functions.exec_command",
		ToolInput: map[string]any{"cmd": "rm -rf " + scriptDir},
	},
	"allowed_patch_text_mentions_cleanup": {
		ToolName: "apply_patch",
		ToolInput: map[string]any{
			"cmd": strings.Join([]string{
				"*** Begin Patch",
				"*** Add File: " + scriptDir + "/example.txt",
				"+rm -rf " + scriptDir,
				"*** End Patch",
			}, "\n"),
		},
	},
	"denied_patch_delete_tmp_script": {
		ToolName: "apply_patch",
		ToolInput: map[string]any{
			"cmd": strings.Join([]string{
				"*** Begin Patch",
				"*** Delete File: " + scriptDir + "/example.txt",
				"*** End Patch",
			}, "\n"),
		},
	},
}

func elapsedMSForCommand(command []string, body []byte) (float64, int, []byte, []byte) {
	startedAt := time.Now()
	cmd := exec.Command(command[0], command[1:]...)
	if body != nil {
		cmd.Stdin = bytes.NewReader(body)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	elapsedMS := float64(time.Since(startedAt).Nanoseconds()) / 1_000_000
	return elapsedMS, exitCode(err), stdout.Bytes(), stderr.Bytes()
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func percentile(sortedValues []float64, percentileValue float64) float64 {
	if len(sortedValues) == 1 {
		return sortedValues[0]
	}
	position := float64(len(sortedValues)-1) * percentileValue
	lower := int(math.Floor(position))
	upper := lower + 1
	if upper >= len(sortedValues) {
		upper = len(sortedValues) - 1
	}
	fraction := position - float64(lower)
	return sortedValues[lower]*(1-fraction) + sortedValues[upper]*fraction
}

func summarize(values []float64) result {
	sortedValues := append([]float64(nil), values...)
	sort.Float64s(sortedValues)

	total := 0.0
	for _, value := range sortedValues {
		total += value
	}

	median := sortedValues[len(sortedValues)/2]
	if len(sortedValues)%2 == 0 {
		median = (sortedValues[len(sortedValues)/2-1] + sortedValues[len(sortedValues)/2]) / 2
	}

	return result{
		"min_ms":    sortedValues[0],
		"median_ms": median,
		"mean_ms":   total / float64(len(sortedValues)),
		"p90_ms":    percentile(sortedValues, 0.90),
		"p95_ms":    percentile(sortedValues, 0.95),
		"p99_ms":    percentile(sortedValues, 0.99),
		"max_ms":    sortedValues[len(sortedValues)-1],
	}
}

func benchmarkHook(command []string, caseName string, iterations int, warmup int) (result, error) {
	payloadBody, err := json.Marshal(payloads[caseName])
	if err != nil {
		return nil, err
	}

	for index := 0; index < warmup; index++ {
		elapsedMSForCommand(command, payloadBody)
	}

	timings := make([]float64, 0, iterations)
	returnCodeSet := make(map[int]bool)
	var firstStdout []byte
	var firstStderr []byte

	for index := 0; index < iterations; index++ {
		elapsedMS, returnCode, stdout, stderr := elapsedMSForCommand(command, payloadBody)
		timings = append(timings, elapsedMS)
		returnCodeSet[returnCode] = true
		if index == 0 {
			firstStdout = append([]byte(nil), stdout...)
			firstStderr = append([]byte(nil), stderr...)
		}
	}

	returnCodes := make([]int, 0, len(returnCodeSet))
	for returnCode := range returnCodeSet {
		returnCodes = append(returnCodes, returnCode)
	}
	sort.Ints(returnCodes)

	summary := summarize(timings)
	summary["case"] = caseName
	summary["return_codes"] = returnCodes
	summary["first_stdout_bytes"] = len(firstStdout)
	summary["first_stderr_bytes"] = len(firstStderr)
	return summary, nil
}

func benchmarkBaseline(iterations int, warmup int) result {
	command := []string{"/usr/bin/true"}
	for index := 0; index < warmup; index++ {
		elapsedMSForCommand(command, nil)
	}

	timings := make([]float64, 0, iterations)
	for index := 0; index < iterations; index++ {
		elapsedMS, _, _, _ := elapsedMSForCommand(command, nil)
		timings = append(timings, elapsedMS)
	}

	summary := summarize(timings)
	summary["case"] = "baseline_spawn_true"
	return summary
}
