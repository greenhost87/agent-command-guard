package main

import (
	"io"
	"os"
	"strings"
)

func denialMessage(commandText, reason string) string {
	preview := commandText
	truncated := false
	characters := 0
	for index := range commandText {
		if characters == 50 {
			preview = commandText[:index]
			truncated = true
			break
		}
		characters++
	}

	message := "Blocked shell command: " + preview
	if truncated {
		message += "..."
	}
	message += "\n" + reason
	return message
}

func deny(commandText, reason string) {
	denyMessage(denialMessage(commandText, reason))
}

func allowPiCommandRewrite(command, scriptPath string) {
	encoded := []byte(`{"agentCommandGuard":{"rewriteCommand":`)
	encoded = appendJSONString(encoded, command)
	encoded = append(encoded, `,"scriptPath":`...)
	encoded = appendJSONString(encoded, scriptPath)
	encoded = append(encoded, "}}\n"...)
	_, _ = os.Stdout.Write(encoded)
}

func denyMessage(message string) {
	encoded := make([]byte, 0, len(message)+180)
	encoded = append(encoded, `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":`...)
	encoded = appendJSONString(encoded, message)
	encoded = append(encoded, "}}\n"...)
	_, _ = os.Stdout.Write(encoded)
}

func confirmInstall(commandText string) bool {
	const script = `on run argv
display dialog "A coding agent wants to run an installation command:" & return & return & item 1 of argv with title "Confirm installation" buttons {"Cancel", "Allow"} default button "Cancel" cancel button "Cancel" with icon caution
end run`
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer func() { _ = null.Close() }()
	process, err := os.StartProcess("/usr/bin/osascript", []string{"osascript", "-e", script, commandText}, &os.ProcAttr{Files: []*os.File{null, null, null}})
	if err != nil {
		return false
	}
	state, err := process.Wait()
	return err == nil && state.Success()
}

func main() {
	body, err := io.ReadAll(os.Stdin)
	if err != nil || len(body) == 0 || isJSONWhitespaceOnly(body) {
		return
	}

	if handleCursor(body) {
		return
	}

	data := extractPayload(body)

	var commandText, reason string
	shellTool := false
	if isPatchToolName(data.ToolName) {
		commandText = extractCommand(data.ToolInput)
		if commandText == "" {
			return
		}
		reason = detectPatchDeleteReasonInCwd(commandText, data.Cwd)
		if reason == "" {
			reason = evaluateAgentQualityGateAccess(commandText, data.Cwd)
		}
	} else if data.ToolName != "" && !isShellToolName(data.ToolName) {
		return
	} else {
		commandText = extractCommand(data.ToolInput)
		if commandText == "" {
			return
		}
		shellTool = true
		reason = evaluateShellCommandInCwd(commandText, data.Cwd)
	}

	integration := resolveIntegration(false)
	if reason != "" {
		if shellTool && integration == "pi" && (reason == inlineInterpreterReason || reason == stdinInterpreterReason) {
			if stagedPath := stageInlineScript(commandText, data.Cwd); stagedPath != "" {
				if rewritten, ok := commandForStagedScript(commandText, stagedPath); ok && evaluateShellCommandInCwd(rewritten, data.Cwd) == "" {
					allowPiCommandRewrite(rewritten, stagedPath)
					logHookDecision(body, integration, true)
					return
				}
			}
		}
		if shellTool {
			denyMessage(shellDenialMessage(commandText, data.Cwd, reason))
		} else {
			deny(commandText, reason)
		}
		logHookDecision(body, integration, false)
		return
	}
	logHookDecision(body, integration, true)
}

func touchesAgentQualityGate(text string) bool {
	return strings.Contains(text, agentQualityGateMarker)
}

func cwdAllowsAgentQualityGate(cwd string) bool {
	return cwdMatchesProjectRoot(cwd, agentQualityGateCwdToken)
}

func evaluateAgentQualityGateAccess(text, cwd string) string {
	if !touchesAgentQualityGate(text) {
		return ""
	}
	if cwdAllowsAgentQualityGate(cwd) {
		return ""
	}
	return agentQualityGateReason
}

func evaluateShellCommand(commandText string) string {
	return evaluateShellCommandInCwd(commandText, "")
}

func evaluateShellCommandInCwd(commandText, cwd string) string {
	if strings.Contains(commandText, agentTranscriptsMarker) {
		return agentTranscriptsReason
	}
	if reason := evaluateAgentQualityGateAccess(commandText, cwd); reason != "" {
		return reason
	}
	installApproved := false
	if requiresInstallConfirmation(commandText) {
		if !isInstallConfirmationSupported() {
			return "Installation commands require explicit user confirmation, but osascript is unavailable on this platform."
		}
		if !confirmInstall(commandText) {
			return "Installation command was not explicitly approved by the user."
		}
		installApproved = true
	}
	return detectBlockReasonWithInstallApprovalInCwd(commandText, installApproved, cwd)
}
