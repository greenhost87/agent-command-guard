package main

import (
	"fmt"
	"strings"
)

func commandNameAfterWrappers(commandText string, tokens []shellToken, index int) string {
	for index < len(tokens) {
		value := tokens[index].value(commandText)
		if isAssignment(value) {
			index++
			continue
		}
		name := commandNameToken(value)
		if isWrapper(name) {
			index++
			if name == "rtk" && index < len(tokens) && strings.EqualFold(tokens[index].value(commandText), "proxy") {
				index++
			}
			continue
		}
		if name == "env" {
			index = skipEnv(commandText, tokens, index)
			continue
		}
		return name
	}
	return ""
}

func hasInlineInterpreterCode(commandText string, name string, args []shellToken) bool {
	if isNodeInterpreter(name) {
		return nodeInlineEval(commandText, args)
	}
	if isPythonInterpreter(name) {
		return pythonInlineEval(commandText, args)
	}
	if isShellInterpreter(name) {
		return containsShortFlag(commandText, args, 'c')
	}
	handlers := map[string]func(string, []shellToken) bool{
		"perl": perlOrRubyInlineEval, "ruby": perlOrRubyInlineEval, "php": phpInlineEval,
		"bun": genericInlineEval, "julia": genericInlineEval, "lua": genericInlineEval, "luajit": genericInlineEval,
		"R": genericInlineEval, "Rscript": genericInlineEval, "swift": genericInlineEval,
	}
	if handler := handlers[name]; handler != nil {
		return handler(commandText, args)
	}
	if name == "osascript" {
		return containsExactArg(commandText, args, "-e")
	}
	return name == "deno" && len(args) > 0 && args[0].value(commandText) == "eval"
}

func readsInterpreterProgramFromStdin(commandText string, name string, args []shellToken) bool {
	if !readsProgramFromStdin(commandText, args) {
		return false
	}
	switch {
	case isNodeInterpreter(name), isPythonInterpreter(name),
		name == "perl", name == "ruby", name == "php", name == "osascript":
		return true
	case isShellInterpreter(name):
		return hasHeredoc(commandText, args)
	}
	return false
}

func isInteractiveInterpreterArg(name, value string) bool {
	if isPythonInterpreter(name) || isShellInterpreter(name) {
		return value == "--interactive" || strings.HasPrefix(value, "-") && !strings.HasPrefix(value, "--") && strings.Contains(strings.TrimPrefix(value, "-"), "i")
	}
	if isNodeInterpreter(name) {
		return value == "-i" || value == "--interactive"
	}
	if name == "php" {
		return value == "-a" || value == "--interactive"
	}
	return (name == "bun" || name == "deno") && value == "repl"
}

func startsInteractiveInterpreter(commandText string, name string, args []shellToken) bool {
	if len(args) == 0 {
		return isPipeInterpreter(name)
	}
	for _, arg := range args {
		if isInteractiveInterpreterArg(name, arg.value(commandText)) {
			return true
		}
	}
	return false
}

func commandReceivesPipe(commandText string, tokens []shellToken, commandStart int) bool {
	for index := commandStart - 1; index >= 0; index-- {
		value := tokens[index].value(commandText)
		if value == "|" {
			return true
		}
		if isSeparator(value) {
			return false
		}
	}
	return false
}

func detectBlockReason(commandText string) string {
	return detectBlockReasonInCwd(commandText, "")
}

func detectBlockReasonInCwd(commandText, cwd string) string {
	return detectBlockReasonWithInstallApprovalInCwd(commandText, false, cwd)
}

func detectBlockReasonWithInstallApproval(commandText string, installApproved bool) string {
	return detectBlockReasonWithInstallApprovalInCwd(commandText, installApproved, "")
}

func detectBlockReasonWithInstallApprovalInCwd(commandText string, installApproved bool, cwd string) string {
	return detectBlockReasonAtDepthInCwd(commandText, installApproved, 0, cwd)
}

func interpreterSpanBlockReason(commandText string, tokens []shellToken, span commandSpan) string {
	name := span.name
	args := tokens[span.start+1 : span.end]
	if name == "rtk run" {
		return "Blocked `rtk run`, which bypasses shell command inspection. Run the command directly through the shell tool."
	}
	if isRemoteCommand(name) {
		return fmt.Sprintf("Blocked `%s`: remote shell and file transfer commands are not allowed.", name)
	}
	if name == "eval" {
		return "Blocked shell `eval`. " + scriptGuidance
	}
	if hasInlineInterpreterCode(commandText, name, args) {
		return inlineInterpreterReason
	}
	if readsInterpreterProgramFromStdin(commandText, name, args) {
		return stdinInterpreterReason
	}
	if !commandReceivesPipe(commandText, tokens, span.start) && startsInteractiveInterpreter(commandText, name, args) {
		return interactiveInterpreterRe
	}
	return ""
}

func pipeInterpreterBlockReason(commandText string, tokens []shellToken, spans []commandSpan, installApproved bool) string {
	for index := 0; index+1 < len(tokens); index++ {
		if tokens[index].value(commandText) != "|" {
			continue
		}
		next := index + 1
		for next < len(tokens) && isAssignment(tokens[next].value(commandText)) {
			next++
		}
		if next >= len(tokens) {
			continue
		}
		name := commandNameAfterWrappers(commandText, tokens, next)
		if !isPipeInterpreter(name) {
			continue
		}
		if installApproved && isInstallerPipeAt(commandText, tokens, spans, index) {
			continue
		}
		return fmt.Sprintf("Blocked pipe-to-interpreter (`| %s`). Pipe data to a normal file or use a workspace script under `%s` with explicit inputs.", name, scriptDir)
	}
	return ""
}

func indirectShellBlockReason(commandText string, tokens []shellToken) string {
	for index, token := range tokens {
		name := basenameToken(token.value(commandText))
		if name == "find" && findExecShellC(commandText, tokens, index) {
			return "Blocked `find ... -exec sh -c`. " + scriptGuidance
		}
		if name == "xargs" && xargsShellC(commandText, tokens, index) {
			return "Blocked `xargs ... sh -c`. " + scriptGuidance
		}
	}
	return ""
}

func detectBlockReasonAtDepthInCwd(commandText string, installApproved bool, substDepth int, cwd string) string {
	if reason := detectCommandSubstitutionReasonAtDepthInCwd(commandText, installApproved, substDepth, cwd); reason != "" {
		return reason
	}
	if !needsDetailedShellScan(commandText) {
		return ""
	}

	var tokenBuffer [16]shellToken
	tokens := shellTokens(commandText, tokenBuffer[:0])
	var spanBuffer [4]commandSpan
	spans := commandSpans(commandText, tokens, spanBuffer[:0])
	if reason := detectEnvSplitString(commandText, tokens); reason != "" {
		return reason
	}
	if reason := detectDestructiveDeletionInCwd(commandText, tokens, spans, cwd); reason != "" {
		return reason
	}

	for _, span := range spans {
		if reason := interpreterSpanBlockReason(commandText, tokens, span); reason != "" {
			return reason
		}
	}
	if reason := pipeInterpreterBlockReason(commandText, tokens, spans, installApproved); reason != "" {
		return reason
	}
	return indirectShellBlockReason(commandText, tokens)
}

func forbiddenProtectedPath(allow bool, path string) bool {
	return !allow && touchesProtectedPath(path)
}

func detectPatchDeleteReason(commandText string) string {
	return detectPatchDeleteReasonInCwd(commandText, "")
}

func detectPatchDeleteReasonInCwd(commandText, cwd string) string {
	allowProtected := cwdAllowsProtectedConfig(cwd)
	addMarker := "*** " + "Add File:"
	deleteMarker := "*** " + "Delete File:"
	updateMarker := "*** " + "Update File:"
	moveMarker := "*** " + "Move to:"
	currentUpdateTouchesScriptDir := false

	for len(commandText) > 0 {
		line := commandText
		if index := strings.IndexByte(commandText, '\n'); index >= 0 {
			line = commandText[:index]
			commandText = commandText[index+1:]
		} else {
			commandText = ""
		}
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, updateMarker):
			pathText := strings.TrimSpace(strings.TrimPrefix(line, updateMarker))
			currentUpdateTouchesScriptDir = touchesScriptDir(pathText)
			if forbiddenProtectedPath(allowProtected, pathText) {
				return protectedConfigReason
			}
		case strings.HasPrefix(line, addMarker):
			pathText := strings.TrimSpace(strings.TrimPrefix(line, addMarker))
			if forbiddenProtectedPath(allowProtected, pathText) {
				return protectedConfigReason
			}
			currentUpdateTouchesScriptDir = false
		case strings.HasPrefix(line, deleteMarker):
			pathText := strings.TrimSpace(strings.TrimPrefix(line, deleteMarker))
			if touchesScriptDir(pathText) {
				return fmt.Sprintf("Blocked deletion of `%s` audit scripts. Leave generated scripts in place for review.", scriptDir)
			}
			if forbiddenProtectedPath(allowProtected, pathText) {
				return protectedConfigReason
			}
			currentUpdateTouchesScriptDir = false
		case strings.HasPrefix(line, moveMarker):
			if currentUpdateTouchesScriptDir {
				return fmt.Sprintf("Blocked moving `%s` audit scripts out of the project. Leave generated scripts in place for review.", scriptDir)
			}
		case strings.HasPrefix(line, "*** "):
			currentUpdateTouchesScriptDir = false
		}
	}
	return ""
}

func findExecShellC(commandText string, tokens []shellToken, findIndex int) bool {
	for index := findIndex + 1; index < len(tokens) && !isSeparator(tokens[index].value(commandText)); index++ {
		if tokens[index].value(commandText) == "-exec" && index+1 < len(tokens) {
			name := basenameToken(tokens[index+1].value(commandText))
			if name == "sh" || name == "bash" || name == "zsh" {
				for cursor := index + 2; cursor < len(tokens); cursor++ {
					value := tokens[cursor].value(commandText)
					if value == ";" || value == "&&" || value == "||" || value == "|" {
						break
					}
					if value == "-c" {
						return true
					}
				}
			}
		}
	}
	return false
}

func xargsShellC(commandText string, tokens []shellToken, xargsIndex int) bool {
	for index := xargsIndex + 1; index < len(tokens) && !isSeparator(tokens[index].value(commandText)); index++ {
		name := basenameToken(tokens[index].value(commandText))
		if name == "sh" || name == "bash" || name == "zsh" {
			for cursor := index + 1; cursor < len(tokens) && !isSeparator(tokens[cursor].value(commandText)); cursor++ {
				if tokens[cursor].value(commandText) == "-c" {
					return true
				}
			}
		}
	}
	return false
}
