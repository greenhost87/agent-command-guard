package main

import (
	"fmt"
	"strings"
)

// maxSubstitutionDepth bounds the mutual recursion between the command
// substitution scanner and the block-reason scan on deeply nested input.
const maxSubstitutionDepth = 32

func updateShellQuote(character byte, quote *byte) bool {
	switch character {
	case '\'', '"':
		switch *quote {
		case 0:
			*quote = character
		case character:
			*quote = 0
		}
		return true
	default:
		return false
	}
}

func substitutionEnd(text string, start int, closing byte, nested bool) int {
	depth, quote := 1, byte(0)
	escaped := false
	for index := start; index < len(text); index++ {
		character := text[index]
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if updateShellQuote(character, &quote) {
			continue
		}
		if quote != 0 {
			continue
		}
		if nested && character == '(' {
			depth++
		}
		if character != closing {
			continue
		}
		depth--
		if depth == 0 {
			return index
		}
	}
	return -1
}

func detectCommandSubstitutionReasonAtDepthInCwd(commandText string, installApproved bool, substDepth int, cwd string) string {
	if substDepth > maxSubstitutionDepth {
		return ""
	}
	quote, escaped := byte(0), false
	for index := 0; index < len(commandText); index++ {
		character := commandText[index]
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if updateShellQuote(character, &quote) {
			continue
		}
		if quote == '\'' {
			continue
		}
		start, closing, nested := 0, byte(0), false
		if character == '`' {
			start, closing = index+1, '`'
		}
		if character == '$' && index+1 < len(commandText) && commandText[index+1] == '(' {
			start, closing, nested = index+2, ')', true
		}
		if closing == 0 {
			continue
		}
		end := substitutionEnd(commandText, start, closing, nested)
		if end < 0 {
			continue
		}
		if reason := detectBlockReasonAtDepthInCwd(commandText[start:end], installApproved, substDepth+1, cwd); reason != "" {
			return reason
		}
		index = end
	}
	return ""
}

func isDeletionCommand(name string) bool {
	for _, candidate := range []string{"rm", "rmdir", "unlink", "trash", "trash-put"} {
		if name == candidate {
			return true
		}
	}
	return false
}

func isProtectedWriteCommand(name string) bool { return name == "mv" || name == "cp" || name == "tee" }
func protectedArgsForbidden(cwd, commandText string, args []shellToken) bool {
	return !cwdAllowsProtectedConfig(cwd) && anyTouchesProtectedPath(commandText, args)
}

func basicDeletionReason(commandText, name string, args []shellToken, cwd string) string {
	deletion := isDeletionCommand(name)
	if deletion && protectedArgsForbidden(cwd, commandText, args) {
		return protectedConfigReason
	}
	if len(args) > 0 && isProtectedWriteCommand(name) && protectedArgsForbidden(cwd, commandText, args) {
		return protectedConfigReason
	}
	if deletion && anyTouchesScriptDir(commandText, args) {
		return fmt.Sprintf("Blocked deletion of `%s` audit scripts. Leave generated scripts in place for review.", scriptDir)
	}
	if deletion && anyTouchesExternalPath(commandText, args) {
		return "Blocked deletion outside the workspace. Keep cleanup commands scoped to explicit relative paths inside the current project."
	}
	if name == "mv" && len(args) > 0 && touchesScriptDir(args[0].value(commandText)) {
		return fmt.Sprintf("Blocked moving `%s` audit scripts out of the project. Leave generated scripts in place for review.", scriptDir)
	}
	return ""
}

func findDeleteOperation(commandText string, args []shellToken) bool {
	for index, arg := range args {
		if arg.value(commandText) == "-delete" {
			return true
		}
		if arg.value(commandText) != "-exec" || index+1 >= len(args) {
			continue
		}
		if isDeletionCommand(basenameToken(args[index+1].value(commandText))) {
			return true
		}
	}
	return false
}

func findDeletionReason(commandText, name string, args []shellToken, cwd string) string {
	if name != "find" || !findDeleteOperation(commandText, args) {
		return ""
	}
	if anyTouchesScriptDir(commandText, args) {
		return fmt.Sprintf("Blocked `find ... -delete` touching `%s` audit scripts.", scriptDir)
	}
	if cwdAllowsProtectedConfig(cwd) {
		return ""
	}
	lowered := strings.ToLower(commandText)
	for _, path := range policy.protectedPathsLower {
		if strings.Contains(lowered, path) {
			return protectedConfigReason
		}
	}
	return ""
}

func gitDestructiveReason(commandText, name string, args []shellToken) string {
	if name != "git" || len(args) == 0 {
		return ""
	}
	switch args[0].value(commandText) {
	case "clean":
		return "Blocked `git clean`: it can delete local `.codex/tmp-scripts/` audit scripts. Use a narrower cleanup command that explicitly preserves that directory."
	case "reset":
		if containsExactArg(commandText, args[1:], "--hard") {
			return "Blocked `git reset --hard`: it can discard uncommitted work."
		}
	case "checkout":
		if containsExactArg(commandText, args[1:], "--") {
			return "Blocked `git checkout --`: it can discard uncommitted work."
		}
	}
	return ""
}

func redirectionDeletionReason(commandText string, tokens []shellToken, cwd string) string {
	for index := 0; index+1 < len(tokens); index++ {
		token, target := tokens[index].value(commandText), tokens[index+1].value(commandText)
		overwrite := token == ">" || token == ">|" || token == "2>" || token == "&>"
		if overwrite && touchesScriptDir(target) {
			return fmt.Sprintf("Blocked overwriting `%s` audit scripts via shell redirection.", scriptDir)
		}
		protectedWrite := overwrite || token == ">>"
		if protectedWrite && !cwdAllowsProtectedConfig(cwd) && touchesProtectedPath(target) {
			return protectedConfigReason
		}
	}
	return ""
}

func detectDestructiveDeletionInCwd(commandText string, tokens []shellToken, spans []commandSpan, cwd string) string {
	for _, span := range spans {
		args := tokens[span.start+1 : span.end]
		for _, reason := range []string{basicDeletionReason(commandText, span.name, args, cwd), findDeletionReason(commandText, span.name, args, cwd), gitDestructiveReason(commandText, span.name, args)} {
			if reason != "" {
				return reason
			}
		}
	}
	return redirectionDeletionReason(commandText, tokens, cwd)
}

func anyTouchesScriptDir(commandText string, args []shellToken) bool {
	for _, arg := range args {
		if touchesScriptDir(arg.value(commandText)) {
			return true
		}
	}
	return false
}

func anyTouchesExternalPath(commandText string, args []shellToken) bool {
	for _, arg := range args {
		if touchesExternalPath(arg.value(commandText)) {
			return true
		}
	}
	return false
}

func needsDetailedShellScan(commandText string) bool {
	lowered := strings.ToLower(commandText)
	// Protected config paths bypass the trigger list — they always need a detailed scan.
	for _, path := range policy.protectedPathsLower {
		if strings.Contains(lowered, path) {
			return true
		}
	}
	// Leading `sh` matched at index 0 in the pre-config switch. A Contains("sh")
	// trigger would also hit mid-token substrings ("push", "flush"), so keep the
	// prefix check here instead of putting "sh" in scan_triggers.
	if strings.HasPrefix(lowered, "sh") {
		return true
	}
	for _, trigger := range policy.scanTriggers {
		if strings.Contains(lowered, trigger) {
			return true
		}
	}
	return false
}

func detectEnvSplitString(commandText string, tokens []shellToken) string {
	for index, token := range tokens {
		if commandNameToken(token.value(commandText)) != "env" {
			continue
		}
		for cursor := index + 1; cursor < len(tokens) && !isSeparator(tokens[cursor].value(commandText)); cursor++ {
			value := tokens[cursor].value(commandText)
			var splitText string
			switch {
			case value == "-S" && cursor+1 < len(tokens):
				splitText = tokens[cursor+1].value(commandText)
			case strings.HasPrefix(value, "--split-string="):
				splitText = strings.TrimPrefix(value, "--split-string=")
			}
			if splitText == "" {
				continue
			}
			if reason := detectBlockReason(splitText); reason != "" {
				return "Blocked `env -S` split-string containing unsafe inline interpreter use. " + reason
			}
		}
	}
	return ""
}
