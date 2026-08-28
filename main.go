package main

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"
)

// scriptDir, scriptGuidance and all marker/reason strings below are
// populated at startup from config/policy.json (see policy.go).
var (
	scriptDir                string
	scriptGuidance           string
	inlineInterpreterReason  string
	stdinInterpreterReason   string
	interactiveInterpreterRe string
	agentTranscriptsMarker   string
	agentTranscriptsReason   string
	agentQualityGateMarker   string
	agentQualityGateCwdToken string
	agentQualityGateReason   string
	protectedConfigReason    string

	protectedCwdToken = "agent-command-guard"
)

type commandSpan struct {
	name       string
	start, end int
}

type shellToken struct {
	start, end int
	text       string
}

type payload struct {
	ToolName  string
	ToolInput []byte
	Cwd       string
}

func (token shellToken) value(commandText string) string {
	if token.text != "" {
		return token.text
	}
	return commandText[token.start:token.end]
}

func basenameToken(token string) string {
	if index := strings.LastIndex(token, "/"); index >= 0 {
		return token[index+1:]
	}
	return token
}

func commandNameToken(token string) string {
	return strings.ToLower(basenameToken(token))
}

func cwdAllowsProtectedConfig(cwd string) bool {
	return cwdMatchesProjectRoot(cwd, protectedCwdToken)
}

func cwdMatchesProjectRoot(cwd, rootName string) bool {
	if cwd == "" || !filepath.IsAbs(cwd) {
		return false
	}
	return filepath.Base(filepath.Clean(cwd)) == rootName
}

func touchesProtectedPath(token string) bool {
	normalizedToken := path.Clean(strings.ReplaceAll(token, `\`, "/"))
	for _, protected := range policy.protectedPaths {
		normalizedProtected := path.Clean(strings.ReplaceAll(protected, `\`, "/"))
		if strings.Contains(normalizedToken, normalizedProtected) ||
			strings.Contains(normalizedToken, "/"+normalizedProtected) ||
			strings.Contains(normalizedToken, "./"+normalizedProtected) {
			return true
		}
	}
	return false
}

func anyTouchesProtectedPath(commandText string, args []shellToken) bool {
	for _, arg := range args {
		if touchesProtectedPath(arg.value(commandText)) {
			return true
		}
	}
	return false
}

func isSeparator(token string) bool {
	return policy.separators.has(token)
}

func isShellKeyword(token string) bool {
	return policy.keywords.has(token)
}

func isWrapper(name string) bool {
	return policy.wrappers.has(name)
}

func isShellToolName(name string) bool {
	return policy.shellTools.has(name)
}

func isPatchToolName(name string) bool {
	return policy.patchTools.has(name)
}

func isASCIIAlpha(r byte) bool {
	return ('A' <= r && r <= 'Z') || ('a' <= r && r <= 'z')
}

func isASCIIDigit(r byte) bool {
	return '0' <= r && r <= '9'
}

func isAssignment(token string) bool {
	if len(token) < 2 || (!isASCIIAlpha(token[0]) && token[0] != '_') {
		return false
	}
	for index := 1; index < len(token); index++ {
		r := token[index]
		if r == '=' {
			return true
		}
		if !isASCIIAlpha(r) && !isASCIIDigit(r) && r != '_' {
			return false
		}
	}
	return false
}

func isVersionedInterpreterName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if len(name) == len(prefix) {
		return true
	}
	suffixStart := name[len(prefix)]
	return suffixStart == '.' || isASCIIDigit(suffixStart)
}

func isPythonInterpreter(name string) bool {
	for _, prefix := range policy.pythonPrefixes {
		if isVersionedInterpreterName(name, prefix) {
			return true
		}
	}
	return false
}

func isNodeInterpreter(name string) bool {
	return policy.node.has(name)
}

func isShellInterpreter(name string) bool {
	return policy.shell.has(name)
}

func isPipeInterpreter(name string) bool {
	return policy.pipe.has(name) || isNodeInterpreter(name) ||
		isShellInterpreter(name) || isPythonInterpreter(name)
}

func isRemoteCommand(name string) bool {
	return policy.remote.has(name)
}

func isASCIISpace(character byte) bool {
	switch character {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	default:
		return false
	}
}

func isUnicodeSpace(character rune) bool {
	switch character {
	case '\u0085', '\u00a0', '\u1680', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000':
		return true
	default:
		return '\u2000' <= character && character <= '\u200a'
	}
}

func isJSONWhitespaceOnly(data []byte) bool {
	for _, character := range data {
		if !isASCIISpace(character) {
			return false
		}
	}
	return true
}

func isPunctuation(character byte) bool {
	switch character {
	case '|', '&', ';', '(', ')', '<', '>':
		return true
	default:
		return false
	}
}

func repeatedPunctuation(first byte, second byte) bool {
	switch {
	case first == '|' && second == '|':
		return true
	case first == '&' && second == '&':
		return true
	case first == '<' && second == '<':
		return true
	case first == '>' && second == '>':
		return true
	}
	return false
}

func shellTokens(commandText string, tokens []shellToken) []shellToken {
	var cooked strings.Builder
	tokenStart := -1
	rawStart := 0
	cookedMode := false
	quote := byte(0)
	escaped := false

	beginToken := func(index int) {
		if tokenStart < 0 {
			tokenStart = index
			rawStart = index
		}
	}

	ensureCooked := func(index int) {
		if !cookedMode {
			cookedMode = true
		}
		if rawStart < index {
			cooked.WriteString(commandText[rawStart:index])
		}
	}

	flush := func(end int) {
		if tokenStart < 0 {
			return
		}
		if cookedMode {
			if rawStart < end {
				cooked.WriteString(commandText[rawStart:end])
			}
			if cooked.Len() > 0 {
				tokens = append(tokens, shellToken{text: cooked.String()})
			}
			cooked.Reset()
			cookedMode = false
		} else if tokenStart < end {
			tokens = append(tokens, shellToken{start: tokenStart, end: end})
		}
		tokenStart = -1
		rawStart = end
	}

	for index := 0; index < len(commandText); {
		character := commandText[index]
		if escaped {
			width := 1
			if character >= utf8.RuneSelf {
				_, width = utf8.DecodeRuneInString(commandText[index:])
			}
			cooked.WriteString(commandText[index : index+width])
			rawStart = index + width
			escaped = false
			index += width
			continue
		}

		if character == '\\' {
			beginToken(index)
			ensureCooked(index)
			rawStart = index + 1
			escaped = true
			index++
			continue
		}

		if quote != 0 {
			if character == quote {
				ensureCooked(index)
				rawStart = index + 1
				quote = 0
				index++
				continue
			}
			index++
			continue
		}

		if character == '\'' || character == '"' {
			beginToken(index)
			ensureCooked(index)
			rawStart = index + 1
			quote = character
			index++
			continue
		}

		if character < utf8.RuneSelf && isASCIISpace(character) {
			flush(index)
			index++
			rawStart = index
			continue
		}

		if character >= utf8.RuneSelf {
			r, width := utf8.DecodeRuneInString(commandText[index:])
			if isUnicodeSpace(r) {
				flush(index)
				index += width
				rawStart = index
				continue
			}
			beginToken(index)
			index += width
			continue
		}

		if isPunctuation(character) {
			flush(index)
			if index+1 < len(commandText) && repeatedPunctuation(character, commandText[index+1]) {
				tokens = append(tokens, shellToken{start: index, end: index + 2})
				index += 2
				rawStart = index
				continue
			}
			tokens = append(tokens, shellToken{start: index, end: index + 1})
			index++
			rawStart = index
			continue
		}

		beginToken(index)
		index++
	}

	if escaped {
		cooked.WriteByte('\\')
		rawStart = len(commandText)
	}
	flush(len(commandText))
	return tokens
}

func skipEnv(commandText string, tokens []shellToken, index int) int {
	index++
	for index < len(tokens) {
		token := tokens[index].value(commandText)
		if token == "--" {
			return index + 1
		}
		if strings.HasPrefix(token, "-") || isAssignment(token) {
			index++
			continue
		}
		return index
	}
	return index
}

func commandSpans(commandText string, tokens []shellToken, spans []commandSpan) []commandSpan {
	expectCommand := true
	current := commandSpan{}
	hasCurrent := false

	for index := 0; index < len(tokens); {
		token := tokens[index].value(commandText)
		if isSeparator(token) || token == "(" || token == ")" || isShellKeyword(token) {
			if hasCurrent {
				current.end = index
				spans = append(spans, current)
				hasCurrent = false
			}
			expectCommand = true
			index++
			continue
		}

		if !expectCommand {
			index++
			continue
		}

		if isAssignment(token) {
			index++
			continue
		}

		if strings.HasPrefix(token, "-") || token == ">" || token == ">>" || token == "<" || token == "<<" || token == "2" || token == "1" {
			index++
			continue
		}

		name := commandNameToken(token)
		if name == "rtk" {
			index++
			for index < len(tokens) && strings.HasPrefix(tokens[index].value(commandText), "-") {
				index++
			}
			if index < len(tokens) && strings.EqualFold(tokens[index].value(commandText), "run") {
				current = commandSpan{name: "rtk run", start: index, end: len(tokens)}
				hasCurrent = true
				expectCommand = false
				index++
				continue
			}
			if index < len(tokens) && strings.EqualFold(tokens[index].value(commandText), "proxy") {
				index++
			}
			continue
		}
		if isWrapper(name) {
			index++
			continue
		}
		if name == "env" {
			index = skipEnv(commandText, tokens, index)
			continue
		}

		current = commandSpan{name: name, start: index, end: len(tokens)}
		hasCurrent = true
		expectCommand = false
		index++
	}

	if hasCurrent {
		spans = append(spans, current)
	}
	return spans
}

func firstSubcommand(commandText string, args []shellToken) string {
	for _, arg := range args {
		value := arg.value(commandText)
		if value != "--" && !strings.HasPrefix(value, "-") {
			return value
		}
	}
	return ""
}

func isPip(name string) bool {
	return isVersionedInterpreterName(name, "pip")
}

func isInstallerPipeAt(commandText string, tokens []shellToken, spans []commandSpan, pipeIndex int) bool {
	for _, span := range spans {
		if span.end != pipeIndex || (span.name != "curl" && span.name != "wget") {
			continue
		}
		return isShellInterpreter(commandNameAfterWrappers(commandText, tokens, pipeIndex+1))
	}
	return false
}

func requiresInstallConfirmation(commandText string) bool {
	if !strings.Contains(commandText, "brew") && !strings.Contains(commandText, "pip") &&
		!strings.Contains(commandText, "curl") && !strings.Contains(commandText, "wget") {
		return false
	}

	var tokenBuffer [16]shellToken
	tokens := shellTokens(commandText, tokenBuffer[:0])
	var spanBuffer [4]commandSpan
	spans := commandSpans(commandText, tokens, spanBuffer[:0])

	for _, span := range spans {
		args := tokens[span.start+1 : span.end]
		subcommand := firstSubcommand(commandText, args)
		switch {
		case span.name == "brew" && (subcommand == "install" || subcommand == "reinstall" || subcommand == "upgrade" || subcommand == "bundle"):
			return true
		case isPip(span.name) && subcommand == "install":
			return true
		case isPythonInterpreter(span.name):
			for index := 0; index+1 < len(args); index++ {
				if args[index].value(commandText) == "-m" && isPip(basenameToken(args[index+1].value(commandText))) &&
					firstSubcommand(commandText, args[index+2:]) == "install" {
					return true
				}
			}
		}
	}

	for index, token := range tokens {
		if token.value(commandText) == "|" && isInstallerPipeAt(commandText, tokens, spans, index) {
			return true
		}
	}
	return false
}

func containsExactArg(commandText string, args []shellToken, names ...string) bool {
	for _, arg := range args {
		value := arg.value(commandText)
		for _, name := range names {
			if value == name {
				return true
			}
		}
	}
	return false
}

func containsShortFlag(commandText string, args []shellToken, flag byte) bool {
	for _, arg := range args {
		value := arg.value(commandText)
		if len(value) < 2 || value[0] != '-' || strings.HasPrefix(value, "--") {
			continue
		}
		for index := 1; index < len(value); index++ {
			if value[index] == flag {
				return true
			}
		}
	}
	return false
}

func hasHeredoc(commandText string, args []shellToken) bool {
	for _, arg := range args {
		value := arg.value(commandText)
		if value == "<<" || value == "<<-" || strings.HasPrefix(value, "<<") {
			return true
		}
	}
	return false
}

func nodeInlineEval(commandText string, args []shellToken) bool {
	for _, arg := range args {
		value := arg.value(commandText)
		if value == "-e" || value == "--eval" || value == "-p" || value == "--print" {
			return true
		}
		if strings.HasPrefix(value, "--eval=") || strings.HasPrefix(value, "--print=") {
			return true
		}
		if strings.HasPrefix(value, "-") && !strings.HasPrefix(value, "--") {
			flags := strings.TrimPrefix(value, "-")
			if strings.ContainsAny(flags, "ep") {
				return true
			}
		}
	}
	return false
}

func pythonInlineEval(commandText string, args []shellToken) bool {
	return containsShortFlag(commandText, args, 'c')
}

func perlOrRubyInlineEval(commandText string, args []shellToken) bool {
	for _, arg := range args {
		value := arg.value(commandText)
		if value == "-e" {
			return true
		}
		if strings.HasPrefix(value, "-") && !strings.HasPrefix(value, "--") && strings.Contains(strings.TrimPrefix(value, "-"), "e") {
			return true
		}
	}
	return false
}

func phpInlineEval(commandText string, args []shellToken) bool {
	for _, arg := range args {
		value := arg.value(commandText)
		if value == "-r" || value == "-B" || value == "-R" || value == "-E" {
			return true
		}
		if strings.HasPrefix(value, "-r") || strings.HasPrefix(value, "-B") ||
			strings.HasPrefix(value, "-R") || strings.HasPrefix(value, "-E") {
			return true
		}
	}
	return false
}

func genericInlineEval(commandText string, args []shellToken) bool {
	return containsShortFlag(commandText, args, 'e') || containsExactArg(commandText, args, "--eval")
}

func readsProgramFromStdin(commandText string, args []shellToken) bool {
	return hasHeredoc(commandText, args) || (len(args) > 0 && args[0].value(commandText) == "-")
}

func touchesScriptDir(token string) bool {
	normalized := strings.ReplaceAll(token, `\/`, "/")
	return strings.Contains(normalized, scriptDir) || strings.Contains(normalized, "/"+scriptDir) || strings.Contains(normalized, "./"+scriptDir)
}

func touchesExternalPath(token string) bool {
	normalized := strings.ReplaceAll(token, `\/`, "/")
	if strings.HasPrefix(normalized, "/") || strings.HasPrefix(normalized, "~/") {
		return true
	}
	if normalized == ".." || normalized == "../" || strings.HasPrefix(normalized, "../") {
		return true
	}
	if strings.Contains(normalized, "/../") {
		return true
	}
	if strings.HasSuffix(normalized, "/..") {
		return true
	}
	return false
}

func isInstallConfirmationSupported() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	if _, err := os.Stat("/usr/bin/osascript"); err != nil {
		return false
	}
	return true
}

// maxSubstitutionDepth bounds the mutual recursion between the command
// substitution scanner and the block-reason scan on deeply nested input.
const maxSubstitutionDepth = 32

func detectCommandSubstitutionReasonAtDepthInCwd(commandText string, installApproved bool, substDepth int, cwd string) string {
	if substDepth > maxSubstitutionDepth {
		return ""
	}
	inSingle := false
	inDouble := false
	escaped := false
	for i := 0; i < len(commandText); i++ {
		c := commandText[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && !inSingle {
			escaped = true
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if inSingle {
			continue
		}
		if c == '`' {
			end := -1
			innerSingle := false
			innerDouble := false
			innerEscaped := false
			for j := i + 1; j < len(commandText); j++ {
				cj := commandText[j]
				if innerEscaped {
					innerEscaped = false
					continue
				}
				if cj == '\\' && !innerSingle {
					innerEscaped = true
					continue
				}
				if cj == '\'' && !innerDouble {
					innerSingle = !innerSingle
					continue
				}
				if cj == '"' && !innerSingle {
					innerDouble = !innerDouble
					continue
				}
				if innerSingle || innerDouble {
					continue
				}
				if cj == '`' && !innerSingle && !innerDouble {
					end = j
					break
				}
			}
			if end == -1 {
				continue
			}
			inner := commandText[i+1 : end]
			if reason := detectBlockReasonAtDepthInCwd(inner, installApproved, substDepth+1, cwd); reason != "" {
				return reason
			}
			i = end
			continue
		}
		if c == '$' && i+1 < len(commandText) && commandText[i+1] == '(' {
			depth := 1
			innerSingle2 := false
			innerDouble2 := false
			innerEscaped2 := false
			end := -1
			for j := i + 2; j < len(commandText); j++ {
				cj := commandText[j]
				if innerEscaped2 {
					innerEscaped2 = false
					continue
				}
				if cj == '\\' && !innerSingle2 {
					innerEscaped2 = true
					continue
				}
				if cj == '\'' && !innerDouble2 {
					innerSingle2 = !innerSingle2
					continue
				}
				if cj == '"' && !innerSingle2 {
					innerDouble2 = !innerDouble2
					continue
				}
				if innerSingle2 || innerDouble2 {
					continue
				}
				if cj == '(' {
					depth++
				} else if cj == ')' {
					depth--
					if depth == 0 {
						end = j
						break
					}
				}
			}
			if end == -1 {
				continue
			}
			inner := commandText[i+2 : end]
			if reason := detectBlockReasonAtDepthInCwd(inner, installApproved, substDepth+1, cwd); reason != "" {
				return reason
			}
			i = end
			continue
		}
	}
	return ""
}

func detectDestructiveDeletionInCwd(commandText string, tokens []shellToken, spans []commandSpan, cwd string) string {
	for _, span := range spans {
		args := tokens[span.start+1 : span.end]
		name := span.name

		if !cwdAllowsProtectedConfig(cwd) && (name == "rm" || name == "rmdir" || name == "unlink" || name == "trash" || name == "trash-put") && anyTouchesProtectedPath(commandText, args) {
			return protectedConfigReason
		}
		if !cwdAllowsProtectedConfig(cwd) && (name == "mv" || name == "cp" || name == "tee") && len(args) > 0 && anyTouchesProtectedPath(commandText, args) {
			return protectedConfigReason
		}

		if (name == "rm" || name == "rmdir" || name == "unlink" || name == "trash" || name == "trash-put") && anyTouchesScriptDir(commandText, args) {
			return fmt.Sprintf("Blocked deletion of `%s` audit scripts. Leave generated scripts in place for review.", scriptDir)
		}
		if (name == "rm" || name == "rmdir" || name == "unlink" || name == "trash" || name == "trash-put") && anyTouchesExternalPath(commandText, args) {
			return "Blocked deletion outside the workspace. Keep cleanup commands scoped to explicit relative paths inside the current project."
		}

		if name == "mv" && len(args) > 0 && touchesScriptDir(args[0].value(commandText)) {
			return fmt.Sprintf("Blocked moving `%s` audit scripts out of the project. Leave generated scripts in place for review.", scriptDir)
		}

		if name == "find" && anyTouchesScriptDir(commandText, args) {
			for _, arg := range args {
				if arg.value(commandText) == "-delete" {
					return fmt.Sprintf("Blocked `find ... -delete` touching `%s` audit scripts.", scriptDir)
				}
			}
			for index := 0; index+1 < len(args); index++ {
				if args[index].value(commandText) == "-exec" {
					nextName := basenameToken(args[index+1].value(commandText))
					if nextName == "rm" || nextName == "rmdir" || nextName == "unlink" {
						return fmt.Sprintf("Blocked `find ... -exec rm` touching `%s` audit scripts.", scriptDir)
					}
				}
			}
		}

		if !cwdAllowsProtectedConfig(cwd) && name == "find" {
			loweredCmd := strings.ToLower(commandText)
			protectedInText := false
			for _, path := range policy.protectedPathsLower {
				if strings.Contains(loweredCmd, path) {
					protectedInText = true
					break
				}
			}
			if protectedInText {
				for _, arg := range args {
					if arg.value(commandText) == "-delete" {
						return protectedConfigReason
					}
				}
				for index := 0; index+1 < len(args); index++ {
					if args[index].value(commandText) == "-exec" {
						nextName := basenameToken(args[index+1].value(commandText))
						if nextName == "rm" || nextName == "rmdir" || nextName == "unlink" {
							return protectedConfigReason
						}
					}
				}
			}
		}

		if name == "git" && len(args) > 0 {
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
		}
	}

	for index := 0; index+1 < len(tokens); index++ {
		token := tokens[index].value(commandText)
		target := tokens[index+1].value(commandText)
		if touchesScriptDir(target) && (token == ">" || token == ">|" || token == "2>" || token == "&>") {
			return fmt.Sprintf("Blocked overwriting `%s` audit scripts via shell redirection.", scriptDir)
		}
		if !cwdAllowsProtectedConfig(cwd) && touchesProtectedPath(target) && (token == ">" || token == ">|" || token == ">>" || token == "2>" || token == "&>") {
			return protectedConfigReason
		}
	}
	return ""
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
	switch {
	case isNodeInterpreter(name):
		return nodeInlineEval(commandText, args)
	case isPythonInterpreter(name):
		return pythonInlineEval(commandText, args)
	case name == "perl" || name == "ruby":
		return perlOrRubyInlineEval(commandText, args)
	case name == "php":
		return phpInlineEval(commandText, args)
	case name == "osascript":
		return containsExactArg(commandText, args, "-e")
	case name == "bun" || name == "julia" || name == "lua" || name == "luajit" || name == "R" || name == "Rscript" || name == "swift":
		return genericInlineEval(commandText, args)
	case name == "deno":
		return len(args) > 0 && args[0].value(commandText) == "eval"
	case isShellInterpreter(name):
		return containsShortFlag(commandText, args, 'c')
	}
	return false
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

func startsInteractiveInterpreter(commandText string, name string, args []shellToken) bool {
	if len(args) == 0 {
		return isPipeInterpreter(name)
	}

	for _, arg := range args {
		value := arg.value(commandText)
		switch {
		case isPythonInterpreter(name), isShellInterpreter(name):
			if value == "--interactive" ||
				(strings.HasPrefix(value, "-") && !strings.HasPrefix(value, "--") &&
					strings.Contains(strings.TrimPrefix(value, "-"), "i")) {
				return true
			}
		case isNodeInterpreter(name):
			if value == "-i" || value == "--interactive" {
				return true
			}
		case name == "php":
			if value == "-a" || value == "--interactive" {
				return true
			}
		case name == "bun" || name == "deno":
			if value == "repl" {
				return true
			}
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
		if !commandReceivesPipe(commandText, tokens, span.start) &&
			startsInteractiveInterpreter(commandText, name, args) {
			return interactiveInterpreterRe
		}
	}

	for index := 0; index+1 < len(tokens); index++ {
		if tokens[index].value(commandText) != "|" {
			continue
		}
		nextIndex := index + 1
		for nextIndex < len(tokens) && isAssignment(tokens[nextIndex].value(commandText)) {
			nextIndex++
		}
		if nextIndex >= len(tokens) {
			continue
		}
		name := commandNameAfterWrappers(commandText, tokens, nextIndex)
		if isPipeInterpreter(name) {
			if installApproved && isInstallerPipeAt(commandText, tokens, spans, index) {
				continue
			}
			return fmt.Sprintf("Blocked pipe-to-interpreter (`| %s`). Pipe data to a normal file or use a workspace script under `%s` with explicit inputs.", name, scriptDir)
		}
	}

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
			if !allowProtected && touchesProtectedPath(pathText) {
				return protectedConfigReason
			}
		case strings.HasPrefix(line, addMarker):
			pathText := strings.TrimSpace(strings.TrimPrefix(line, addMarker))
			if !allowProtected && touchesProtectedPath(pathText) {
				return protectedConfigReason
			}
			currentUpdateTouchesScriptDir = false
		case strings.HasPrefix(line, deleteMarker):
			pathText := strings.TrimSpace(strings.TrimPrefix(line, deleteMarker))
			if touchesScriptDir(pathText) {
				return fmt.Sprintf("Blocked deletion of `%s` audit scripts. Leave generated scripts in place for review.", scriptDir)
			}
			if !allowProtected && touchesProtectedPath(pathText) {
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

func skipJSONSpace(data []byte, index int) int {
	for index < len(data) && isASCIISpace(data[index]) {
		index++
	}
	return index
}

func scanJSONString(data []byte, index int) (string, int, bool) {
	if index >= len(data) || data[index] != '"' {
		return "", index, false
	}
	start := index + 1
	for index = start; index < len(data); index++ {
		character := data[index]
		if character == '"' {
			return string(data[start:index]), index + 1, true
		}
		if character == '\\' {
			for cursor := index + 2; cursor < len(data); cursor++ {
				if data[cursor] == '\\' {
					cursor++
					continue
				}
				if data[cursor] == '"' {
					text, err := strconv.Unquote(string(data[start-1 : cursor+1]))
					return text, cursor + 1, err == nil
				}
			}
			return "", len(data), false
		}
		if character < 0x20 {
			return "", index, false
		}
	}
	return "", index, false
}

func skipJSONString(data []byte, index int) (int, bool) {
	if index >= len(data) || data[index] != '"' {
		return index, false
	}
	for index++; index < len(data); index++ {
		character := data[index]
		switch character {
		case '"':
			return index + 1, true
		case '\\':
			index++
			if index >= len(data) {
				return index, false
			}
			switch data[index] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				if index+4 >= len(data) {
					return len(data), false
				}
				for offset := 1; offset <= 4; offset++ {
					if !isJSONHex(data[index+offset]) {
						return index + offset, false
					}
				}
				index += 4
			default:
				return index, false
			}
		default:
			if character < 0x20 {
				return index, false
			}
		}
	}
	return index, false
}

func isJSONHex(character byte) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F'
}

func skipJSONNumber(data []byte, index int) (int, bool) {
	if index < len(data) && data[index] == '-' {
		index++
	}
	if index >= len(data) {
		return index, false
	}
	if data[index] == '0' {
		index++
	} else {
		if data[index] < '1' || data[index] > '9' {
			return index, false
		}
		for index < len(data) && data[index] >= '0' && data[index] <= '9' {
			index++
		}
	}
	if index < len(data) && data[index] == '.' {
		index++
		start := index
		for index < len(data) && data[index] >= '0' && data[index] <= '9' {
			index++
		}
		if index == start {
			return index, false
		}
	}
	if index < len(data) && (data[index] == 'e' || data[index] == 'E') {
		index++
		if index < len(data) && (data[index] == '+' || data[index] == '-') {
			index++
		}
		start := index
		for index < len(data) && data[index] >= '0' && data[index] <= '9' {
			index++
		}
		if index == start {
			return index, false
		}
	}
	return index, true
}

func skipJSONValue(data []byte, index int) (int, bool) {
	index = skipJSONSpace(data, index)
	if index >= len(data) {
		return index, false
	}
	switch data[index] {
	case '"':
		return skipJSONString(data, index)
	case '{':
		index++
		for {
			index = skipJSONSpace(data, index)
			if index >= len(data) {
				return index, false
			}
			if data[index] == '}' {
				return index + 1, true
			}
			var ok bool
			index, ok = skipJSONString(data, index)
			if !ok {
				return index, false
			}
			index = skipJSONSpace(data, index)
			if index >= len(data) || data[index] != ':' {
				return index, false
			}
			index, ok = skipJSONValue(data, index+1)
			if !ok {
				return index, false
			}
			index = skipJSONSpace(data, index)
			if index < len(data) && data[index] == ',' {
				index++
				if next := skipJSONSpace(data, index); next >= len(data) || data[next] == '}' {
					return next, false
				}
				continue
			}
			if index < len(data) && data[index] == '}' {
				return index + 1, true
			}
			return index, false
		}
	case '[':
		index++
		for {
			index = skipJSONSpace(data, index)
			if index >= len(data) {
				return index, false
			}
			if data[index] == ']' {
				return index + 1, true
			}
			var ok bool
			index, ok = skipJSONValue(data, index)
			if !ok {
				return index, false
			}
			index = skipJSONSpace(data, index)
			if index < len(data) && data[index] == ',' {
				index++
				if next := skipJSONSpace(data, index); next >= len(data) || data[next] == ']' {
					return next, false
				}
				continue
			}
			if index < len(data) && data[index] == ']' {
				return index + 1, true
			}
			return index, false
		}
	default:
		for _, literal := range []string{"true", "false", "null"} {
			if strings.HasPrefix(string(data[index:]), literal) {
				return index + len(literal), true
			}
		}
		return skipJSONNumber(data, index)
	}
}

func extractPayload(data []byte) payload {
	var result payload
	index := skipJSONSpace(data, 0)
	if index >= len(data) || data[index] != '{' {
		return result
	}
	index++
	for {
		index = skipJSONSpace(data, index)
		if index >= len(data) || data[index] == '}' {
			return result
		}
		key, next, ok := scanJSONString(data, index)
		if !ok {
			return payload{}
		}
		index = skipJSONSpace(data, next)
		if index >= len(data) || data[index] != ':' {
			return payload{}
		}
		valueStart := skipJSONSpace(data, index+1)
		valueEnd, ok := skipJSONValue(data, valueStart)
		if !ok {
			return payload{}
		}
		switch key {
		case "tool_name":
			if value, _, ok := scanJSONString(data, valueStart); ok {
				result.ToolName = value
			}
		case "tool_input":
			result.ToolInput = data[valueStart:valueEnd]
		case "cwd":
			if value, _, ok := scanJSONString(data, valueStart); ok {
				result.Cwd = value
			}
		}
		index = skipJSONSpace(data, valueEnd)
		if index < len(data) && data[index] == ',' {
			index++
			continue
		}
		if index < len(data) && data[index] == '}' {
			return result
		}
		return payload{}
	}
}

func extractCommand(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	var commandText, cmdText, shellCommandText string
	commandSet, cmdSet, shellCommandSet := false, false, false

	index := skipJSONSpace(input, 0)
	if index >= len(input) || input[index] != '{' {
		return ""
	}
	index++
	for {
		index = skipJSONSpace(input, index)
		if index >= len(input) || input[index] == '}' {
			break
		}
		key, next, ok := scanJSONString(input, index)
		if !ok {
			return ""
		}
		index = skipJSONSpace(input, next)
		if index >= len(input) || input[index] != ':' {
			return ""
		}
		valueStart := skipJSONSpace(input, index+1)
		valueEnd, ok := skipJSONValue(input, valueStart)
		if !ok {
			return ""
		}
		switch key {
		case "command":
			if value, _, ok := scanJSONString(input, valueStart); ok {
				commandText, commandSet = value, true
			}
		case "cmd":
			if value, _, ok := scanJSONString(input, valueStart); ok {
				cmdText, cmdSet = value, true
			}
		case "shell_command":
			if value, _, ok := scanJSONString(input, valueStart); ok {
				shellCommandText, shellCommandSet = value, true
			}
		}
		index = skipJSONSpace(input, valueEnd)
		if index < len(input) && input[index] == ',' {
			index++
			continue
		}
		if index < len(input) && input[index] == '}' {
			break
		}
		return ""
	}

	if commandSet {
		return commandText
	}
	if cmdSet {
		return cmdText
	}
	if shellCommandSet {
		return shellCommandText
	}
	return ""
}

func appendJSONString(buffer []byte, text string) []byte {
	const hex = "0123456789abcdef"
	buffer = append(buffer, '"')
	start := 0
	for index := 0; index < len(text); index++ {
		character := text[index]
		if character >= 0x20 && character != '\\' && character != '"' {
			continue
		}
		buffer = append(buffer, text[start:index]...)
		switch character {
		case '\\', '"':
			buffer = append(buffer, '\\', character)
		case '\b':
			buffer = append(buffer, '\\', 'b')
		case '\f':
			buffer = append(buffer, '\\', 'f')
		case '\n':
			buffer = append(buffer, '\\', 'n')
		case '\r':
			buffer = append(buffer, '\\', 'r')
		case '\t':
			buffer = append(buffer, '\\', 't')
		default:
			buffer = append(buffer, '\\', 'u', '0', '0', hex[character>>4], hex[character&0x0f])
		}
		start = index + 1
	}
	buffer = append(buffer, text[start:]...)
	buffer = append(buffer, '"')
	return buffer
}

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
	message := denialMessage(commandText, reason)
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
		reason = evaluateShellCommandInCwd(commandText, data.Cwd)
	}

	integration := resolveIntegration(false)
	if reason != "" {
		deny(commandText, reason)
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
