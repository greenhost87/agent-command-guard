package main

import (
	"path"
	"path/filepath"
	"strings"
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
