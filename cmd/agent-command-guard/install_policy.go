package main

import (
	"os"
	"runtime"
	"strings"
)

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

func spanRequiresInstallConfirmation(commandText string, tokens []shellToken, span commandSpan) bool {
	args := tokens[span.start+1 : span.end]
	subcommand := firstSubcommand(commandText, args)
	if span.name == "brew" {
		for _, action := range []string{"install", "reinstall", "upgrade", "bundle"} {
			if subcommand == action {
				return true
			}
		}
	}
	if isPip(span.name) {
		return subcommand == "install"
	}
	if !isPythonInterpreter(span.name) {
		return false
	}
	for index := 0; index+1 < len(args); index++ {
		if args[index].value(commandText) == "-m" && isPip(basenameToken(args[index+1].value(commandText))) && firstSubcommand(commandText, args[index+2:]) == "install" {
			return true
		}
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
		if spanRequiresInstallConfirmation(commandText, tokens, span) {
			return true
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
