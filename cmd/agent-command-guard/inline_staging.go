package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

// literalWords tokenizes only a simple shell command. This is deliberately
// narrower than the policy scanner: anything requiring shell evaluation is
// still denied, but never written as a guessed program.
func literalWords(command string) ([]string, bool) {
	if strings.ContainsRune(command, 0) {
		return nil, false
	}
	var words []string
	for i := 0; i < len(command); {
		if command[i] == ' ' || command[i] == '\t' {
			i++
			continue
		}
		start := i
		var quote byte
		for i < len(command) {
			c := command[i]
			if quote == '\'' {
				if c == '\'' {
					quote = 0
				}
				i++
				continue
			}
			if quote == '"' {
				switch c {
				case '"':
					quote = 0
				case '$', '`':
					return nil, false
				case '\\':
					if i+1 >= len(command) || (command[i+1] != '"' && command[i+1] != '\\') {
						return nil, false
					}
					i++
				}
				i++
				continue
			}
			if c == ' ' || c == '\t' {
				break
			}
			switch c {
			case '\'', '"':
				quote = c
			case '$', '`', '\\', '\n', '\r', '|', '&', ';', '<', '>', '(', ')', '*', '?', '[', ']', '{', '}', '#', '~':
				return nil, false
			}
			i++
		}
		if quote != 0 {
			return nil, false
		}
		words = append(words, command[start:i])
	}
	return words, true
}

// literalCode requires exactly one quoted shell word (not concatenated words).
func literalCode(raw string) (string, bool) {
	if len(raw) < 2 || raw[len(raw)-1] != raw[0] {
		return "", false
	}
	inner := raw[1 : len(raw)-1]
	switch raw[0] {
	case '\'':
		return inner, !strings.ContainsRune(inner, '\'')
	case '"':
		var code strings.Builder
		for i := 0; i < len(inner); i++ {
			switch inner[i] {
			case '"', '$', '`':
				return "", false
			case '\\':
				i++
				if i >= len(inner) || (inner[i] != '"' && inner[i] != '\\') {
					return "", false
				}
			}
			code.WriteByte(inner[i])
		}
		return code.String(), true
	}
	return "", false
}

func unwrapLiteralInterpreter(words []string) ([]string, bool) {
	if len(words) == 0 {
		return nil, false
	}
	if words[0] == "rtk" {
		words = words[1:]
		if len(words) > 0 && strings.EqualFold(words[0], "proxy") {
			words = words[1:]
		}
	}
	if len(words) == 0 || words[0] != commandNameToken(words[0]) {
		return nil, false
	}
	return words, true
}

func interpreterExtension(name string) string {
	switch {
	case isNodeInterpreter(name):
		return ".js"
	case isPythonInterpreter(name):
		return ".py"
	case name == "bun":
		return ".ts"
	default:
		return ""
	}
}

func extractInlineScript(command string) (code, extension string, ok bool) {
	words, valid := literalWords(command)
	if !valid || len(words) < 2 {
		return "", "", false
	}
	words, valid = unwrapLiteralInterpreter(words)
	if !valid || len(words) < 2 {
		return "", "", false
	}
	name := words[0]
	extension = interpreterExtension(name)
	var raw string
	switch {
	case isNodeInterpreter(name):
		args := words[1:]
		if len(args) == 3 && args[0] == "--input-type=module" {
			args = args[1:]
		} else if len(args) == 4 && args[0] == "--input-type" && args[1] == "module" {
			args = args[2:]
		}
		if len(args) == 2 && (args[0] == "-e" || args[0] == "--eval") {
			raw = args[1]
		} else if len(args) == 1 && strings.HasPrefix(args[0], "--eval=") {
			raw = strings.TrimPrefix(args[0], "--eval=")
		}
	case isPythonInterpreter(name):
		if len(words) == 3 && words[1] == "-c" {
			raw = words[2]
		}
	case name == "bun":
		if len(words) == 3 && (words[1] == "-e" || words[1] == "--eval") {
			raw = words[2]
		} else if len(words) == 2 && strings.HasPrefix(words[1], "--eval=") {
			raw = strings.TrimPrefix(words[1], "--eval=")
		}
	}
	code, ok = literalCode(raw)
	return code, extension, ok && extension != ""
}

// openLiteralDirectory pins each directory before accessing the next one.
// Matching the opened directory to its lstat rejects symlink components,
// including a component swapped between the check and open.
func openLiteralDirectory(root *os.Root, name string, create bool) (*os.Root, error) {
	info, err := root.Lstat(name)
	if os.IsNotExist(err) && create {
		if err = root.Mkdir(name, 0o700); err != nil && !os.IsExist(err) {
			return nil, err
		}
		info, err = root.Lstat(name)
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, os.ErrInvalid
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, err := child.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = child.Close()
		return nil, os.ErrInvalid
	}
	return child, nil
}

func extractStdinHeredoc(command string) (string, string, bool) {
	lines := strings.Split(command, "\n")
	if len(lines) < 3 {
		return "", "", false
	}
	header := lines[0]
	if strings.HasSuffix(header, "\r") {
		header = strings.TrimSuffix(header, "\r")
	}
	fields := strings.Fields(header)
	fields, valid := unwrapLiteralInterpreter(fields)
	if !valid || len(fields) < 2 || len(fields) > 3 {
		return "", "", false
	}
	extension := interpreterExtension(fields[0])
	if extension == "" || (len(fields) == 3 && fields[1] != "-") {
		return "", "", false
	}
	redir := fields[len(fields)-1]
	if !strings.HasPrefix(redir, "<<") || strings.HasPrefix(redir, "<<-") {
		return "", "", false
	}
	delimiter := strings.TrimPrefix(redir, "<<")
	if len(delimiter) < 3 || (delimiter[0] != '\'' && delimiter[0] != '"') || delimiter[len(delimiter)-1] != delimiter[0] {
		return "", "", false
	}
	delimiter = delimiter[1 : len(delimiter)-1]
	if delimiter == "" || strings.ContainsAny(delimiter, " \t\\\"'$") {
		return "", "", false
	}
	end := -1
	for index := 1; index < len(lines); index++ {
		if strings.TrimSuffix(lines[index], "\r") == delimiter {
			end = index
			break
		}
	}
	if end < 0 {
		return "", "", false
	}
	for _, trailing := range lines[end+1:] {
		if strings.TrimSpace(strings.TrimSuffix(trailing, "\r")) != "" {
			return "", "", false
		}
	}
	return strings.Join(lines[1:end], "\n") + "\n", extension, true
}

func extractPythonHeredoc(command string) (string, bool) {
	code, extension, ok := extractStdinHeredoc(command)
	return code, ok && extension == ".py"
}

func stageInlineScript(command, cwd string) string {
	if !filepath.IsAbs(cwd) || cwd != filepath.Clean(cwd) || cwd == string(filepath.Separator) || scriptDir != ".codex/tmp-scripts" {
		return ""
	}
	code, extension, ok := extractInlineScript(command)
	if !ok {
		code, extension, ok = extractStdinHeredoc(command)
	}
	if !ok {
		return ""
	}
	root, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return ""
	}
	defer func() { _ = root.Close() }()
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(cwd), string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		child, err := openLiteralDirectory(root, component, false)
		if err != nil {
			return ""
		}
		_ = root.Close()
		root = child
	}
	for _, component := range []string{".codex", "tmp-scripts"} {
		child, err := openLiteralDirectory(root, component, true)
		if err != nil {
			return ""
		}
		_ = root.Close()
		root = child
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return ""
	}
	filename := "inline-" + hex.EncodeToString(random[:]) + extension
	file, err := root.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ""
	}
	_, writeErr := file.WriteString(code)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = root.Remove(filename)
		return ""
	}
	return filepath.ToSlash(filepath.Join(scriptDir, filename))
}

func commandForStagedScript(command, scriptPath string) (string, bool) {
	words, valid := literalWords(command)
	var executionFlags []string
	if valid {
		if _, _, ok := extractInlineScript(command); !ok {
			return "", false
		}
	} else {
		if _, _, ok := extractStdinHeredoc(command); !ok {
			return "", false
		}
		lines := strings.SplitN(command, "\n", 2)
		words = strings.Fields(strings.TrimSuffix(lines[0], "\r"))
	}
	prefix := ""
	if len(words) > 0 && words[0] == "rtk" {
		prefix = words[0] + " "
		words = words[1:]
		if len(words) > 0 && strings.EqualFold(words[0], "proxy") {
			prefix += words[0] + " "
			words = words[1:]
		}
	}
	if len(words) == 0 || words[0] != commandNameToken(words[0]) {
		return "", false
	}
	interpreter := words[0]
	if valid && isNodeInterpreter(interpreter) {
		args := words[1:]
		if len(args) == 4 && args[0] == "--input-type" && args[1] == "module" {
			executionFlags = args[:2]
		} else if len(args) == 3 && args[0] == "--input-type=module" {
			executionFlags = args[:1]
		}
	}
	executionArgs := append(executionFlags, "'"+scriptPath+"'")
	return prefix + interpreter + " " + strings.Join(executionArgs, " "), true
}

func shellDenialMessage(command, cwd, reason string) string {
	if reason == inlineInterpreterReason || reason == stdinInterpreterReason {
		if path := stageInlineScript(command, cwd); path != "" {
			return "Blocked shell command.\n" + reason + "\nSaved interpreter code to " + path + "; original command was not run. Review the file before running it as a script."
		}
	}
	return denialMessage(command, reason)
}
