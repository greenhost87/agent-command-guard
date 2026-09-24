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

func extractInlineScript(command string) (code, extension string, ok bool) {
	words, valid := literalWords(command)
	if !valid || len(words) < 2 {
		return "", "", false
	}
	name := commandNameToken(words[0])
	if words[0] != name { // No wrappers or executable paths in the first version.
		return "", "", false
	}
	var raw string
	switch {
	case isNodeInterpreter(name):
		extension = ".js"
		if len(words) == 3 && (words[1] == "-e" || words[1] == "--eval") {
			raw = words[2]
		} else if len(words) == 2 && strings.HasPrefix(words[1], "--eval=") {
			raw = strings.TrimPrefix(words[1], "--eval=")
		}
	case isPythonInterpreter(name):
		extension = ".py"
		if len(words) == 3 && words[1] == "-c" {
			raw = words[2]
		}
	}
	code, ok = literalCode(raw)
	return code, extension, ok
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

func stageInlineScript(command, cwd string) string {
	if !filepath.IsAbs(cwd) || cwd != filepath.Clean(cwd) || cwd == string(filepath.Separator) || scriptDir != ".codex/tmp-scripts" {
		return ""
	}
	code, extension, ok := extractInlineScript(command)
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

func shellDenialMessage(command, cwd, reason string) string {
	if reason == inlineInterpreterReason {
		if path := stageInlineScript(command, cwd); path != "" {
			return "Blocked shell command.\n" + reason + "\nSaved inline code to " + path + "; original command was not run. Review the file before running it as a script (eval and file argument semantics may differ)."
		}
	}
	return denialMessage(command, reason)
}
