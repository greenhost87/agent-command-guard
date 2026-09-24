package main

import (
	"strings"
	"unicode/utf8"
)

type shellLexer struct {
	text                 string
	tokens               []shellToken
	cooked               strings.Builder
	tokenStart, rawStart int
	cookedMode           bool
	quote                byte
	escaped              bool
}

func (lexer *shellLexer) begin(index int) {
	if lexer.tokenStart < 0 {
		lexer.tokenStart, lexer.rawStart = index, index
	}
}

func (lexer *shellLexer) ensureCooked(index int) {
	lexer.cookedMode = true
	if lexer.rawStart < index {
		lexer.cooked.WriteString(lexer.text[lexer.rawStart:index])
	}
}

func (lexer *shellLexer) flush(end int) {
	if lexer.tokenStart < 0 {
		return
	}
	if lexer.cookedMode {
		if lexer.rawStart < end {
			lexer.cooked.WriteString(lexer.text[lexer.rawStart:end])
		}
		if lexer.cooked.Len() > 0 {
			lexer.tokens = append(lexer.tokens, shellToken{text: lexer.cooked.String()})
		}
		lexer.cooked.Reset()
		lexer.cookedMode = false
	} else if lexer.tokenStart < end {
		lexer.tokens = append(lexer.tokens, shellToken{start: lexer.tokenStart, end: end})
	}
	lexer.tokenStart, lexer.rawStart = -1, end
}

func (lexer *shellLexer) escapedStep(index int) int {
	width := 1
	if lexer.text[index] >= utf8.RuneSelf {
		_, width = utf8.DecodeRuneInString(lexer.text[index:])
	}
	lexer.cooked.WriteString(lexer.text[index : index+width])
	lexer.rawStart, lexer.escaped = index+width, false
	return index + width
}

func (lexer *shellLexer) plainStep(index int) int {
	character := lexer.text[index]
	if character == '\\' {
		lexer.begin(index)
		lexer.ensureCooked(index)
		lexer.rawStart, lexer.escaped = index+1, true
		return index + 1
	}
	if character == '\'' || character == '"' {
		lexer.begin(index)
		lexer.ensureCooked(index)
		lexer.rawStart, lexer.quote = index+1, character
		return index + 1
	}
	if character < utf8.RuneSelf && isASCIISpace(character) {
		lexer.flush(index)
		lexer.rawStart = index + 1
		return index + 1
	}
	if character >= utf8.RuneSelf {
		runeValue, width := utf8.DecodeRuneInString(lexer.text[index:])
		if isUnicodeSpace(runeValue) {
			lexer.flush(index)
			lexer.rawStart = index + width
		} else {
			lexer.begin(index)
		}
		return index + width
	}
	if isPunctuation(character) {
		return lexer.punctuationStep(index, character)
	}
	lexer.begin(index)
	return index + 1
}

func (lexer *shellLexer) punctuationStep(index int, character byte) int {
	lexer.flush(index)
	width := 1
	if index+1 < len(lexer.text) && repeatedPunctuation(character, lexer.text[index+1]) {
		width = 2
	}
	lexer.tokens = append(lexer.tokens, shellToken{start: index, end: index + width})
	lexer.rawStart = index + width
	return index + width
}

func shellTokens(commandText string, tokens []shellToken) []shellToken {
	lexer := shellLexer{text: commandText, tokens: tokens, tokenStart: -1}
	for index := 0; index < len(commandText); {
		if lexer.escaped {
			index = lexer.escapedStep(index)
			continue
		}
		if lexer.quote != 0 {
			if commandText[index] == lexer.quote {
				lexer.ensureCooked(index)
				lexer.rawStart, lexer.quote = index+1, 0
			}
			index++
			continue
		}
		index = lexer.plainStep(index)
	}
	if lexer.escaped {
		lexer.cooked.WriteByte('\\')
		lexer.rawStart = len(commandText)
	}
	lexer.flush(len(commandText))
	return lexer.tokens
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

func finishCommandSpan(spans []commandSpan, current commandSpan, active bool, end int) []commandSpan {
	if active {
		current.end = end
		return append(spans, current)
	}
	return spans
}

func isCommandBoundary(token string) bool {
	return isSeparator(token) || token == "(" || token == ")" || isShellKeyword(token)
}
func isIgnoredCommandPrefix(token string) bool {
	if isAssignment(token) || strings.HasPrefix(token, "-") {
		return true
	}
	for _, redirection := range []string{">", ">>", "<", "<<", "2", "1"} {
		if token == redirection {
			return true
		}
	}
	return false
}

func skipRTKPrefix(commandText string, tokens []shellToken, index int) (int, string) {
	index++
	for index < len(tokens) && strings.HasPrefix(tokens[index].value(commandText), "-") {
		index++
	}
	if index < len(tokens) && strings.EqualFold(tokens[index].value(commandText), "run") {
		return index, "rtk run"
	}
	if index < len(tokens) && strings.EqualFold(tokens[index].value(commandText), "proxy") {
		index++
	}
	return index, ""
}

func skipCommandPrefix(commandText string, tokens []shellToken, index int) (int, string) {
	for index < len(tokens) {
		token := tokens[index].value(commandText)
		if isCommandBoundary(token) {
			return index, ""
		}
		if isIgnoredCommandPrefix(token) {
			index++
			continue
		}
		name := commandNameToken(token)
		if name == "env" {
			index = skipEnv(commandText, tokens, index)
			continue
		}
		if name == "rtk" {
			var rtkName string
			index, rtkName = skipRTKPrefix(commandText, tokens, index)
			if rtkName != "" {
				return index, rtkName
			}
			continue
		}
		if isWrapper(name) {
			index++
			continue
		}
		return index, name
	}
	return index, ""
}

func commandSpans(commandText string, tokens []shellToken, spans []commandSpan) []commandSpan {
	expectCommand, active := true, false
	current := commandSpan{}
	for index := 0; index < len(tokens); {
		token := tokens[index].value(commandText)
		if isSeparator(token) || token == "(" || token == ")" || isShellKeyword(token) {
			spans = finishCommandSpan(spans, current, active, index)
			expectCommand, active, index = true, false, index+1
			continue
		}
		if !expectCommand {
			index++
			continue
		}
		start, name := skipCommandPrefix(commandText, tokens, index)
		if name == "" {
			if start > index {
				index = start
				continue
			}
			return finishCommandSpan(spans, current, active, len(tokens))
		}
		current = commandSpan{name: name, start: start, end: len(tokens)}
		expectCommand, active, index = false, true, start+1
	}
	return finishCommandSpan(spans, current, active, len(tokens))
}
