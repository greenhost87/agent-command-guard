package main

import (
	"strconv"
	"strings"
)

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

func skipJSONDigits(data []byte, index int) (int, bool) {
	start := index
	for index < len(data) && data[index] >= '0' && data[index] <= '9' {
		index++
	}
	return index, index > start
}

func isJSONExponent(character byte) bool { return character == 'e' || character == 'E' }
func isJSONSign(character byte) bool     { return character == '+' || character == '-' }

func skipJSONNumber(data []byte, index int) (int, bool) {
	if index < len(data) && data[index] == '-' {
		index++
	}
	if index >= len(data) {
		return index, false
	}
	if data[index] == '0' {
		index++
	} else if data[index] < '1' || data[index] > '9' {
		return index, false
	} else {
		index, _ = skipJSONDigits(data, index)
	}
	if index < len(data) && data[index] == '.' {
		var ok bool
		index, ok = skipJSONDigits(data, index+1)
		if !ok {
			return index, false
		}
	}
	if index < len(data) && isJSONExponent(data[index]) {
		index++
		if index < len(data) && isJSONSign(data[index]) {
			index++
		}
		return skipJSONDigits(data, index)
	}
	return index, true
}

func skipJSONObjectKey(data []byte, index int) (int, bool) {
	next, ok := skipJSONString(data, index)
	next = skipJSONSpace(data, next)
	if !ok || next >= len(data) || data[next] != ':' {
		return next, false
	}
	return next + 1, true
}

func skipJSONSequence(data []byte, index int, object bool) (int, bool) {
	closing := byte(']')
	if object {
		closing = '}'
	}
	for {
		index = skipJSONSpace(data, index)
		if index >= len(data) || data[index] == closing {
			return index + 1, index < len(data)
		}
		if object {
			var ok bool
			index, ok = skipJSONObjectKey(data, index)
			if !ok {
				return index, false
			}
		}
		var ok bool
		index, ok = skipJSONValue(data, index)
		if !ok {
			return index, false
		}
		index = skipJSONSpace(data, index)
		if index < len(data) && data[index] == closing {
			return index + 1, true
		}
		if index >= len(data) {
			return index, false
		}
		if data[index] != ',' {
			return index, false
		}
		index = skipJSONSpace(data, index+1)
		if index >= len(data) {
			return index, false
		}
		if data[index] == closing {
			return index, false
		}
	}
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
		return skipJSONSequence(data, index+1, true)
	case '[':
		return skipJSONSequence(data, index+1, false)
	default:
		for _, literal := range []string{"true", "false", "null"} {
			if strings.HasPrefix(string(data[index:]), literal) {
				return index + len(literal), true
			}
		}
		return skipJSONNumber(data, index)
	}
}

func scanJSONObject(data []byte, visit func(string, int, int)) bool {
	index := skipJSONSpace(data, 0)
	if index >= len(data) || data[index] != '{' {
		return false
	}
	for index++; ; {
		index = skipJSONSpace(data, index)
		if index < len(data) && data[index] == '}' {
			return true
		}
		key, next, ok := scanJSONString(data, index)
		index = skipJSONSpace(data, next)
		if !ok || index >= len(data) || data[index] != ':' {
			return false
		}
		start := skipJSONSpace(data, index+1)
		end, ok := skipJSONValue(data, start)
		if !ok {
			return false
		}
		visit(key, start, end)
		index = skipJSONSpace(data, end)
		if index < len(data) && data[index] == '}' {
			return true
		}
		if index >= len(data) || data[index] != ',' {
			return false
		}
		index++
	}
}

func extractPayload(data []byte) payload {
	var result payload
	valid := scanJSONObject(data, func(key string, start, end int) {
		value, _, stringOK := scanJSONString(data, start)
		switch key {
		case "tool_name":
			if stringOK {
				result.ToolName = value
			}
		case "tool_input":
			result.ToolInput = data[start:end]
		case "cwd":
			if stringOK {
				result.Cwd = value
			}
		}
	})
	if !valid {
		return payload{}
	}
	return result
}

func extractCommand(input []byte) string {
	values := make(map[string]string, 3)
	valid := scanJSONObject(input, func(key string, start, _ int) {
		if value, _, ok := scanJSONString(input, start); ok {
			values[key] = value
		}
	})
	if !valid {
		return ""
	}
	for _, key := range []string{"command", "cmd", "shell_command"} {
		if value, ok := values[key]; ok {
			return value
		}
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
