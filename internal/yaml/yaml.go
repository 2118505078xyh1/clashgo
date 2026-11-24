// Package yaml implements the subset of YAML used by ClashGo profiles and
// settings, using only the Go standard library.
//
// It intentionally mirrors the small public surface of go.yaml.in/yaml/v3
// that the rest of the project relies on: Unmarshal, Marshal and
// MarshalIndent. Scalars, block/flow collections, comments, block scalars and
// anchors are understood; struct fields are matched via `yaml:"name"` tags.
package yaml

import (
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unicode"
)

// Unmarshal parses a YAML document and stores the result in out, which must
// be a non-nil pointer. Fields that are absent from the document keep their
// existing values (so callers can pre-fill defaults).
func Unmarshal(data []byte, out any) error {
	if out == nil {
		return fmt.Errorf("yaml: Unmarshal(nil)")
	}
	v := reflect.ValueOf(out)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return fmt.Errorf("yaml: Unmarshal(non-pointer %T)", out)
	}
	node, err := parseDocument(data)
	if err != nil {
		return err
	}
	if node == nil {
		return nil
	}
	return decodeValue(node, v.Elem())
}

// Marshal serialises v to YAML. It uses the four-space indentation of
// go.yaml.in/yaml/v3; use MarshalIndent for a different indentation.
func Marshal(v any) ([]byte, error) {
	return marshalValue(v, "", "    ")
}

// MarshalIndent is like Marshal but prefixes every line with prefix and uses
// indent (normally two spaces) for each nesting level.
func MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	if indent == "" {
		indent = "    "
	}
	return marshalValue(v, prefix, indent)
}

// ---------------------------------------------------------------------------
// Scalar resolution (plain scalars -> Go values)
// ---------------------------------------------------------------------------

// resolvePlain converts an unquoted YAML scalar to its natural Go type.
func resolvePlain(s string) any {
	if s == "" {
		return nil
	}
	switch strings.ToLower(s) {
	case "~", "null":
		return nil
	case "true", "yes", "on":
		return true
	case "false", "no", "off":
		return false
	case ".inf", "+.inf":
		return math.Inf(1)
	case "-.inf":
		return math.Inf(-1)
	case ".nan":
		return math.NaN()
	}

	t := strings.ReplaceAll(s, "_", "")

	// Hexadecimal / octal / binary integers.
	if len(t) > 2 && t[0] == '0' {
		switch t[1] {
		case 'x', 'X', 'o', 'O', 'b', 'B':
			if n, err := strconv.ParseInt(t, 0, 64); err == nil {
				return int(n)
			}
			if n, err := strconv.ParseUint(t, 0, 64); err == nil {
				return uint64(n)
			}
		}
	}

	// Decimal integers.
	if isDecimalInt(t) {
		if n, err := strconv.ParseInt(t, 10, 64); err == nil {
			if int64(int(n)) == n {
				return int(n)
			}
			return n
		}
		if n, err := strconv.ParseUint(t, 10, 64); err == nil {
			return n
		}
	}

	// Floating point numbers.
	if strings.ContainsAny(t, ".eE") {
		if f, err := strconv.ParseFloat(t, 64); err == nil {
			return f
		}
	}
	return s
}

func isDecimalInt(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '+' || s[0] == '-' {
		i++
	}
	if i == len(s) {
		return false
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Quoting / comments
// ---------------------------------------------------------------------------

// stripComment removes an inline YAML comment (a # preceded by whitespace or
// at the start of the text). Quotes are respected, including escaped quotes
// inside double-quoted strings.
func stripComment(s string) string {
	var quote byte
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && c == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				if quote == '\'' && i+1 < len(s) && s[i+1] == '\'' {
					i++ // doubled '' inside single quotes
				} else {
					quote = 0
				}
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '#':
			if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
				return strings.TrimRight(s[:i], " \t")
			}
		}
	}
	return strings.TrimRight(s, " \t")
}

// unquoteString decodes a single- or double-quoted YAML scalar. ok is false
// when s is not a quoted scalar.
func unquoteString(s string) (string, bool) {
	if len(s) < 2 {
		return "", false
	}
	switch s[0] {
	case '\'':
		if s[len(s)-1] != '\'' {
			return "", false
		}
		inner := s[1 : len(s)-1]
		return strings.ReplaceAll(inner, "''", "'"), true
	case '"':
		if s[len(s)-1] != '"' {
			return "", false
		}
		return unescapeDouble(s[1 : len(s)-1]), true
	}
	return "", false
}

func unescapeDouble(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch s[i] {
		case '0':
			b.WriteByte(0)
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 't', '\t':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		case 'v':
			b.WriteByte('\v')
		case 'f':
			b.WriteByte('\f')
		case 'r':
			b.WriteByte('\r')
		case 'e':
			b.WriteByte(0x1b)
		case ' ':
			b.WriteByte(' ')
		case '"':
			b.WriteByte('"')
		case '/':
			b.WriteByte('/')
		case '\\':
			b.WriteByte('\\')
		case 'N':
			b.WriteRune('\u0085')
		case '_':
			b.WriteRune('\u00a0')
		case 'L':
			b.WriteRune('\u2028')
		case 'P':
			b.WriteRune('\u2029')
		case 'x', 'u', 'U':
			n := 2
			if s[i] == 'u' {
				n = 4
			} else if s[i] == 'U' {
				n = 8
			}
			if i+n < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+1+n], 16, 32); err == nil {
					b.WriteRune(rune(v))
					i += n
					continue
				}
			}
			b.WriteByte(s[i])
		case '\n':
			// Escaped line break: skip following indentation.
			for i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '\t') {
				i++
			}
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// scalarText converts an already comment-stripped scalar token to a Go value.
func scalarText(s string) any {
	s = strings.TrimSpace(s)
	if v, ok := unquoteString(s); ok {
		return v
	}
	return resolvePlain(s)
}

// ---------------------------------------------------------------------------
// Helpers shared by parser and encoder
// ---------------------------------------------------------------------------

// findMapColon returns the index of the key/value separator colon in a
// mapping entry, or -1. Colons inside quotes or flow collections are ignored.
func findMapColon(s string) int {
	var quote byte
	escaped := false
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && c == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				if quote == '\'' && i+1 < len(s) && s[i+1] == '\'' {
					i++
				} else {
					quote = 0
				}
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '[', '{':
			depth++
		case ']', '}':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 && (i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t') {
				return i
			}
		}
	}
	return -1
}

// leadingSpace counts spaces (and, leniently, tabs) at the start of s.
func leadingSpace(s string) int {
	n := 0
	for n < len(s) && (s[n] == ' ' || s[n] == '\t') {
		n++
	}
	return n
}

// isBlank reports whether s contains only whitespace.
func isBlank(s string) bool {
	return strings.TrimSpace(s) == ""
}

// isSeqMarker reports whether the text starts a block sequence item.
func isSeqMarker(s string) bool {
	return s == "-" || strings.HasPrefix(s, "- ") || strings.HasPrefix(s, "-\t")
}

// needsQuotes reports whether a plain scalar cannot be emitted verbatim.
func needsQuotes(s string) bool {
	if s == "" {
		return true
	}
	if isBlank(s) || strings.TrimSpace(s) != s {
		return true
	}
	if strings.ContainsAny(s, "\n\r\t") {
		return true
	}
	if strings.Contains(s, " #") || strings.HasPrefix(s, "#") {
		return true
	}
	// Indicators only need escaping when they lead a scalar; commas and
	// brackets inside a plain scalar are legal in block context.
	if strings.ContainsRune("[]{}&,!|>'\"%@`*", rune(s[0])) {
		return true
	}
	if s[0] == '-' || s[0] == '?' || s[0] == ':' {
		if len(s) == 1 || s[1] == ' ' || s[1] == '\t' {
			return true
		}
	}
	if findMapColon(s) >= 0 {
		return true
	}
	switch strings.ToLower(s) {
	case "~", "null", "true", "false", "yes", "no", "on", "off",
		".inf", "+.inf", "-.inf", ".nan":
		return true
	}
	if _, ok := resolvePlain(s).(string); !ok {
		return true
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// quoteScalar renders s as a double-quoted YAML scalar.
func quoteScalar(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if unicode.IsControl(r) {
				b.WriteString(fmt.Sprintf(`\x%02X`, r))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
