// Package cfgscript implements a tiny, dependency-free interpreter for the
// small JS/Lua subset used by configuration enhancement scripts.
//
// It intentionally is not a general purpose language engine. It only knows
// how to locate a `function main(config, profileName) ...` wrapper and execute
// the handful of statements/expressions that real enhancement scripts use:
// assignments into nested maps/slices, array/object literals, console.*
// logging, `return config` and `throw`.
package cfgscript

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Config is the config map passed to and returned from scripts.
type Config = map[string]any

// arrayBase is the numeric index base used by the mini interpreter. The
// reference Lua-style scripts index lists starting at 1 (config.proxies[1]),
// and the JS-shaped samples in the profile scripts use the same convention.
const arrayBase = 1

// Run executes scriptSrc against a private deep copy of config. On any parse
// or runtime error the original config is returned unchanged together with an
// error; console output is appended to *logs (when logs is non-nil).
func Run(scriptSrc string, config Config, profileName string, logs *[]string) (Config, error) {
	work, err := cloneConfig(config)
	if err != nil {
		return config, err
	}

	toks, err := (&lexer{src: scriptSrc}).tokens()
	if err != nil {
		return config, err
	}

	p := &parser{
		toks: toks,
		env:  make(map[string]any),
		logs: logs,
	}
	result, err := p.execute(work, profileName)
	if err != nil {
		return config, err
	}

	out, ok := result.(map[string]any)
	if !ok || out == nil {
		return config, fmt.Errorf("main must return a config object")
	}
	return out, nil
}

// cloneConfig normalises the config through JSON so that all numbers become
// float64 and nested values become plain map[string]any / []any. It also makes
// sure a script failure can never mutate the caller's config.
func cloneConfig(config Config) (Config, error) {
	if config == nil {
		return Config{}, nil
	}
	b, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	var out Config
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = Config{}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

type token struct {
	typ  string // "ident", "num", "str", "EOF", or a single punctuation char
	text string // raw identifier/number text
	sval string // decoded string value
	nval float64
	pos  int
}

type lexer struct {
	src string
	pos int
}

func (l *lexer) tokens() ([]token, error) {
	var out []token
	for l.pos < len(l.src) {
		c := l.src[l.pos]

		// Whitespace (including newlines, which separate Lua statements).
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			l.pos++
			continue
		}

		// C-style comments and Lua-style line comments.
		if c == '/' && l.pos+1 < len(l.src) {
			if l.src[l.pos+1] == '/' {
				for l.pos < len(l.src) && l.src[l.pos] != '\n' {
					l.pos++
				}
				continue
			}
			if l.src[l.pos+1] == '*' {
				l.pos += 2
				for l.pos+1 < len(l.src) && !(l.src[l.pos] == '*' && l.src[l.pos+1] == '/') {
					l.pos++
				}
				if l.pos+1 < len(l.src) {
					l.pos += 2
				}
				continue
			}
		}
		if c == '-' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '-' {
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
			continue
		}

		// String literals.
		if c == '"' || c == '\'' {
			tok, err := l.readString(c)
			if err != nil {
				return nil, err
			}
			out = append(out, tok)
			continue
		}

		// Numbers.
		if isDigit(c) {
			out = append(out, l.readNumber())
			continue
		}

		// Identifiers / keywords.
		if isIdentStart(c) {
			out = append(out, l.readIdent())
			continue
		}

		// Single-character punctuation.
		out = append(out, token{typ: string(c), pos: l.pos})
		l.pos++
	}
	out = append(out, token{typ: "EOF", pos: l.pos})
	return out, nil
}

func (l *lexer) readString(quote byte) (token, error) {
	start := l.pos
	l.pos++
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == quote {
			l.pos++
			return token{typ: "str", sval: b.String(), pos: start}, nil
		}
		if c == '\\' && l.pos+1 < len(l.src) {
			l.pos++
			e := l.src[l.pos]
			switch e {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '\\':
				b.WriteByte('\\')
			case '"':
				b.WriteByte('"')
			case '\'':
				b.WriteByte('\'')
			default:
				b.WriteByte(e)
			}
			l.pos++
			continue
		}
		b.WriteByte(c)
		l.pos++
	}
	return token{}, fmt.Errorf("unterminated string literal at offset %d", start)
}

func (l *lexer) readNumber() token {
	start := l.pos
	for l.pos < len(l.src) && (isDigit(l.src[l.pos]) || l.src[l.pos] == '.') {
		l.pos++
	}
	text := l.src[start:l.pos]
	n, err := strconv.ParseFloat(text, 64)
	if err != nil {
		n = 0
	}
	return token{typ: "num", text: text, nval: n, pos: start}
}

func (l *lexer) readIdent() token {
	start := l.pos
	for l.pos < len(l.src) && isIdentPart(l.src[l.pos]) {
		l.pos++
	}
	return token{typ: "ident", text: l.src[start:l.pos], pos: start}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$'
}

func isIdentPart(c byte) bool { return isIdentStart(c) || isDigit(c) }

// ---------------------------------------------------------------------------
// Path helpers (nested map/slice access)
// ---------------------------------------------------------------------------

type lvalueStep struct {
	key     string
	idx     int
	isIndex bool
}

func getStep(v any, st lvalueStep) (any, error) {
	if st.isIndex {
		arr, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("cannot index %T with a number", v)
		}
		i := st.idx - arrayBase
		if i < 0 || i >= len(arr) {
			return nil, fmt.Errorf("array index %d out of range", st.idx)
		}
		return arr[i], nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("cannot index %T with key %q", v, st.key)
	}
	child, ok := m[st.key]
	if !ok {
		return nil, fmt.Errorf("missing key %q", st.key)
	}
	return child, nil
}

func newContainer(next lvalueStep) any {
	if next.isIndex {
		return []any{}
	}
	return map[string]any{}
}

// setAt assigns val into container following steps. Root containers are maps
// (the config), so mutations are visible to the caller of Run via `work`.
func setAt(container any, steps []lvalueStep, val any) error {
	if len(steps) == 0 {
		return fmt.Errorf("empty assignment path")
	}
	st := steps[0]
	last := len(steps) == 1

	switch c := container.(type) {
	case map[string]any:
		key := st.key
		if st.isIndex {
			key = strconv.Itoa(st.idx)
		}
		if last {
			c[key] = val
			return nil
		}
		child := c[key]
		if child == nil {
			child = newContainer(steps[1])
			c[key] = child
		}
		return setAt(child, steps[1:], val)

	case []any:
		if !st.isIndex {
			return fmt.Errorf("array index must be a number")
		}
		i := st.idx - arrayBase
		if i < 0 || i >= len(c) {
			return fmt.Errorf("array index %d out of range", st.idx)
		}
		if last {
			c[i] = val
			return nil
		}
		if c[i] == nil {
			c[i] = newContainer(steps[1])
		}
		return setAt(c[i], steps[1:], val)

	default:
		return fmt.Errorf("cannot assign into %T", container)
	}
}

// ---------------------------------------------------------------------------
// Parser / evaluator
// ---------------------------------------------------------------------------

type parser struct {
	toks []token
	pos  int
	env  map[string]any
	logs *[]string
}

func (p *parser) peek() token {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return token{typ: "EOF"}
}

func (p *parser) skipSemi() {
	for p.pos < len(p.toks) && p.toks[p.pos].typ == ";" {
		p.pos++
	}
}

// execute locates main(...), binds its parameters and runs its body.
func (p *parser) execute(config Config, profileName string) (any, error) {
	i := 0
	for i+1 < len(p.toks) {
		if p.toks[i].typ == "ident" && p.toks[i].text == "function" &&
			p.toks[i+1].typ == "ident" && p.toks[i+1].text == "main" {
			break
		}
		i++
	}
	if i+1 >= len(p.toks) {
		return nil, fmt.Errorf("script must define main(config, profileName)")
	}

	j := i + 2
	if j >= len(p.toks) || p.toks[j].typ != "(" {
		return nil, fmt.Errorf("malformed main function signature")
	}
	j++
	var params []string
	for j < len(p.toks) && p.toks[j].typ != ")" {
		if p.toks[j].typ == "ident" {
			params = append(params, p.toks[j].text)
		}
		j++
	}
	if j >= len(p.toks) {
		return nil, fmt.Errorf("malformed main function signature")
	}
	j++ // skip ')'

	// Bind both positional parameters and the conventional names so scripts
	// that omit or rename them still work.
	p.env["config"] = config
	p.env["profileName"] = profileName
	if len(params) > 0 {
		p.env[params[0]] = config
	}
	if len(params) > 1 {
		p.env[params[1]] = profileName
	}

	body, err := p.extractBody(j)
	if err != nil {
		return nil, err
	}
	p.toks = body
	p.pos = 0
	return p.runStatements()
}

// extractBody returns the tokens of the main body. JS bodies are delimited by
// { ... }, Lua bodies run up to the matching `end` keyword.
func (p *parser) extractBody(start int) ([]token, error) {
	if start >= len(p.toks) {
		return nil, fmt.Errorf("missing main function body")
	}
	if p.toks[start].typ == "{" {
		depth := 0
		for k := start; k < len(p.toks); k++ {
			switch p.toks[k].typ {
			case "{":
				depth++
			case "}":
				depth--
				if depth == 0 {
					return p.bodySlice(start+1, k), nil
				}
			}
		}
		return nil, fmt.Errorf("unterminated main function body")
	}

	depth := 0
	for k := start; k < len(p.toks); k++ {
		t := p.toks[k]
		if t.typ != "ident" {
			continue
		}
		switch t.text {
		case "function", "if", "for", "while":
			depth++
		case "end":
			if depth == 0 {
				return p.bodySlice(start, k), nil
			}
			depth--
		}
	}
	return nil, fmt.Errorf("unterminated main function body (missing end)")
}

func (p *parser) bodySlice(from, to int) []token {
	body := make([]token, 0, to-from+1)
	body = append(body, p.toks[from:to]...)
	return append(body, token{typ: "EOF"})
}

func (p *parser) runStatements() (any, error) {
	var result any
	for p.pos < len(p.toks) && p.toks[p.pos].typ != "EOF" {
		p.skipSemi()
		if p.pos >= len(p.toks) || p.toks[p.pos].typ == "EOF" {
			break
		}
		t := p.peek()

		if t.typ == "ident" {
			switch t.text {
			case "return":
				p.pos++
				v, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				result = v
				p.skipSemi()
				continue
			case "throw":
				p.pos++
				return nil, fmt.Errorf("throw: %s", p.collectThrowMessage())
			case "var", "let", "const", "local":
				p.pos++
				if err := p.parseDeclaration(); err != nil {
					return nil, err
				}
				p.skipSemi()
				continue
			case "console":
				if err := p.parseConsole(); err != nil {
					return nil, err
				}
				p.skipSemi()
				continue
			}
		}

		if err := p.parseAssignment(); err != nil {
			return nil, err
		}
		p.skipSemi()
	}
	return result, nil
}

func (p *parser) parseDeclaration() error {
	if p.pos >= len(p.toks) || p.toks[p.pos].typ != "ident" {
		return nil
	}
	name := p.toks[p.pos].text
	p.pos++
	if p.pos < len(p.toks) && p.toks[p.pos].typ == "=" {
		p.pos++
		v, err := p.parseExpr()
		if err != nil {
			return err
		}
		p.env[name] = v
	}
	return nil
}

func (p *parser) parseConsole() error {
	// console . method ( args )
	if p.pos+2 >= len(p.toks) || p.toks[p.pos+1].typ != "." {
		return fmt.Errorf("malformed console call")
	}
	method := p.toks[p.pos+2].text
	p.pos += 3
	if p.pos >= len(p.toks) || p.toks[p.pos].typ != "(" {
		return fmt.Errorf("malformed console call")
	}
	p.pos++
	var args []any
	for p.pos < len(p.toks) && p.toks[p.pos].typ != ")" && p.toks[p.pos].typ != "EOF" {
		v, err := p.parseExpr()
		if err != nil {
			return err
		}
		args = append(args, v)
		if p.pos < len(p.toks) && p.toks[p.pos].typ == "," {
			p.pos++
			continue
		}
		break
	}
	if p.pos < len(p.toks) && p.toks[p.pos].typ == ")" {
		p.pos++
	}
	if p.logs != nil && len(args) > 0 {
		b, _ := json.MarshalIndent(args[0], "", "  ")
		*p.logs = append(*p.logs, fmt.Sprintf("[%s] %s", method, string(b)))
		if len(*p.logs) > 1000 {
			*p.logs = (*p.logs)[len(*p.logs)-1000:]
		}
	}
	return nil
}

func (p *parser) collectThrowMessage() string {
	var parts []string
	for p.pos < len(p.toks) {
		t := p.toks[p.pos]
		if t.typ == ";" || t.typ == "EOF" || t.typ == "}" {
			break
		}
		switch t.typ {
		case "str":
			parts = append(parts, t.sval)
		case "ident", "num":
			parts = append(parts, t.text)
		}
		p.pos++
	}
	if len(parts) == 0 {
		return "error"
	}
	return strings.Join(parts, " ")
}

// parsePath reads an identifier followed by zero or more `.name` / `[index]`
// selectors and returns the root variable plus the resulting steps.
func (p *parser) parsePath() (string, []lvalueStep, error) {
	t := p.peek()
	if t.typ != "ident" {
		return "", nil, fmt.Errorf("expected identifier, got %q", t.typ)
	}
	root := t.text
	p.pos++

	var steps []lvalueStep
	for p.pos < len(p.toks) {
		t := p.toks[p.pos]
		switch t.typ {
		case ".":
			p.pos++
			if p.pos >= len(p.toks) || p.toks[p.pos].typ != "ident" {
				return "", nil, fmt.Errorf("expected property name after '.'")
			}
			steps = append(steps, lvalueStep{key: p.toks[p.pos].text})
			p.pos++
		case "[":
			p.pos++
			st, err := p.parseIndex()
			if err != nil {
				return "", nil, err
			}
			if p.pos >= len(p.toks) || p.toks[p.pos].typ != "]" {
				return "", nil, fmt.Errorf("expected ']'")
			}
			p.pos++
			steps = append(steps, st)
		default:
			return root, steps, nil
		}
	}
	return root, steps, nil
}

func (p *parser) parseIndex() (lvalueStep, error) {
	t := p.peek()
	switch t.typ {
	case "num":
		p.pos++
		return lvalueStep{isIndex: true, idx: int(t.nval)}, nil
	case "str":
		p.pos++
		return lvalueStep{key: t.sval}, nil
	default:
		v, err := p.parseExpr()
		if err != nil {
			return lvalueStep{}, err
		}
		switch x := v.(type) {
		case float64:
			return lvalueStep{isIndex: true, idx: int(x)}, nil
		case string:
			return lvalueStep{key: x}, nil
		default:
			return lvalueStep{}, fmt.Errorf("unsupported index type %T", v)
		}
	}
}

func (p *parser) parseAssignment() error {
	root, steps, err := p.parsePath()
	if err != nil {
		return err
	}
	if p.pos >= len(p.toks) || p.toks[p.pos].typ != "=" {
		return fmt.Errorf("expected '=' near %q", p.peek().typ)
	}
	p.pos++
	v, err := p.parseExpr()
	if err != nil {
		return err
	}
	container, ok := p.env[root]
	if !ok {
		return fmt.Errorf("undefined variable %q", root)
	}
	return setAt(container, steps, v)
}

func (p *parser) parseExpr() (any, error) {
	v, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	v, err = p.parseValuePostfix(v)
	if err != nil {
		return nil, err
	}
	for p.pos < len(p.toks) && p.toks[p.pos].typ == "+" {
		p.pos++
		r, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		r, err = p.parseValuePostfix(r)
		if err != nil {
			return nil, err
		}
		v = addValues(v, r)
	}
	return v, nil
}

func (p *parser) parseValuePostfix(v any) (any, error) {
	for p.pos < len(p.toks) {
		t := p.toks[p.pos]
		switch t.typ {
		case ".":
			p.pos++
			if p.pos >= len(p.toks) || p.toks[p.pos].typ != "ident" {
				return nil, fmt.Errorf("expected property name after '.'")
			}
			key := p.toks[p.pos].text
			p.pos++
			child, err := getStep(v, lvalueStep{key: key})
			if err != nil {
				return nil, err
			}
			v = child
		case "[":
			p.pos++
			st, err := p.parseIndex()
			if err != nil {
				return nil, err
			}
			if p.pos >= len(p.toks) || p.toks[p.pos].typ != "]" {
				return nil, fmt.Errorf("expected ']'")
			}
			p.pos++
			child, err := getStep(v, st)
			if err != nil {
				return nil, err
			}
			v = child
		default:
			return v, nil
		}
	}
	return v, nil
}

func (p *parser) parsePrimary() (any, error) {
	t := p.peek()
	switch t.typ {
	case "str":
		p.pos++
		return t.sval, nil
	case "num":
		p.pos++
		return t.nval, nil
	case "ident":
		switch t.text {
		case "true", "True":
			p.pos++
			return true, nil
		case "false", "False":
			p.pos++
			return false, nil
		case "null", "nil", "None":
			p.pos++
			return nil, nil
		case "new":
			p.pos++
			if p.pos < len(p.toks) && p.toks[p.pos].typ == "ident" {
				p.pos++
			}
			if p.pos < len(p.toks) && p.toks[p.pos].typ == "(" {
				p.pos++
				var v any = ""
				if p.pos < len(p.toks) && p.toks[p.pos].typ != ")" {
					v, _ = p.parseExpr()
				}
				if p.pos < len(p.toks) && p.toks[p.pos].typ == ")" {
					p.pos++
				}
				return v, nil
			}
			return nil, nil
		}
		p.pos++
		if v, ok := p.env[t.text]; ok {
			return v, nil
		}
		return nil, nil
	case "(":
		p.pos++
		v, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if p.pos < len(p.toks) && p.toks[p.pos].typ == ")" {
			p.pos++
		}
		return v, nil
	case "[":
		return p.parseArray()
	case "{":
		return p.parseObjectOrArray()
	default:
		return nil, fmt.Errorf("unexpected token %q", t.typ)
	}
}

func (p *parser) parseArray() (any, error) {
	p.pos++ // '['
	arr := []any{}
	for p.pos < len(p.toks) && p.toks[p.pos].typ != "]" && p.toks[p.pos].typ != "EOF" {
		v, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		if p.pos < len(p.toks) && p.toks[p.pos].typ == "," {
			p.pos++
			continue
		}
		break
	}
	if p.pos < len(p.toks) && p.toks[p.pos].typ == "]" {
		p.pos++
	}
	return arr, nil
}

func (p *parser) parseObjectOrArray() (any, error) {
	p.pos++ // '{'
	arr := []any{}
	obj := map[string]any{}
	isObj := false
	for p.pos < len(p.toks) && p.toks[p.pos].typ != "}" && p.toks[p.pos].typ != "EOF" {
		first, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if p.pos < len(p.toks) && p.toks[p.pos].typ == ":" {
			isObj = true
			p.pos++
			v, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			obj[fmt.Sprint(first)] = v
		} else {
			if isObj {
				return nil, fmt.Errorf("mixed object and array literal")
			}
			arr = append(arr, first)
		}
		if p.pos < len(p.toks) && p.toks[p.pos].typ == "," {
			p.pos++
			continue
		}
		break
	}
	if p.pos < len(p.toks) && p.toks[p.pos].typ == "}" {
		p.pos++
	}
	if isObj {
		return obj, nil
	}
	return arr, nil
}

func addValues(a, b any) any {
	switch x := a.(type) {
	case string:
		return x + fmt.Sprint(b)
	case float64:
		if y, ok := b.(float64); ok {
			return x + y
		}
	}
	return fmt.Sprint(a) + fmt.Sprint(b)
}
