package yaml

import (
	"fmt"
	"strings"
)

// srcLine is one physical line of the input. text starts after the leading
// indentation; raw is the untouched line (needed for block scalars).
type srcLine struct {
	indent int
	text   string
	raw    string
	num    int
}

type parser struct {
	lines   []srcLine
	pos     int
	anchors map[string]any
}

func parseDocument(data []byte) (any, error) {
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	parts := strings.Split(s, "\n")
	lines := make([]srcLine, 0, len(parts))
	for i, raw := range parts {
		ind := leadingSpace(raw)
		lines = append(lines, srcLine{
			indent: ind,
			text:   raw[ind:],
			raw:    raw,
			num:    i + 1,
		})
	}
	p := &parser{lines: lines, anchors: make(map[string]any)}
	l := p.peekSignificant()
	if l == nil {
		return nil, nil
	}
	return p.parseBlock(l.indent), nil
}

// ignorable lines are blank, comment-only, or YAML document markers.
func ignorable(l *srcLine) bool {
	t := strings.TrimSpace(stripComment(l.text))
	return t == "" || strings.HasPrefix(t, "#") || t == "---" || t == "..."
}

// peekSignificant returns the next structural line without consuming it.
func (p *parser) peekSignificant() *srcLine {
	for i := p.pos; i < len(p.lines); i++ {
		l := &p.lines[i]
		if ignorable(l) {
			continue
		}
		return l
	}
	return nil
}

// consumeSignificant consumes and returns the next structural line.
func (p *parser) consumeSignificant() *srcLine {
	for p.pos < len(p.lines) {
		l := &p.lines[p.pos]
		p.pos++
		if ignorable(l) {
			continue
		}
		return l
	}
	return nil
}

// parseBlock parses a mapping, sequence or scalar starting at minIndent.
func (p *parser) parseBlock(minIndent int) any {
	l := p.peekSignificant()
	if l == nil || l.indent < minIndent {
		return nil
	}
	base := l.indent
	text := strings.TrimSpace(stripComment(l.text))
	if isSeqMarker(text) {
		return p.parseSequence(base)
	}
	if findMapColon(text) >= 0 {
		return p.parseMapping(base, nil)
	}
	p.consumeSignificant()
	return p.parseValue(text, base)
}

// parseMapping parses a block mapping. first, when non-nil, is an already
// consumed entry (used for "- key: value" sequence items); it is processed as
// the first key/value pair at indentation base.
func (p *parser) parseMapping(base int, first *srcLine) any {
	m := make(map[string]any)
	var merges []any

	for {
		var l *srcLine
		if first != nil {
			l = first
			first = nil
		} else {
			nl := p.peekSignificant()
			if nl == nil || nl.indent != base {
				break
			}
			if isSeqMarker(strings.TrimSpace(stripComment(nl.text))) {
				break
			}
			l = p.consumeSignificant()
		}

		text := strings.TrimSpace(stripComment(l.text))
		ci := findMapColon(text)
		if ci < 0 {
			// Malformed entry: skip it rather than failing the whole document.
			continue
		}
		keyText := strings.TrimSpace(text[:ci])
		if key, ok := unquoteString(keyText); ok {
			keyText = key
		}
		rest := strings.TrimSpace(text[ci+1:])
		value := p.parseValue(rest, base)

		if keyText == "<<" {
			merges = append(merges, value)
			continue
		}
		m[keyText] = value
	}

	// Apply anchor merge keys ("<<"). Explicit keys always win.
	for _, src := range merges {
		switch s := src.(type) {
		case map[string]any:
			for k, v := range s {
				if _, exists := m[k]; !exists {
					m[k] = v
				}
			}
		case []any:
			for _, item := range s {
				if sm, ok := item.(map[string]any); ok {
					for k, v := range sm {
						if _, exists := m[k]; !exists {
							m[k] = v
						}
					}
				}
			}
		}
	}
	return m
}

// parseSequence parses a block sequence ("- item") at indentation base.
func (p *parser) parseSequence(base int) any {
	seq := make([]any, 0)
	for {
		l := p.peekSignificant()
		if l == nil || l.indent != base ||
			!isSeqMarker(strings.TrimSpace(stripComment(l.text))) {
			break
		}
		l = p.consumeSignificant()

		// Content after the dash, and the column where the item starts.
		dash := l.text[leadingSpace(l.text)]
		_ = dash // the marker was verified above
		after := l.text[leadingSpace(l.text)+1:]
		spaces := leadingSpace(after)
		itemCol := base + 1 + spaces
		itemText := strings.TrimSpace(stripComment(after))

		var item any
		switch {
		case itemText == "":
			nl := p.peekSignificant()
			if nl != nil && nl.indent > base {
				item = p.parseBlock(nl.indent)
			} else {
				item = nil
			}
		case findMapColon(itemText) >= 0:
			first := &srcLine{indent: itemCol, text: itemText, raw: itemText, num: l.num}
			item = p.parseMapping(itemCol, first)
		default:
			item = p.parseValue(itemText, base)
		}
		seq = append(seq, item)
	}
	return seq
}

// parseValue parses the value part of a mapping entry or sequence item. base
// is the indentation of the owning key/dash, used to find nested blocks.
func (p *parser) parseValue(text string, base int) any {
	text = strings.TrimSpace(stripComment(text))

	// Skip tags and record anchors; both may appear before the real value.
	var anchor string
	for {
		if strings.HasPrefix(text, "&") {
			tok, rest := splitFirstToken(text)
			anchor = tok[1:]
			text = strings.TrimSpace(rest)
			continue
		}
		if strings.HasPrefix(text, "!!") || strings.HasPrefix(text, "!<") {
			_, rest := splitFirstToken(text)
			text = strings.TrimSpace(rest)
			continue
		}
		break
	}

	var v any
	switch {
	case text == "":
		nl := p.peekSignificant()
		if nl != nil && nl.indent > base {
			v = p.parseBlock(nl.indent)
		} else if nl != nil && nl.indent == base &&
			isSeqMarker(strings.TrimSpace(stripComment(nl.text))) {
			// Indentless sequence under a mapping key (common in Clash configs).
			v = p.parseSequence(base)
		}
	case isBlockScalarHeader(text):
		v = p.parseBlockScalar(text, base)
	case strings.HasPrefix(text, "*"):
		v = p.anchors[strings.TrimSpace(text[1:])]
	case strings.HasPrefix(text, "["):
		v = (&flowParser{s: text}).parse()
	case strings.HasPrefix(text, "{"):
		v = (&flowParser{s: text}).parse()
	default:
		v = scalarText(text)
	}
	if anchor != "" {
		p.anchors[anchor] = v
	}
	return v
}

// splitFirstToken splits "tok rest" at the first whitespace.
func splitFirstToken(s string) (string, string) {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			return s[:i], s[i:]
		}
	}
	return s, ""
}

// ---------------------------------------------------------------------------
// Block scalars (| and >, with optional chomping / indentation indicators)
// ---------------------------------------------------------------------------

func isBlockScalarHeader(s string) bool {
	return s != "" && (s[0] == '|' || s[0] == '>')
}

func (p *parser) parseBlockScalar(header string, base int) string {
	folded := header[0] == '>'
	chomp := byte(0) // 0 = clip, '-' = strip, '+' = keep
	explicit := 0
	for i := 1; i < len(header); i++ {
		switch {
		case header[i] == '-' || header[i] == '+':
			chomp = header[i]
		case header[i] >= '1' && header[i] <= '9':
			explicit = int(header[i] - '0')
		}
	}

	// Collect the physical lines belonging to the scalar.
	var raw []srcLine
	for p.pos < len(p.lines) {
		l := p.lines[p.pos]
		if isBlank(l.text) {
			raw = append(raw, l)
			p.pos++
			continue
		}
		if l.indent <= base {
			break
		}
		raw = append(raw, l)
		p.pos++
	}

	contentIndent := base + 1
	if explicit > 0 {
		contentIndent = base + explicit
	} else {
		minIndent := -1
		for _, l := range raw {
			if !isBlank(l.text) && (minIndent < 0 || l.indent < minIndent) {
				minIndent = l.indent
			}
		}
		if minIndent >= 0 {
			contentIndent = minIndent
		}
	}

	lines := make([]string, 0, len(raw))
	for _, l := range raw {
		if isBlank(l.text) {
			lines = append(lines, "")
			continue
		}
		n := contentIndent
		if n > len(l.raw) {
			n = len(l.raw)
		}
		lines = append(lines, l.raw[n:])
	}

	var s string
	if folded {
		s = foldLines(lines)
	} else {
		s = strings.Join(lines, "\n")
	}

	switch chomp {
	case '-':
		s = strings.TrimRight(s, "\n")
	case '+':
		// Keep all trailing line breaks produced by the join above.
	default:
		s = strings.TrimRight(s, "\n")
		if s != "" {
			s += "\n"
		}
	}
	return s
}

func foldLines(lines []string) string {
	var b strings.Builder
	for i, ln := range lines {
		if i == 0 {
			b.WriteString(ln)
			continue
		}
		prev := lines[i-1]
		switch {
		case prev == "" && ln == "":
			b.WriteByte('\n')
		case ln == "":
			b.WriteByte('\n')
		case prev == "":
			// The newline was emitted for the blank line already.
		case leadingSpace(ln) > leadingSpace(prev) || leadingSpace(ln) < leadingSpace(prev):
			b.WriteByte('\n')
			b.WriteString(ln)
			continue
		default:
			b.WriteByte(' ')
		}
		b.WriteString(ln)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Flow collections: [a, b] and {k: v}
// ---------------------------------------------------------------------------

type flowParser struct {
	s   string
	pos int
}

func (f *flowParser) parse() any {
	return f.node("]}")
}

func (f *flowParser) skipSpace() {
	for f.pos < len(f.s) && (f.s[f.pos] == ' ' || f.s[f.pos] == '\t' || f.s[f.pos] == '\n') {
		f.pos++
	}
}

// node parses one flow value, stopping at any of the characters in stops
// (with ':' only acting as a stop when followed by whitespace or a delimiter).
func (f *flowParser) node(stops string) any {
	f.skipSpace()
	if f.pos >= len(f.s) {
		return nil
	}
	switch c := f.s[f.pos]; {
	case c == '[':
		return f.sequence()
	case c == '{':
		return f.mapping()
	case c == '\'' || c == '"':
		return f.quoted()
	}
	start := f.pos
	for f.pos < len(f.s) {
		c := f.s[f.pos]
		if strings.IndexByte(stops, c) >= 0 {
			if c != ':' || f.colonIsSeparator() {
				break
			}
		}
		f.pos++
	}
	return scalarText(strings.TrimSpace(f.s[start:f.pos]))
}

func (f *flowParser) colonIsSeparator() bool {
	if f.pos+1 >= len(f.s) {
		return true
	}
	next := f.s[f.pos+1]
	return next == ' ' || next == '\t' || next == ',' || next == '}' || next == ']'
}

func (f *flowParser) quoted() any {
	q := f.s[f.pos]
	start := f.pos
	f.pos++
	for f.pos < len(f.s) {
		if f.s[f.pos] == '\\' && q == '"' {
			f.pos += 2
			continue
		}
		if f.s[f.pos] == q {
			if q == '\'' && f.pos+1 < len(f.s) && f.s[f.pos+1] == '\'' {
				f.pos += 2
				continue
			}
			f.pos++
			break
		}
		f.pos++
	}
	if v, ok := unquoteString(f.s[start:f.pos]); ok {
		return v
	}
	return f.s[start:f.pos]
}

func (f *flowParser) sequence() []any {
	f.pos++ // '['
	out := make([]any, 0)
	for {
		f.skipSpace()
		if f.pos >= len(f.s) || f.s[f.pos] == ']' {
			if f.pos < len(f.s) {
				f.pos++
			}
			break
		}
		out = append(out, f.node("],"))
		f.skipSpace()
		if f.pos < len(f.s) && f.s[f.pos] == ',' {
			f.pos++
		}
	}
	return out
}

func (f *flowParser) mapping() map[string]any {
	f.pos++ // '{'
	out := make(map[string]any)
	for {
		f.skipSpace()
		if f.pos >= len(f.s) || f.s[f.pos] == '}' {
			if f.pos < len(f.s) {
				f.pos++
			}
			break
		}
		key := fmt.Sprint(f.node(":,}"))
		f.skipSpace()
		if f.pos < len(f.s) && f.s[f.pos] == ':' {
			f.pos++
		}
		out[key] = f.node(",}")
		f.skipSpace()
		if f.pos < len(f.s) && f.s[f.pos] == ',' {
			f.pos++
		}
	}
	return out
}
