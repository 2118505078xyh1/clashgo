package yaml

import (
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type encoder struct {
	buf    strings.Builder
	prefix string
	indent string
}

type entry struct {
	key   string
	value reflect.Value
}

func marshalValue(v any, prefix, indent string) ([]byte, error) {
	e := &encoder{prefix: prefix, indent: indent}
	if v == nil {
		e.write("null\n")
		return []byte(e.buf.String()), nil
	}
	e.emitNested(reflect.ValueOf(v), "")
	return []byte(e.buf.String()), nil
}

func (e *encoder) write(s string) {
	e.buf.WriteString(e.prefix)
	e.buf.WriteString(s)
}

// emitNested emits the children of a collection at the given indentation.
// orderedValue 是 OrderedMap 实现的接口，用于按插入顺序输出键。
type orderedValue interface{ orderedEntries() []entry }

// reflectValueOf 把 any 转成 reflect.Value（供 OrderedMap 使用）。
func reflectValueOf(v any) reflect.Value { return reflect.ValueOf(v) }

func (e *encoder) emitNested(v reflect.Value, indent string) {
	v = deref(v)
	if !v.IsValid() {
		e.write(indent + "null\n")
		return
	}
	// 优先识别有序映射（保持键的插入顺序）。
	if ov, ok := v.Interface().(orderedValue); ok {
		for _, en := range ov.orderedEntries() {
			e.emitEntry(indent, en.key, en.value)
		}
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		for _, en := range structEntries(v) {
			e.emitEntry(indent, en.key, en.value)
		}
	case reflect.Map:
		for _, en := range mapEntries(v) {
			e.emitEntry(indent, en.key, en.value)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			e.emitItem(indent, v.Index(i))
		}
	default:
		e.write(indent + e.scalar(v) + "\n")
	}
}

// emitEntry writes "indent key: value", or a block value on following lines.
func (e *encoder) emitEntry(indent, key string, v reflect.Value) {
	keyToken := key
	if needsQuotes(key) {
		keyToken = quoteScalar(key)
	}
	v = deref(v)
	if isInline(v) {
		e.write(indent + keyToken + ": " + e.scalar(v) + "\n")
		return
	}
	e.write(indent + keyToken + ":\n")
	e.emitNested(v, indent+e.indent)
}

// emitItem writes one sequence item, with "- " for the first part of maps.
func (e *encoder) emitItem(indent string, v reflect.Value) {
	v = deref(v)
	if isInline(v) {
		e.write(indent + "- " + e.scalar(v) + "\n")
		return
	}
	switch v.Kind() {
	case reflect.Struct, reflect.Map:
		entries := collectionEntries(v)
		if len(entries) == 0 {
			e.write(indent + "- {}\n")
			return
		}
		e.emitEntry(indent+"- ", entries[0].key, entries[0].value)
		for _, en := range entries[1:] {
			e.emitEntry(indent+"  ", en.key, en.value)
		}
	case reflect.Slice, reflect.Array:
		if v.Len() == 0 {
			e.write(indent + "- []\n")
			return
		}
		e.write(indent + "-\n")
		e.emitNested(v, indent+e.indent)
	default:
		e.write(indent + "- " + e.scalar(v) + "\n")
	}
}

func collectionEntries(v reflect.Value) []entry {
	if v.Kind() == reflect.Struct {
		return structEntries(v)
	}
	return mapEntries(v)
}

// isInline reports whether v can be written on a single line.
func isInline(v reflect.Value) bool {
	if !v.IsValid() {
		return true
	}
	switch v.Kind() {
	case reflect.Map, reflect.Slice, reflect.Array:
		return v.Len() == 0
	case reflect.Struct:
		return len(structEntries(v)) == 0
	default:
		return true
	}
}

func deref(v reflect.Value) reflect.Value {
	for v.IsValid() && (v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer) {
		if v.IsNil() {
			return reflect.Value{}
		}
		v = v.Elem()
	}
	return v
}

// scalar renders a scalar (or an empty collection) as a YAML token.
func (e *encoder) scalar(v reflect.Value) string {
	if !v.IsValid() {
		return "null"
	}
	switch v.Kind() {
	case reflect.String:
		s := v.String()
		if needsQuotes(s) {
			return quoteScalar(s)
		}
		return s
	case reflect.Bool:
		return strconv.FormatBool(v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(v.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		f := v.Float()
		switch {
		case math.IsNaN(f):
			return ".nan"
		case math.IsInf(f, 1):
			return ".inf"
		case math.IsInf(f, -1):
			return "-.inf"
		}
		return strconv.FormatFloat(f, 'g', -1, 64)
	case reflect.Map:
		return "{}"
	case reflect.Slice, reflect.Array:
		return "[]"
	default:
		s := fmt.Sprint(v.Interface())
		if needsQuotes(s) {
			return quoteScalar(s)
		}
		return s
	}
}

// structEntries returns the YAML key/value pairs of a struct, preserving
// declaration order and flattening anonymous embedded structs.
func structEntries(v reflect.Value) []entry {
	t := v.Type()
	var out []entry
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		et := f.Type
		isEmbeddedStruct := f.Anonymous && et.Kind() == reflect.Struct ||
			f.Anonymous && et.Kind() == reflect.Pointer && et.Elem().Kind() == reflect.Struct
		if f.PkgPath != "" && !isEmbeddedStruct {
			continue
		}
		tag, hasTag := f.Tag.Lookup("yaml")
		name, omit := parseYamlTag(tag)
		if hasTag && name == "-" {
			continue
		}
		fv := v.Field(i)
		if f.Anonymous && (!hasTag || name == "") {
			if et.Kind() == reflect.Pointer {
				if fv.IsNil() {
					continue
				}
				fv = fv.Elem()
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct {
				out = append(out, structEntries(fv)...)
				continue
			}
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		if omit && isEmptyValue(fv) {
			continue
		}
		out = append(out, entry{key: name, value: fv})
	}
	return out
}

// mapEntries returns sorted key/value pairs of a map for deterministic output.
func mapEntries(v reflect.Value) []entry {
	entries := make([]entry, 0, v.Len())
	iter := v.MapRange()
	for iter.Next() {
		key := asString(iter.Key().Interface())
		if iter.Key().Kind() == reflect.String {
			key = iter.Key().String()
		}
		entries = append(entries, entry{key: key, value: iter.Value()})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
	return entries
}

func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer, reflect.Map, reflect.Slice:
		return v.IsNil()
	case reflect.Array, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	}
	return false
}
