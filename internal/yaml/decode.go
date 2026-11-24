package yaml

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// decodeValue converts a parsed YAML value into out using reflection.
func decodeValue(node any, out reflect.Value) error {
	if !out.CanSet() {
		return nil
	}

	// Interfaces accept the generic tree as-is.
	if out.Kind() == reflect.Interface {
		if node == nil {
			out.Set(reflect.Zero(out.Type()))
			return nil
		}
		rv := reflect.ValueOf(node)
		if rv.Type().AssignableTo(out.Type()) {
			out.Set(rv)
		} else if rv.Type().ConvertibleTo(out.Type()) {
			out.Set(rv.Convert(out.Type()))
		}
		return nil
	}

	// Pointers: allocate as needed, then decode into the element.
	if out.Kind() == reflect.Pointer {
		if node == nil {
			out.Set(reflect.Zero(out.Type()))
			return nil
		}
		if out.IsNil() {
			out.Set(reflect.New(out.Type().Elem()))
		}
		return decodeValue(node, out.Elem())
	}

	if node == nil {
		out.Set(reflect.Zero(out.Type()))
		return nil
	}

	switch out.Kind() {
	case reflect.Struct:
		return decodeStruct(node, out)
	case reflect.Map:
		return decodeMap(node, out)
	case reflect.Slice, reflect.Array:
		return decodeSlice(node, out)
	default:
		decodeScalar(node, out)
		return nil
	}
}

// ---------------------------------------------------------------------------
// Structs, maps and slices
// ---------------------------------------------------------------------------

type fieldInfo struct {
	index     []int
	name      string
	omitEmpty bool
}

func parseYamlTag(tag string) (string, bool) {
	parts := strings.Split(tag, ",")
	name := parts[0]
	omit := false
	for _, opt := range parts[1:] {
		if opt == "omitempty" {
			omit = true
		}
	}
	return name, omit
}

// structFields returns the set of settable fields of t. Anonymous structs are
// flattened so embedded configurations can be decoded transparently.
func structFields(t reflect.Type) []fieldInfo {
	var out []fieldInfo
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		embeddedType := f.Type
		if embeddedType.Kind() == reflect.Pointer {
			embeddedType = embeddedType.Elem()
		}
		// Anonymous struct types may themselves be unexported; their exported
		// subfields are still promoted and settable.
		if f.PkgPath != "" && (!f.Anonymous || embeddedType.Kind() != reflect.Struct) {
			continue
		}
		tag, hasTag := f.Tag.Lookup("yaml")
		name, omit := parseYamlTag(tag)
		if hasTag && name == "-" {
			continue
		}
		if f.Anonymous && (!hasTag || name == "") && embeddedType.Kind() == reflect.Struct {
			for _, sub := range structFields(embeddedType) {
				idx := make([]int, 0, len(sub.index)+1)
				idx = append(idx, i)
				idx = append(idx, sub.index...)
				sub.index = idx
				out = append(out, sub)
			}
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		out = append(out, fieldInfo{index: []int{i}, name: name, omitEmpty: omit})
	}
	return out
}

// fieldByIndexAlloc walks an index path, allocating embedded pointers.
func fieldByIndexAlloc(v reflect.Value, index []int) reflect.Value {
	for _, i := range index {
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				v.Set(reflect.New(v.Type().Elem()))
			}
			v = v.Elem()
		}
		v = v.Field(i)
	}
	return v
}

func decodeStruct(node any, out reflect.Value) error {
	m, ok := node.(map[string]any)
	if !ok {
		return nil // tolerate type mismatches
	}
	lookup := make(map[string]fieldInfo)
	for _, f := range structFields(out.Type()) {
		key := strings.ToLower(f.name)
		if _, exists := lookup[key]; !exists {
			lookup[key] = f
		}
	}
	for k, v := range m {
		fi, ok := lookup[strings.ToLower(k)]
		if !ok {
			continue
		}
		fv := fieldByIndexAlloc(out, fi.index)
		if err := decodeValue(v, fv); err != nil {
			return fmt.Errorf("field %q: %w", k, err)
		}
	}
	return nil
}

func decodeMap(node any, out reflect.Value) error {
	m, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	if out.IsNil() {
		out.Set(reflect.MakeMapWithSize(out.Type(), len(m)))
	}
	kt, et := out.Type().Key(), out.Type().Elem()
	for k, v := range m {
		kv := reflect.New(kt).Elem()
		if err := decodeValue(k, kv); err != nil {
			continue
		}
		ev := reflect.New(et).Elem()
		if err := decodeValue(v, ev); err != nil {
			continue
		}
		out.SetMapIndex(kv, ev)
	}
	return nil
}

func decodeSlice(node any, out reflect.Value) error {
	s, ok := node.([]any)
	if !ok {
		// Allow a plain string to fill a []byte.
		if str, ok := node.(string); ok && out.Type().Elem().Kind() == reflect.Uint8 {
			out.SetBytes([]byte(str))
		}
		return nil
	}
	if out.Kind() == reflect.Array {
		n := len(s)
		if n > out.Len() {
			n = out.Len()
		}
		for i := 0; i < n; i++ {
			_ = decodeValue(s[i], out.Index(i))
		}
		return nil
	}
	if out.IsNil() || out.Cap() < len(s) {
		out.Set(reflect.MakeSlice(out.Type(), len(s), len(s)))
	} else {
		out.SetLen(len(s))
	}
	for i, v := range s {
		if err := decodeValue(v, out.Index(i)); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Scalars with best-effort type conversion
// ---------------------------------------------------------------------------

func decodeScalar(node any, out reflect.Value) {
	switch out.Kind() {
	case reflect.String:
		out.SetString(asString(node))
	case reflect.Bool:
		out.SetBool(asBool(node))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if n, ok := asInt64(node); ok && !out.OverflowInt(n) {
			out.SetInt(n)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if n, ok := asUint64(node); ok && !out.OverflowUint(n) {
			out.SetUint(n)
		}
	case reflect.Float32, reflect.Float64:
		if f, ok := asFloat64(node); ok {
			if out.Kind() == reflect.Float32 && (f > 3.4e38 || f < -3.4e38) {
				return
			}
			out.SetFloat(f)
		}
	case reflect.Interface:
		rv := reflect.ValueOf(node)
		if rv.IsValid() && rv.Type().AssignableTo(out.Type()) {
			out.Set(rv)
		}
	}
}

func asString(node any) string {
	switch v := node.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	case bool:
		return strconv.FormatBool(v)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func asBool(node any) bool {
	switch v := node.(type) {
	case bool:
		return v
	case int:
		return v != 0
	case int64:
		return v != 0
	case uint64:
		return v != 0
	case float64:
		return v != 0
	case string:
		if b, ok := resolvePlain(strings.TrimSpace(v)).(bool); ok {
			return b
		}
		if n, err := strconv.ParseInt(v, 0, 64); err == nil {
			return n != 0
		}
	}
	return false
}

func asInt64(node any) (int64, bool) {
	switch v := node.(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case uint64:
		if v <= uint64(^uint64(0)>>1) {
			return int64(v), true
		}
	case float64:
		return int64(v), true
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	case string:
		if n, ok := resolvePlain(strings.TrimSpace(v)).(int); ok {
			return int64(n), true
		}
		if n, ok := resolvePlain(strings.TrimSpace(v)).(int64); ok {
			return n, true
		}
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return int64(f), true
		}
	}
	return 0, false
}

func asUint64(node any) (uint64, bool) {
	switch v := node.(type) {
	case uint64:
		return v, true
	case int:
		if v >= 0 {
			return uint64(v), true
		}
	case int64:
		if v >= 0 {
			return uint64(v), true
		}
	case float64:
		if v >= 0 {
			return uint64(v), true
		}
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	case string:
		s := strings.TrimSpace(v)
		if n, err := strconv.ParseUint(s, 0, 64); err == nil {
			return n, true
		}
		if n, ok := asInt64(v); ok && n >= 0 {
			return uint64(n), true
		}
	}
	return 0, false
}

func asFloat64(node any) (float64, bool) {
	switch v := node.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint64:
		return float64(v), true
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return f, true
		}
	}
	return 0, false
}
