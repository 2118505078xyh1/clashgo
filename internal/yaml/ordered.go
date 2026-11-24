package yaml

// OrderedMap 保留插入顺序的映射，用于需要确定性键序（优先级键在前）的场景。
type OrderedMap struct {
	Keys   []string
	Values []any
}

func NewOrderedMap() *OrderedMap { return &OrderedMap{} }

func (o *OrderedMap) Set(k string, v any) {
	for i, key := range o.Keys {
		if key == k {
			o.Values[i] = v
			return
		}
	}
	o.Keys = append(o.Keys, k)
	o.Values = append(o.Values, v)
}

func (o OrderedMap) orderedEntries() []entry {
	out := make([]entry, 0, len(o.Keys))
	for i, k := range o.Keys {
		out = append(out, entry{key: k, value: reflectValueOf(o.Values[i])})
	}
	return out
}
