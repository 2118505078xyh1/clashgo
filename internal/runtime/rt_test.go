package runtime

import (
	"os"
	"testing"

	"clashgo/internal/config"
	"clashgo/internal/yaml"
)

func TestGen(t *testing.T) {
	b, err := os.ReadFile("D:/clashgo/data/profiles/imported.yaml")
	if err != nil {
		t.Skip(err)
	}
	s := config.DefaultSettings()
	data, err := Generate(b, s, nil, nil, "D:/tmp/rt2.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	r, _ := m["rules"].([]any)
	t.Logf("生成 %d 字节, rules %d 条", len(data), len(r))
}
