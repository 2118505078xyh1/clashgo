package safemode

import (
	"reflect"
	"testing"
)

func TestApplySafeNoOpWhenDisabled(t *testing.T) {
	cfg := map[string]any{
		"listeners":           []any{map[string]any{"name": "in"}},
		"external-controller": "127.0.0.1:9097",
		"allow-lan":           true,
	}
	want := map[string]any{
		"listeners":           []any{map[string]any{"name": "in"}},
		"external-controller": "127.0.0.1:9097",
		"allow-lan":           true,
	}
	if changed := ApplySafe(cfg, SafeSettings{SafeMode: false}); len(changed) != 0 {
		t.Fatalf("disabled safe mode should not change anything, got %v", changed)
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("config was modified with safe mode off: %#v", cfg)
	}
	if changed := ApplySafe(nil, SafeSettings{SafeMode: true}); len(changed) != 0 {
		t.Fatalf("nil config should be a no-op, got %v", changed)
	}
}

func TestApplySafeHardensConfig(t *testing.T) {
	cfg := map[string]any{
		"port":                7897,
		"listeners":           []any{map[string]any{"name": "in"}},
		"tunnels":             []any{map[string]any{"name": "tun"}},
		"external-controller": "0.0.0.0:9090",
		"allow-lan":           true,
	}
	changed := ApplySafe(cfg, SafeSettings{SafeMode: true})
	wantChanged := []string{"listeners", "tunnels", "external-controller", "allow-lan"}
	if !reflect.DeepEqual(changed, wantChanged) {
		t.Fatalf("changed keys = %v, want %v", changed, wantChanged)
	}
	if _, ok := cfg["listeners"]; ok {
		t.Fatal("listeners must be removed")
	}
	if _, ok := cfg["tunnels"]; ok {
		t.Fatal("tunnels must be removed")
	}
	if v := cfg["external-controller"]; v != "" {
		t.Fatalf("external-controller = %v, want empty string", v)
	}
	if v := cfg["allow-lan"]; v != false {
		t.Fatalf("allow-lan = %v, want false", v)
	}
	if cfg["port"] != 7897 {
		t.Fatal("unrelated keys must be preserved")
	}
}

func TestApplySafeAddsMissingKeysAndIsIdempotent(t *testing.T) {
	cfg := map[string]any{"port": 7897}
	changed := ApplySafe(cfg, SafeSettings{SafeMode: true})
	want := []string{"external-controller", "allow-lan"}
	if !reflect.DeepEqual(changed, want) {
		t.Fatalf("changed keys = %v, want %v", changed, want)
	}
	if cfg["external-controller"] != "" || cfg["allow-lan"] != false {
		t.Fatalf("missing keys should be added with hardened values: %#v", cfg)
	}
	if again := ApplySafe(cfg, SafeSettings{SafeMode: true}); len(again) != 0 {
		t.Fatalf("second application should be a no-op, got %v", again)
	}
}
