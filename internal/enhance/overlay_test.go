package enhance

import "testing"

func TestOverlayDirectives(t *testing.T) {
	config := Mapping{
		"proxy-groups": []any{
			Mapping{"name": "SELECT", "type": "select", "proxies": []any{"A", "DIRECT"}},
		},
		"rules": []any{"MATCH,DIRECT", "DOMAIN,example.com,DIRECT"},
		"dns":   Mapping{"fake-ip-range": "198.18.0.1/16", "enable": true},
	}
	merge := Mapping{
		"prepend__proxy-groups.0.proxies": []any{"NEW1", "NEW2"},
		"append__rules":                   []any{"DOMAIN,test.com,DIRECT"},
		"override__dns.fake-ip-range":     "10.0.0.1/16",
		"remove__dns.enable":              nil,
	}
	out := UseMerge(Mapping{}, merge)
	_ = out
	out = UseMerge(config, merge)

	groups := out["proxy-groups"].([]any)
	proxies := groups[0].(Mapping)["proxies"].([]any)
	if len(proxies) != 4 || proxies[0] != "NEW1" || proxies[1] != "NEW2" {
		t.Errorf("prepend to dotted path: %v", proxies)
	}

	rules := out["rules"].([]any)
	if rules[len(rules)-1] != "DOMAIN,test.com,DIRECT" {
		t.Errorf("append to rules: %v", rules)
	}

	dns := out["dns"].(Mapping)
	if dns["fake-ip-range"] != "10.0.0.1/16" {
		t.Errorf("override dotted path: %v", dns)
	}
	if _, ok := dns["enable"]; ok {
		t.Error("remove directive did not delete dns.enable")
	}
}

func TestOverlayDoesNotCreateMissingPath(t *testing.T) {
	config := Mapping{"a": Mapping{"b": 1}}
	out := UseMerge(config, Mapping{"override__x.y.z": 123})
	if _, ok := out["x"]; ok {
		t.Error("override should not create missing path")
	}
}
