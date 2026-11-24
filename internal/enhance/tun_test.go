package enhance

import (
	"testing"

	"clashgo/internal/config"
)

func TestTUNFakeIPBaseline(t *testing.T) {
	freshProfileDir(t)
	// A profile with DNS disabled — TUN must force DNS on with fake-ip.
	profile := []byte("port: 7890\nmode: rule\ndns:\n  enable: false\n")
	s := config.DefaultSettings()
	s.EnableTUN = true
	item := &config.PrfItem{Name: "x"}
	res, err := Execute(profile, item, nil, s)
	if err != nil {
		t.Fatal(err)
	}
	dns, ok := res.Config["dns"].(Mapping)
	if !ok {
		t.Fatal("dns missing")
	}
	if dns["enable"] != true {
		t.Error("TUN must force dns.enable=true")
	}
	if dns["enhanced-mode"] != "fake-ip" {
		t.Errorf("enhanced-mode: %v", dns["enhanced-mode"])
	}
	if dns["fake-ip-range"] == nil {
		t.Error("fake-ip-range missing")
	}
	if dns["fake-ip-range6"] == nil {
		t.Error("fake-ip-range6 missing for IPv6 support")
	}
	tun := res.Config["tun"].(Mapping)
	if tun["enable"] != true {
		t.Error("tun.enable not set")
	}
	if tun["dns-hijack"] == nil {
		t.Error("dns-hijack missing")
	}
	excluded := toStringSlice(tun["route-exclude-address"])
	if len(excluded) < 6 {
		t.Errorf("private routes not excluded: %v", excluded)
	}
}

func TestTUNDegradationConfig(t *testing.T) {
	freshProfileDir(t)
	profile := []byte("port: 7890\nmode: rule\n")
	s := config.DefaultSettings()
	s.EnableTUN = false
	item := &config.PrfItem{Name: "x"}
	res, err := Execute(profile, item, nil, s)
	if err != nil {
		t.Fatal(err)
	}
	tun := res.Config["tun"].(Mapping)
	if tun["enable"] != false {
		t.Error("tun should be disabled")
	}
	if tun["mtu"] == nil {
		t.Error("tun mtu default missing")
	}
}
