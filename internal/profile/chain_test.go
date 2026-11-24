package profile

import (
	"reflect"
	"testing"

	"clashgo/internal/config"
)

// TestBuildChain builds three profiles A -> B -> C and checks that the chain
// expands in the same order from every starting point.
func TestBuildChain(t *testing.T) {
	a := &config.PrfItem{UID: "A", Name: "A", Option: &config.PrfOption{NextProfile: "B"}}
	b := &config.PrfItem{UID: "B", Name: "B", Option: &config.PrfOption{PrevProfile: "A", NextProfile: "C", PreSocksPort: 7890}}
	c := &config.PrfItem{UID: "C", Name: "C", Option: &config.PrfOption{PrevProfile: "B"}}
	db := &config.ProfilesDB{Items: []*config.PrfItem{a, b, c}}

	want := []string{"A", "B", "C"}
	for _, tc := range []struct {
		name string
		item *config.PrfItem
	}{
		{"from first", a},
		{"from middle", b},
		{"from last", c},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildChain(db, tc.item)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("BuildChain = %v, want %v", got, want)
			}
		})
	}
}

// TestBuildChainCycle verifies cycle detection: a ring X -> Y -> Z -> X
// terminates and never repeats a UID.
func TestBuildChainCycle(t *testing.T) {
	x := &config.PrfItem{UID: "X", Option: &config.PrfOption{NextProfile: "Y"}}
	y := &config.PrfItem{UID: "Y", Option: &config.PrfOption{NextProfile: "Z"}}
	z := &config.PrfItem{UID: "Z", Option: &config.PrfOption{NextProfile: "X"}}
	db := &config.ProfilesDB{Items: []*config.PrfItem{x, y, z}}

	got := BuildChain(db, x)
	want := []string{"X", "Y", "Z"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildChain with cycle = %v, want %v", got, want)
	}

	// Starting elsewhere in the same ring must also terminate; the walk just
	// stops when it reaches a UID already seen (Z here).
	got = BuildChain(db, z)
	want = []string{"Z", "X", "Y"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildChain from another ring node = %v, want %v", got, want)
	}
}

// TestBuildChainMissingRef covers dangling references and nil inputs.
func TestBuildChainMissingRef(t *testing.T) {
	a := &config.PrfItem{UID: "A", Option: &config.PrfOption{PrevProfile: "gone", NextProfile: "also-gone"}}
	db := &config.ProfilesDB{Items: []*config.PrfItem{a}}
	if got, want := BuildChain(db, a), []string{"A"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildChain with dangling refs = %v, want %v", got, want)
	}
	if got := BuildChain(nil, a); got != nil {
		t.Fatalf("BuildChain(nil db) = %v, want nil", got)
	}
	if got := BuildChain(db, nil); got != nil {
		t.Fatalf("BuildChain(nil item) = %v, want nil", got)
	}
}
