package oklch

import (
	"math"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	cases := []RGB{
		{255, 0, 0}, {0, 255, 0}, {0, 0, 255},
		{91, 140, 255}, {255, 255, 255}, {26, 26, 26},
	}
	for _, c := range cases {
		got := FromRGB(c).ToRGB()
		dr := int(got.R) - int(c.R)
		dg := int(got.G) - int(c.G)
		db := int(got.B) - int(c.B)
		if math.Abs(float64(dr)) > 2 || math.Abs(float64(dg)) > 2 || math.Abs(float64(db)) > 2 {
			t.Errorf("roundtrip %v -> %v (diff %d,%d,%d)", c, got, dr, dg, db)
		}
	}
}

func TestOKLCHLightness(t *testing.T) {
	// Colors with the same OKLCH L should have similar perceived brightness.
	a := OKLCH{0.7, 0.15, 30}.ToRGB()
	b := OKLCH{0.7, 0.15, 200}.ToRGB()
	lum := func(c RGB) float64 { return 0.2126*float64(c.R) + 0.7152*float64(c.G) + 0.0722*float64(c.B) }
	if math.Abs(lum(a)-lum(b)) > 40 {
		t.Errorf("same-L colors differ too much in luminance: %.0f vs %.0f", lum(a), lum(b))
	}
}
