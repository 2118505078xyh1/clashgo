package ui

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"
)

// Clash Party design tokens. Kept in one place so every page shares the
// same semantic colors, radii and elevation.
const (
	partyPrimary    = "#006FEE"
	partyOnPrimary  = "#FFFFFF"
	partySurface1   = "#18181B"
	partySurface2   = "#27272A"
	partySurface3   = "#3F3F46"
	partyForeground = "#E4E4E7"
	partyMuted      = "#A1A1AA"
	partySuccess    = "#17C964"
	partyWarning    = "#F5A524"
	partyDanger     = "#F31260"

	partyRadiusSmall  = 8
	partyRadiusMedium = 12
	partyRadiusLarge  = 14
)

// applyRefinedTheme applies the fixed dark Clash Party palette. The accent is
// the token primary unless a user explicitly picked another color.
func applyRefinedTheme(c *ui.Context, accentHex string, mode string) {
	accent := ui.Hex(normalizeAccent(accentHex))
	primary := ui.Hex(partyPrimary)

	t := *ui.DarkTheme()
	t.Dark = true
	t.Background = ui.Hex(partySurface1)
	t.Surface = ui.Hex(partySurface2)
	t.SurfaceHover = ui.Hex(partySurface3)
	t.SurfacePressed = ui.Hex("#52525B")
	t.Border = ui.Hex(partySurface3)
	t.Text = ui.Hex(partyForeground)
	t.TextMuted = ui.Hex(partyMuted)
	t.Accent = accent
	t.AccentHover = mix(accent, ui.Hex("#FFFFFF"), 0.18)
	t.AccentPressed = mix(accent, ui.Hex("#000000"), 0.18)
	t.AccentText = ui.Hex(partyOnPrimary)
	t.Success = ui.Hex(partySuccess)
	t.Warning = ui.Hex(partyWarning)
	t.Danger = ui.Hex(partyDanger)
	t.Selection = withAlpha(primary, 0.35)
	t.Focus = withAlpha(primary, 0.6)
	t.Scrollbar = ui.Hex("#52525B")
	t.Radius = partyRadiusLarge
	t.Spacing = 5
	t.FocusRingWidth = 2
	c.SetTheme(&t)
}

// normalizeAccent maps the legacy default blue and empty values to the
// Clash Party primary, while leaving explicit user choices untouched.
func normalizeAccent(hex string) string {
	if hex == "" || strings.EqualFold(hex, "#5b8cff") || strings.EqualFold(hex, partyPrimary) {
		return partyPrimary
	}
	return hex
}

// colorToHex converts a mygo Color to a #rrggbb string.
func colorToHex(c ui.Color) string {
	return fmt.Sprintf("#%02x%02x%02x", c.R, c.G, c.B)
}

// mix blends two colors; t=0 returns a, t=1 returns b.
func mix(a, b ui.Color, t float32) ui.Color {
	ar, ag, ab, aa := a.R, a.G, a.B, float32(a.A)/255
	br, bg, bb, ba := b.R, b.G, b.B, float32(b.A)/255
	m := func(x, y uint8) uint8 { return uint8(float32(x)*(1-t) + float32(y)*t) }
	return ui.RGBA(m(ar, br), m(ag, bg), m(ab, bb), aa*(1-t)+ba*t)
}

// withAlpha scales a color's alpha channel.
func withAlpha(c ui.Color, a float32) ui.Color {
	return c.Alpha(a)
}
