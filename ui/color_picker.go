package ui

import (
	"fmt"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/oklch"
)

// openColorPicker initializes the picker state from the current accent color.
func (a *App) openColorPicker() {
	col := ui.Hex(a.Settings.PrimaryColor)
	o := oklch.FromRGB(oklch.RGB{R: col.R, G: col.G, B: col.B})
	a.ColorL, a.ColorC, a.ColorH = o.L, o.C, o.H
	a.ColorPickerOpen = true
}

func (a *App) overlayColorPicker(c *ui.Context) {
	ui.Modal(c, &a.ColorPickerOpen, func() {
		ui.Column(c).Width(440).Padding(24).Gap(16).
			Background(c.Theme().Surface).Radius(12).Children(func() {
			text(c, "取色器 (OKLCH)").FontSize(18).Bold()

			// Live preview swatch.
			preview := oklch.OKLCH{L: a.ColorL, C: a.ColorC, H: a.ColorH}.ToRGB()
			hex := fmt.Sprintf("#%02x%02x%02x", preview.R, preview.G, preview.B)
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				ui.Box(c).Size(64, 64).Radius(12).Background(ui.RGB(preview.R, preview.G, preview.B))
				ui.Column(c).Gap(4).Children(func() {
					text(c, hex).FontSize(18).Bold()
					text(c, "感知均匀色彩 · 亮度优先").FontSize(11).TextColor(c.Theme().TextMuted)
				})
			})

			// Three perceptual sliders.
			text(c, fmt.Sprintf("亮度 L  %.2f", a.ColorL)).FontSize(12)
			ui.Slider(c, &a.ColorL, 0.2, 0.98)
			text(c, fmt.Sprintf("色度 C  %.2f", a.ColorC)).FontSize(12)
			ui.Slider(c, &a.ColorC, 0, 0.25)
			text(c, fmt.Sprintf("色相 H  %.0f°", a.ColorH)).FontSize(12)
			ui.Slider(c, &a.ColorH, 0, 360)

			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, "取消").Clicked() {
					a.ColorPickerOpen = false
				}
				if ui.PrimaryButton(c, "应用").Clicked() {
					a.Settings.PrimaryColor = hex
					a.Settings.UseSystemAccent = false
					a.mustSaveSettings()
					a.ColorPickerOpen = false
				}
			})
		})
	})
}
