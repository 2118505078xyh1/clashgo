package ui

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"
)

// 设计令牌（design tokens）。
//
// 全部集中在这一处，保证每个页面共享同一套颜色、圆角、间距与层次。
// 命名按语义（surface1/2/3、accent、success…）而不是按颜色，
// 这样换主题时只需要改这一处。

const (
	// 品牌主色：蓝紫渐变的起点。
	brandPrimary   = "#3B82F6"
	brandSecondary = "#8B5CF6"
	// 强调色（可被用户设置覆盖）。
	accentDefault = "#4F8CFF"

	// 表面层次：越靠前的层越亮，制造"浮起"的纵深。
	surfaceBase    = "#0B0D14" // 窗口底色
	surfaceRaised  = "#141824" // 侧栏 / 顶层容器
	surfaceCard    = "#181C2A" // 卡片
	surfaceOverlay = "#1E2333" // 浮层 / 弹窗
	surfaceHover   = "#252B3D" // 悬停
	surfaceActive  = "#2E3550" // 按下

	// 描边：默认几乎不可见，强调时才显现。
	borderSubtle = "#232838"
	borderCard   = "#2A3044"
	borderStrong = "#3A4260"

	// 文字层次。
	textPrimary   = "#F0F2F8"
	textSecondary = "#A8B0C4"
	textTertiary  = "#6B7490"
	textOnAccent  = "#FFFFFF"

	// 语义色。
	colorSuccess = "#34D399"
	colorWarning = "#FBBF24"
	colorDanger  = "#F87171"
	colorInfo    = "#60A5FA"

	// 圆角。
	radiusSm   = 8
	radiusMd   = 12
	radiusLg   = 16
	radiusXl   = 20
	radiusFull = 999

	// 间距节奏（8 的倍数）。
	spaceXs  = 4
	spaceSm  = 8
	spaceMd  = 12
	spaceLg  = 16
	spaceXl  = 24
	space2Xl = 32
)

// 旧令牌别名：保留历史命名，避免大面积改动页面代码。
// 新代码请直接用上面的语义化令牌。
const (
	partyPrimary    = accentDefault
	partyOnPrimary  = textOnAccent
	partySurface1   = surfaceBase
	partySurface2   = surfaceCard
	partySurface3   = surfaceHover
	partyForeground = textPrimary
	partyMuted      = textSecondary
	partySuccess    = colorSuccess
	partyWarning    = colorWarning
	partyDanger     = colorDanger

	partyRadiusSmall  = radiusSm
	partyRadiusMedium = radiusMd
	partyRadiusLarge  = radiusLg
)

// applyRefinedTheme 应用深色主题。
//
// accentHex 为空或等于历史默认值时使用品牌蓝；用户显式选择的颜色保持不变。
func applyRefinedTheme(c *ui.Context, accentHex string, mode string) {
	accent := ui.Hex(normalizeAccent(accentHex))

	t := *ui.DarkTheme()
	t.Dark = true

	t.Background = ui.Hex(surfaceBase)
	t.Surface = ui.Hex(surfaceCard)
	t.SurfaceHover = ui.Hex(surfaceHover)
	t.SurfacePressed = ui.Hex(surfaceActive)
	t.Border = ui.Hex(borderCard)

	t.Text = ui.Hex(textPrimary)
	t.TextMuted = ui.Hex(textSecondary)

	t.Accent = accent
	t.AccentHover = mix(accent, ui.Hex("#FFFFFF"), 0.16)
	t.AccentPressed = mix(accent, ui.Hex("#000000"), 0.16)
	t.AccentText = ui.Hex(textOnAccent)

	t.Success = ui.Hex(colorSuccess)
	t.Warning = ui.Hex(colorWarning)
	t.Danger = ui.Hex(colorDanger)

	t.Selection = withAlpha(accent, 0.28)
	t.Focus = withAlpha(accent, 0.55)
	t.Scrollbar = ui.Hex(borderStrong)

	t.Radius = radiusMd
	t.Spacing = 5
	t.FocusRingWidth = 2
	c.SetTheme(&t)
}

// normalizeAccent 把空值和历史默认蓝映射到品牌色，其余用户选择保持不变。
func normalizeAccent(hex string) string {
	if hex == "" || strings.EqualFold(hex, "#5b8cff") || strings.EqualFold(hex, accentDefault) {
		return accentDefault
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

// brandGradient 返回品牌蓝紫渐变。
func brandGradient() ui.LinearGradient {
	return ui.LinearGradient{
		From:  ui.Hex(brandPrimary),
		To:    ui.Hex(brandSecondary),
		Angle: 135,
	}
}

// accentGradient 返回当前强调色的渐变（用于主按钮 / 选中态）。
func accentGradient(accent ui.Color) ui.LinearGradient {
	return ui.LinearGradient{
		From:  accent,
		To:    mix(accent, ui.Hex(brandSecondary), 0.45),
		Angle: 135,
	}
}

// elevationShadow 返回一层柔和的投影。
// level 1 最轻（卡片），2 中等（弹窗），3 最重（浮层）。
func elevationShadow(level int) ui.Color {
	switch level {
	case 1:
		return withAlpha(ui.Hex("#000000"), 0.28)
	case 3:
		return withAlpha(ui.Hex("#000000"), 0.55)
	default:
		return withAlpha(ui.Hex("#000000"), 0.42)
	}
}
