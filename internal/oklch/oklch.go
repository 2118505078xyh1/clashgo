// Package oklch implements the OKLCH perceptual color space converter.
// OKLCH is more intuitive than HSL: L=lightness, C=chroma, H=hue, and colors
// with the same L have similar perceived brightness (Material You/HCT idea).
package oklch

import "math"

// OKLCH holds lightness (0..1), chroma (0..0.4), hue (0..360 degrees).
type OKLCH struct {
	L, C, H float64
}

// RGB holds sRGB components in 0..255.
type RGB struct{ R, G, B uint8 }

// ToRGB converts OKLCH to sRGB via OKLab.
func (o OKLCH) ToRGB() RGB {
	h := o.H * math.Pi / 180
	a := o.C * math.Cos(h)
	b := o.C * math.Sin(h)
	l_ := o.L + 0.3963377774*a + 0.2158037573*b
	m_ := o.L - 0.1055613458*a - 0.0638541728*b
	s_ := o.L - 0.0894841775*a - 1.2914855480*b
	l, m, s := l_*l_*l_, m_*m_*m_, s_*s_*s_
	lr := +4.0767416621*l - 3.3077115913*m + 0.2309699292*s
	lg := -1.2684380046*l + 2.6097574011*m - 0.3413193965*s
	lb := -0.0041960863*l - 0.7034186147*m + 1.7076147010*s
	return RGB{u8(lr), u8(lg), u8(lb)}
}

func u8(x float64) uint8 {
	if x <= 0 {
		return 0
	}
	if x >= 1 {
		return 255
	}
	// sRGB gamma.
	if x <= 0.0031308 {
		x = 12.92 * x
	} else {
		x = 1.055*math.Pow(x, 1/2.4) - 0.055
	}
	if x <= 0 {
		return 0
	}
	if x >= 1 {
		return 255
	}
	return uint8(x*255 + 0.5)
}

// FromRGB converts sRGB to OKLCH (inverse of ToRGB).
func FromRGB(rgb RGB) OKLCH {
	r, g, b := lin(rgb.R), lin(rgb.G), lin(rgb.B)
	l := math.Cbrt(0.4122214708*r + 0.5363325363*g + 0.0514459929*b)
	m := math.Cbrt(0.2119034982*r + 0.6806995451*g + 0.1073969566*b)
	s := math.Cbrt(0.0883024619*r + 0.2817188376*g + 0.6299787005*b)
	L := 0.2104542553*l + 0.7936177850*m - 0.0040720468*s
	a := 1.9779984951*l - 2.4285922050*m + 0.4505937099*s
	bb := 0.0259040371*l + 0.7827717662*m - 0.8086757660*s
	C := math.Sqrt(a*a + bb*bb)
	H := math.Atan2(bb, a) * 180 / math.Pi
	if H < 0 {
		H += 360
	}
	return OKLCH{L, C, H}
}

func lin(v uint8) float64 {
	x := float64(v) / 255
	if x <= 0.04045 {
		return x / 12.92
	}
	return math.Pow((x+0.055)/1.055, 2.4)
}
