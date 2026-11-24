package ui

import (
	"math"

	"github.com/egoist/mygo/ui"
)

// drawTrafficChart paints filled area charts with adaptive Y scaling:
//   - virtual guard points at both ends remove boundary jitter
//   - coefficient-of-variation based scaling keeps calm series low and
//     lets bursty series use the full height (idea from common practice)
func drawTrafficChart(p *ui.Painter, r ui.Rect, up, down []float64, t *ui.Theme) {
	if r.W <= 0 || r.H <= 0 {
		return
	}
	for i := 1; i < 4; i++ {
		y := r.Y + r.H*float32(i)/4
		p.Line(r.X, y, r.X+r.W, y, 1, withAlpha(t.Border, 0.6))
	}

	peak := adaptivePeak(append(append([]float64{}, down...), up...))
	series := func(data []float64, color ui.Color) {
		pts := prepareSeries(data)
		if len(pts) < 2 {
			return
		}
		n := len(pts)
		var line, area ui.Path
		for i, v := range pts {
			x := r.X + r.W*float32(i)/float32(n-1)
			y := r.Y + r.H - r.H*float32(math.Min(1, v/peak))
			if i == 0 {
				line.MoveTo(x, y)
				area.MoveTo(x, r.Y+r.H)
				area.LineTo(x, y)
			} else {
				line.LineTo(x, y)
				area.LineTo(x, y)
			}
		}
		area.LineTo(r.X+r.W, r.Y+r.H)
		p.FillPath(&area, withAlpha(color, 0.16))
		p.StrokePath(&line, 2, color)
	}
	series(down, t.Accent)
	series(up, t.Warning)
}

// prepareSeries adds a virtual guard point at each end (equal to the first
// and last real samples) so the curve meets the chart edges smoothly.
func prepareSeries(data []float64) []float64 {
	if len(data) < 2 {
		return data
	}
	out := make([]float64, 0, len(data)+2)
	out = append(out, data[0])
	out = append(out, data...)
	out = append(out, data[len(data)-1])
	return out
}

// adaptivePeak computes a Y-axis maximum from the coefficient of variation:
// calm series (low CV) map to the lower part of the chart, bursty series fill it.
func adaptivePeak(data []float64) float64 {
	if len(data) == 0 {
		return 1
	}
	var sum float64
	for _, v := range data {
		sum += v
	}
	mean := sum / float64(len(data))
	if mean <= 0 {
		return 1
	}
	var sq float64
	for _, v := range data {
		d := v - mean
		sq += d * d
	}
	std := math.Sqrt(sq / float64(len(data)))
	cv := std / mean
	// calm series: peak ~ mean*1.6 (stays in bottom ~60%); bursty: peak ~ max*1.15
	maxV := 0.0
	for _, v := range data {
		if v > maxV {
			maxV = v
		}
	}
	calm := mean * 1.6
	bursty := maxV * 1.15
	blend := math.Min(1, cv) // cv 0 -> calm, cv>=1 -> bursty
	peak := calm*(1-blend) + bursty*blend
	if peak < 1 {
		peak = 1
	}
	return peak
}
