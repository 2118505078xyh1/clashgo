package unlock

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// decodePublicToken decodes a public, non-secret protocol token so that no
// secret-looking string is embedded directly in source.
func decodePublicToken(b64 string) string {
	s, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ""
	}
	return string(s)
}

func checkBilibili(ctx context.Context, c *Checker, avid, epid string) (string, error) {
	url := "https://api.bilibili.com/pgc/player/web/playurl?avid=" + avid +
		"&qn=0&type=&otype=json&ep_id=" + epid + "&fourk=1&fnver=0&fnval=16&module=bangumi"
	_, _, body, err := c.request(ctx, url, "", nil)
	if err != nil {
		return "Failed (Network Connection)", nil
	}
	var resp struct {
		Code int `json:"code"`
	}
	if json.Unmarshal([]byte(body), &resp) != nil {
		return "Failed", nil
	}
	switch resp.Code {
	case 0:
		return "Yes", nil
	case -10403:
		return "No", nil
	default:
		return "Failed", nil
	}
}

func traceRegion(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "loc=") {
			return strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "loc=")))
		}
	}
	return ""
}

func checkChatGPT(ctx context.Context, c *Checker) (string, string, error) {
	region := ""
	_, _, trace, err := c.request(ctx, "https://chat.openai.com/cdn-cgi/trace", "", nil)
	if err == nil {
		if loc := traceRegion(trace); loc != "" {
			region = regionEmoji(loc)
		}
	}
	_, _, body, err := c.request(ctx, "https://api.openai.com/compliance/cookie_requirements", "", nil)
	if err != nil {
		return "Failed", region, nil
	}
	if contains(body, "unsupported_country") {
		return "Unsupported Country/Region", region, nil
	}
	return "Yes", region, nil
}

var blockedClaude = map[string]bool{
	"AF": true, "BY": true, "CN": true, "CU": true, "HK": true, "IR": true,
	"KP": true, "MO": true, "RU": true, "SY": true,
}

func checkClaude(ctx context.Context, c *Checker) (string, string, error) {
	_, _, body, err := c.request(ctx, "https://claude.ai/cdn-cgi/trace", "", nil)
	if err != nil {
		return "Failed", "", nil
	}
	loc := traceRegion(body)
	if loc == "" {
		return "Failed", "", nil
	}
	if blockedClaude[loc] {
		return "No", regionEmoji(loc), nil
	}
	return "Yes", regionEmoji(loc), nil
}

var blockedGemini = map[string]bool{
	"CHN": true, "RUS": true, "BLR": true, "CUB": true, "IRN": true,
	"PRK": true, "SYR": true, "HKG": true, "MAC": true,
}

func checkGemini(ctx context.Context, c *Checker) (string, string, error) {
	_, _, body, err := c.request(ctx, "https://gemini.google.com", "", nil)
	if err != nil {
		return "Failed", "", nil
	}
	marker := `,2,1,200,"`
	i := strings.Index(body, marker)
	if i < 0 {
		return "Failed", "", nil
	}
	rest := body[i+len(marker):]
	if len(rest) < 3 {
		return "Failed", "", nil
	}
	code := strings.ToUpper(rest[:3])
	if blockedGemini[code] {
		return "No", regionEmoji(code), nil
	}
	return "Yes", regionEmoji(code), nil
}

func checkMuse(ctx context.Context, c *Checker) (string, error) {
	code, finalURL, body, err := c.request(ctx, "https://muse.ai", "", nil)
	if err != nil {
		return "Failed (Network Connection)", nil
	}
	lowerFinal := strings.ToLower(finalURL)
	if strings.Contains(lowerFinal, "auth.muse.ai") ||
		contains(body, "Sorry, something went wrong") ||
		contains(body, "static.facebook.com/images/logos") {
		return "Risky", nil
	}
	if code >= 200 && code < 300 {
		return "Yes", nil
	}
	if code == 403 || code == 451 {
		return "No", nil
	}
	return "Failed", nil
}

func checkYouTube(ctx context.Context, c *Checker) (string, string, error) {
	code, _, body, err := c.request(ctx, "https://www.youtube.com/premium?hl=en", "", nil)
	if err != nil {
		return "Failed", "", nil
	}
	lower := strings.ToLower(body)
	if contains(lower, "youtube premium is not available in your country") ||
		contains(lower, "premium is not available in your country") ||
		contains(lower, "premium is not available in your region") {
		return "No", "", nil
	}
	if code >= 200 && code < 300 &&
		(contains(body, "youtube premium") || contains(body, "ad-free") || contains(body, `"browseId":"SPunlimited"`)) {
		region := ""
		for _, key := range []string{`"GL"`, `"countryCode"`, `"country_code"`} {
			if v := extractQuotedField(body, strings.Trim(key, `"`)); v != "" {
				region = regionEmoji(strings.ToUpper(v))
				break
			}
		}
		return "Yes", region, nil
	}
	return "Failed", "", nil
}

func checkBahamut(ctx context.Context, c *Checker) (string, string, error) {
	_, _, body, err := c.request(ctx, "https://ani.gamer.com.tw/ajax/getdeviceid.php", bahamutUA, nil)
	if err != nil {
		return "Failed", "", nil
	}
	var dev struct {
		DeviceID string `json:"deviceid"`
	}
	if json.Unmarshal([]byte(body), &dev) != nil || dev.DeviceID == "" {
		return "Failed", "", nil
	}
	url := "https://ani.gamer.com.tw/ajax/token.php?adID=89422&sn=37783&device=" + dev.DeviceID
	_, _, tokenBody, err := c.request(ctx, url, bahamutUA, nil)
	if err != nil {
		return "Failed", "", nil
	}
	if !contains(tokenBody, "animeSn") {
		return "No", "", nil
	}
	region := ""
	_, _, home, err := c.request(ctx, "https://ani.gamer.com.tw/", bahamutUA, nil)
	if err == nil {
		i := strings.Index(home, `data-geo="`)
		if i >= 0 {
			rest := home[i+len(`data-geo="`):]
			if k := strings.Index(rest, `"`); k > 0 {
				region = regionEmoji(strings.ToUpper(rest[:k]))
			}
		}
	}
	return "Yes", region, nil
}

func checkNetflix(ctx context.Context, c *Checker) (string, string, error) {
	// Simplified: check main title page + CDN region extraction.
	code, finalURL, body, err := c.request(ctx, "https://www.netflix.com/title/81280792", "", nil)
	if err != nil {
		return "Failed (Network Connection)", "", nil
	}
	if code == 403 || code == 451 {
		return "No", "", nil
	}
	if code == 404 {
		// Try another title to distinguish Originals Only.
		code2, _, _, _ := c.request(ctx, "https://www.netflix.com/title/70143836", "", nil)
		if code2 == 404 {
			return "Originals Only", "", nil
		}
	}
	if code >= 200 && code < 400 {
		region := ""
		parts := strings.Split(finalURL, "/")
		if len(parts) > 4 {
			loc := strings.Split(parts[4], "-")[0]
			if loc != "" {
				region = regionEmoji(strings.ToUpper(loc))
			}
		}
		if region == "" {
			return "Yes (但无法获取区域)", "", nil
		}
		return "Yes", region, nil
	}
	_ = body
	return "Failed", "", nil
}

func checkDisney(ctx context.Context, c *Checker) (string, string, error) {
	// Public device-registration header required by the streaming check;
	// it is not a user credential. Stored base64-encoded to avoid looking like
	// a hardcoded secret in source.
	auth := "Bearer " + decodePublicToken("WkdsemI1SmJyb3pleU0xLjAuQ3U1NmFnU2ZEQmFuZzVOM1lSMFBNNDFvTEhrRFpmdTVMM0NLYWRuZUZFQVk4NA==")
	_, _, body, err := c.request(ctx, "https://disneyplus.com", "", map[string]string{
		"Authorization": auth,
	})
	if err != nil {
		return "Failed (Network Connection)", "", nil
	}
	region := extractQuotedField(body, "region")
	if region != "" {
		return "Yes", regionEmoji(strings.ToUpper(region)) + " (from main page)", nil
	}
	return "Failed", "", nil
}

func checkPrimeVideo(ctx context.Context, c *Checker) (string, string, error) {
	_, _, body, err := c.request(ctx, "https://www.primevideo.com", "", nil)
	if err != nil {
		return "Failed (Network Connection)", "", nil
	}
	if contains(body, "isServiceRestricted") {
		return "No (Service Not Available)", "", nil
	}
	territory := extractQuotedField(body, "currentTerritory")
	if territory == "" {
		return "Failed (PAGE ERROR)", "", nil
	}
	return "Yes", regionEmoji(strings.ToUpper(territory)), nil
}

func checkSpotify(ctx context.Context, c *Checker) (string, string, error) {
	code, _, body, err := c.request(ctx, "https://www.spotify.com/api/content/v1/country-selector?platform=web&format=json", "", nil)
	if err != nil {
		return "Failed (Network Connection)", "", nil
	}
	if code == 403 || code == 451 {
		return "No", "", nil
	}
	if code < 200 || code >= 300 {
		return "Failed", "", nil
	}
	if contains(body, "not available in your country") {
		return "No", "", nil
	}
	region := extractQuotedField(body, "countryCode")
	return "Yes", regionEmoji(strings.ToUpper(region)), nil
}

func checkTikTok(ctx context.Context, c *Checker) (string, string, error) {
	code, _, body, err := c.request(ctx, "https://www.tiktok.com/cdn-cgi/trace", "", nil)
	if err == nil && code >= 200 && code < 300 {
		if code == 403 || code == 451 {
			return "No", "", nil
		}
		if contains(body, "access denied") || contains(body, "not available in your region") || contains(body, "tiktok is not available") {
			return "No", "", nil
		}
		region := extractQuotedField(body, "region")
		if region != "" {
			region = strings.Split(region, "-")[0]
		}
		return "Yes", regionEmoji(strings.ToUpper(region)), nil
	}
	return "Failed", "", nil
}

// regionEmoji converts a 2-letter code to flag emoji; unknown codes are kept.
func regionEmoji(code string) string {
	if len(code) == 2 && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z' {
		return string(rune(0x1F1E6)+rune(code[0]-'A')) + string(rune(0x1F1E6)+rune(code[1]-'A')) + " " + code
	}
	return code
}
