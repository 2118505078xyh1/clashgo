package ipinfo

import "testing"

func TestParseFormats(t *testing.T) {
	cases := []struct {
		body string
		ip   string
		cc   string
	}{
		{`{"status":"success","query":"1.2.3.4","country":"United States","countryCode":"US"}`, "1.2.3.4", "US"},
		{`{"ip":"5.6.7.8","country_code":"JP","city":"Tokyo"}`, "5.6.7.8", "JP"},
		{`{"clientIp":"9.10.11.12","country":"Germany","countryCode":"DE"}`, "9.10.11.12", "DE"},
		{`{"ip_addr":"13.14.15.16","location":{"country_code":"SG"}}`, "13.14.15.16", "SG"},
	}
	for _, c := range cases {
		info, err := Parse([]byte(c.body))
		if err != nil {
			t.Fatalf("parse %s: %v", c.body, err)
		}
		if info.IP != c.ip || info.CountryCode != c.cc {
			t.Errorf("got %s/%s, want %s/%s", info.IP, info.CountryCode, c.ip, c.cc)
		}
	}
}
