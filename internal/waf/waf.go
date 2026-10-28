// Package waf detects web application firewalls and request blocking from
// response characteristics.
package waf

import (
	"regexp"
	"strings"

	"github.com/akshaytheflash/antisqli/internal/model"
)

// Result describes a detected WAF.
type Result struct {
	Detected bool     `json:"detected"`
	Name     string   `json:"name,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
	Blocked  bool     `json:"blocked"`
	Status   int      `json:"status,omitempty"`
	Hints    []string `json:"hints,omitempty"`
}

type signature struct {
	name    string
	header  string
	pattern *regexp.Regexp
}

var bodySignatures = []signature{
	{"Cloudflare", "", regexp.MustCompile(`(?i)cloudflare|cf-error-details|attention required! \| cloudflare`)},
	{"Akamai", "", regexp.MustCompile(`(?i)akamai|reference #\d+\.[0-9a-f]+`)},
	{"Imperva Incapsula", "", regexp.MustCompile(`(?i)incapsula|imperva`)},
	{"Sucuri", "", regexp.MustCompile(`(?i)sucuri website firewall|sucuri\.net`)},
	{"AWS WAF", "", regexp.MustCompile(`(?i)aws waf|request blocked.*cloudfront`)},
	{"F5 BIG-IP", "", regexp.MustCompile(`(?i)big-?ip|the requested url was rejected`)},
	{"ModSecurity", "", regexp.MustCompile(`(?i)mod_security|modsecurity|not acceptable.*406`)},
	{"Wordfence", "", regexp.MustCompile(`(?i)wordfence|your access to this site has been limited`)},
	{"Barracuda", "", regexp.MustCompile(`(?i)barracuda|barra_counter_session`)},
	{"FortiWeb", "", regexp.MustCompile(`(?i)fortiweb|fortigate`)},
	{"Citrix NetScaler", "", regexp.MustCompile(`(?i)netscaler|citrix.*appfw`)},
	{"Wallarm", "", regexp.MustCompile(`(?i)wallarm`)},
	{"Radware", "", regexp.MustCompile(`(?i)radware`)},
	{"SafeDog", "", regexp.MustCompile(`(?i)safedog`)},
	{"360 WAF", "", regexp.MustCompile(`(?i)360wzws|wangzhan\.360\.cn`)},
	{"Generic block page", "", regexp.MustCompile(`(?i)access denied|request rejected|blocked by|security policy`)},
}

var headerSignatures = []signature{
	{"Cloudflare", "cf-ray", nil},
	{"Cloudflare", "cf-cache-status", nil},
	{"Akamai", "x-akamai-transformed", nil},
	{"Akamai", "akamai-grn", nil},
	{"Imperva Incapsula", "x-iinfo", nil},
	{"Sucuri", "x-sucuri-id", nil},
	{"AWS WAF", "x-amzn-requestid", nil},
	{"AWS CloudFront", "x-amz-cf-id", nil},
	{"F5 BIG-IP", "x-wa-info", nil},
	{"Barracuda", "barra-counter-session", nil},
	{"FortiWeb", "fortiwafsid", nil},
	{"Wallarm", "x-wallarm-waf-node", nil},
}

var serverSignatures = map[string]string{
	"cloudflare": "Cloudflare",
	"akamai":     "Akamai",
	"sucuri":     "Sucuri",
	"incapsula":  "Imperva Incapsula",
	"bigip":      "F5 BIG-IP",
	"barracuda":  "Barracuda",
	"wallarm":    "Wallarm",
	"yunsuo":     "Yunsuo",
	"safe3":      "Safe3",
}

// Detect inspects a response for WAF indicators. A response is considered
// "blocked" when it has a blocking status code or a WAF block page.
func Detect(resp *model.Response) Result {
	if resp == nil {
		return Result{}
	}
	res := Result{Status: resp.Status}
	body := resp.Text()
	if len(body) > 512<<10 {
		body = body[:512<<10]
	}

	for _, sig := range headerSignatures {
		if resp.Header != nil && resp.Header.Get(sig.header) != "" {
			res.Detected = true
			res.Name = sig.name
			res.Evidence = "header " + sig.header
			break
		}
	}

	if !res.Detected {
		for _, sig := range bodySignatures {
			if loc := sig.pattern.FindStringIndex(body); loc != nil {
				res.Detected = true
				res.Name = sig.name
				start := loc[0] - 30
				if start < 0 {
					start = 0
				}
				end := loc[1] + 30
				if end > len(body) {
					end = len(body)
				}
				res.Evidence = strings.TrimSpace(body[start:end])
				break
			}
		}
	}

	if !res.Detected && resp.Header != nil {
		server := strings.ToLower(resp.Header.Get("Server"))
		for needle, name := range serverSignatures {
			if strings.Contains(server, needle) {
				res.Detected = true
				res.Name = name
				res.Evidence = "server header: " + resp.Header.Get("Server")
				break
			}
		}
	}

	switch resp.Status {
	case 403, 406, 419, 429, 501, 503:
		if res.Detected {
			res.Blocked = true
		}
	}
	if res.Detected {
		res.Hints = []string{
			"slow down with --delay and --rate",
			"rotate headers and user agents",
			"try --tamper space2comment,randomcase",
		}
	}
	return res
}

// Blocked reports whether a response looks like an active block.
func Blocked(resp *model.Response) bool {
	if resp == nil {
		return false
	}
	switch resp.Status {
	case 403, 406, 419, 429, 501, 503:
		return true
	}
	body := strings.ToLower(resp.Text())
	for _, needle := range []string{"access denied", "request blocked", "web application firewall", "not acceptable"} {
		if strings.Contains(body, needle) {
			return true
		}
	}
	return false
}
