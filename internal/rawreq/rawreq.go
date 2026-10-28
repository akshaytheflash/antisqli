// Package rawreq parses HTTP requests from several user friendly formats:
// raw HTTP request files (as exported by Burp Suite or browser devtools),
// curl commands and plain URLs.
package rawreq

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ParseRaw parses a raw HTTP request. scheme is used when the request target
// is not an absolute URL (default "https").
func ParseRaw(data []byte, scheme string) (*http.Request, error) {
	if scheme == "" {
		scheme = "https"
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.TrimLeft(text, "\n")
	if text == "" {
		return nil, fmt.Errorf("empty request")
	}
	head, body, _ := strings.Cut(text, "\n\n")
	lines := strings.Split(head, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("missing request line")
	}

	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed request line %q", lines[0])
	}
	method := strings.ToUpper(parts[0])
	target := parts[1]

	header := http.Header{}
	host := ""
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			// Header folding: append to previous value.
			keys := make([]string, 0, len(header))
			for k := range header {
				keys = append(keys, k)
			}
			if len(keys) > 0 {
				k := keys[len(keys)-1]
				header[k][len(header[k])-1] += " " + strings.TrimSpace(line)
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if strings.EqualFold(name, "Host") {
			host = value
			continue
		}
		header.Add(name, value)
	}

	var fullURL string
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		fullURL = target
	} else {
		if host == "" {
			return nil, fmt.Errorf("raw request has no Host header")
		}
		if !strings.HasPrefix(target, "/") {
			target = "/" + target
		}
		fullURL = scheme + "://" + host + target
	}
	if _, err := url.Parse(fullURL); err != nil {
		return nil, fmt.Errorf("invalid target URL %q: %w", fullURL, err)
	}

	var reader *bytes.Reader
	if body != "" {
		reader = bytes.NewReader([]byte(body))
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, fullURL, reader)
	if err != nil {
		return nil, err
	}
	req.Header = header
	if body != "" {
		req.ContentLength = int64(len(body))
	}
	return req, nil
}

// ParseCurl parses a curl command line into an HTTP request. Supported flags:
// -X/--request, -H/--header, -d/--data/--data-raw/--data-binary,
// -b/--cookie, -u/--user, -A/--user-agent, --compressed, -k/--insecure,
// --url, and a bare URL argument. Quoting follows shell conventions loosely.
func ParseCurl(cmdline string) (*http.Request, bool, error) {
	tokens, err := shellSplit(cmdline)
	if err != nil {
		return nil, false, err
	}
	if len(tokens) == 0 {
		return nil, false, fmt.Errorf("empty curl command")
	}
	if strings.EqualFold(tokens[0], "curl") {
		tokens = tokens[1:]
	}

	var (
		method   string
		rawURL   string
		body     string
		hasBody  bool
		headers  = http.Header{}
		insecure bool
	)
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		next := func() (string, error) {
			if i+1 >= len(tokens) {
				return "", fmt.Errorf("flag %s requires a value", tok)
			}
			i++
			return tokens[i], nil
		}
		switch {
		case tok == "-X" || tok == "--request":
			v, err := next()
			if err != nil {
				return nil, false, err
			}
			method = strings.ToUpper(v)
		case tok == "-H" || tok == "--header":
			v, err := next()
			if err != nil {
				return nil, false, err
			}
			name, value, ok := strings.Cut(v, ":")
			if ok {
				headers.Add(strings.TrimSpace(name), strings.TrimSpace(value))
			}
		case tok == "-d" || tok == "--data" || tok == "--data-raw" || tok == "--data-binary" || tok == "--data-urlencode":
			v, err := next()
			if err != nil {
				return nil, false, err
			}
			if hasBody {
				body += "&" + v
			} else {
				body = v
			}
			hasBody = true
			if method == "" {
				method = http.MethodPost
			}
		case tok == "-b" || tok == "--cookie":
			v, err := next()
			if err != nil {
				return nil, false, err
			}
			headers.Set("Cookie", v)
		case tok == "-u" || tok == "--user":
			v, err := next()
			if err != nil {
				return nil, false, err
			}
			headers.Set("Authorization", "Basic "+basicAuth(v))
		case tok == "-A" || tok == "--user-agent":
			v, err := next()
			if err != nil {
				return nil, false, err
			}
			headers.Set("User-Agent", v)
		case tok == "-k" || tok == "--insecure":
			insecure = true
		case tok == "--compressed":
			// no-op: Go handles gzip transparently
		case tok == "--url":
			v, err := next()
			if err != nil {
				return nil, false, err
			}
			rawURL = v
		case strings.HasPrefix(tok, "-"):
			// Unknown flag: skip a following value only when it does not look
			// like a URL.
			if i+1 < len(tokens) && !strings.HasPrefix(tokens[i+1], "-") &&
				!strings.HasPrefix(tokens[i+1], "http") {
				i++
			}
		default:
			if rawURL == "" {
				rawURL = tok
			}
		}
	}
	if rawURL == "" {
		return nil, insecure, fmt.Errorf("curl command has no URL")
	}
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	if method == "" {
		method = http.MethodGet
	}
	if hasBody && headers.Get("Content-Type") == "" {
		headers.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	var reader *bytes.Reader
	if hasBody {
		reader = bytes.NewReader([]byte(body))
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		return nil, insecure, err
	}
	req.Header = headers
	if hasBody {
		req.ContentLength = int64(len(body))
	}
	return req, insecure, nil
}

func basicAuth(creds string) string {
	return base64.StdEncoding.EncodeToString([]byte(creds))
}

// shellSplit splits a command line honoring single quotes, double quotes and
// backslash escapes.
func shellSplit(s string) ([]string, error) {
	var (
		tokens  []string
		current strings.Builder
		quote   rune
		escaped bool
		started bool
	)
	for _, r := range s {
		if escaped {
			current.WriteRune(r)
			escaped = false
			started = true
			continue
		}
		switch {
		case r == '\\' && quote != '\'':
			escaped = true
			started = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			started = true
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			if started {
				tokens = append(tokens, current.String())
				current.Reset()
				started = false
			}
		default:
			current.WriteRune(r)
			started = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in curl command")
	}
	if escaped {
		current.WriteRune('\\')
	}
	if started {
		tokens = append(tokens, current.String())
	}
	return tokens, nil
}

// ParseHeaders converts ["Name: value", ...] into an http.Header.
func ParseHeaders(lines []string) (http.Header, error) {
	h := http.Header{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("invalid header %q (expected \"Name: value\")", line)
		}
		h.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	return h, nil
}

// ParseCookies parses a cookie header value into a map.
func ParseCookies(raw string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}
