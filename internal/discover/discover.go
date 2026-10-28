// Package discover extracts links, forms and injection points from HTTP
// responses and requests. It includes a small tolerant HTML tokenizer so the
// tool has no third-party dependencies.
package discover

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/akshaytheflash/antisqli/internal/model"
)

// Input is a form control.
type Input struct {
	Name  string
	Type  string
	Value string
}

// Form is an HTML form.
type Form struct {
	Action  string
	Method  string
	Enctype string
	Inputs  []Input
}

// Page holds everything discovered in one HTML document.
type Page struct {
	Links []string
	Forms []Form
}

// Options controls point extraction.
type Options struct {
	Level     int
	Params    []string // restrict to these names (empty = all)
	Skip      []string // names to ignore
	Headers   []string // extra headers to treat as injectable
	PathSegs  bool
	SkipEmpty bool
}

// PointsFromRequest enumerates injectable locations inside req.
func PointsFromRequest(req *http.Request, opts Options) []model.Point {
	if req == nil || req.URL == nil {
		return nil
	}
	if opts.Level <= 0 {
		opts.Level = 1
	}
	var points []model.Point
	skip := toSet(opts.Skip)
	allow := toSet(opts.Params)
	wanted := func(name string) bool {
		if skip[strings.ToLower(name)] {
			return false
		}
		if len(allow) == 0 {
			return true
		}
		return allow[strings.ToLower(name)]
	}

	base := model.Point{
		Method: req.Method,
		URL:    req.URL,
		Header: req.Header.Clone(),
		Body:   reqBody(req),
	}

	// Query string parameters.
	for _, name := range sortedKeys(req.URL.Query()) {
		if !wanted(name) {
			continue
		}
		p := base
		p.Location = model.LocQuery
		p.Name = name
		p.Original = req.URL.Query().Get(name)
		points = append(points, p)
	}

	// Form encoded body.
	ct := strings.ToLower(req.Header.Get("Content-Type"))
	if strings.Contains(ct, "x-www-form-urlencoded") || (ct == "" && looksLikeForm(string(base.Body))) {
		if form, err := url.ParseQuery(string(base.Body)); err == nil {
			base.BodyType = "form"
			for _, name := range sortedKeys(form) {
				if !wanted(name) {
					continue
				}
				p := base
				p.Location = model.LocBodyForm
				p.Name = name
				p.Original = form.Get(name)
				points = append(points, p)
			}
		}
	}

	// JSON body.
	if strings.Contains(ct, "json") {
		if paths, err := JSONPaths(base.Body); err == nil {
			base.BodyType = "json"
			for _, path := range paths {
				name := strings.Join(path, ".")
				if !wanted(name) {
					continue
				}
				p := base
				p.Location = model.LocBodyJSON
				p.Name = name
				p.JSONPath = path
				p.Original = jsonValueAt(base.Body, path)
				points = append(points, p)
			}
		}
	}

	// Cookies.
	if cookies := req.Cookies(); len(cookies) > 0 {
		names := make([]string, 0, len(cookies))
		byName := map[string]string{}
		for _, c := range cookies {
			names = append(names, c.Name)
			byName[c.Name] = c.Value
		}
		sort.Strings(names)
		for _, name := range names {
			if !wanted(name) {
				continue
			}
			p := base
			p.Location = model.LocCookie
			p.Name = name
			p.Original = byName[name]
			points = append(points, p)
		}
	}

	// Explicitly requested headers.
	for _, name := range opts.Headers {
		if req.Header.Get(name) == "" || !wanted(name) {
			continue
		}
		p := base
		p.Location = model.LocHeader
		p.Name = name
		p.Original = req.Header.Get(name)
		points = append(points, p)
	}

	// Level 3: common headers that are frequently interpolated into queries.
	if opts.Level >= 3 && len(opts.Headers) == 0 {
		for _, name := range []string{"User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP"} {
			if req.Header.Get(name) == "" || !wanted(name) {
				continue
			}
			p := base
			p.Location = model.LocHeader
			p.Name = name
			p.Original = req.Header.Get(name)
			points = append(points, p)
		}
	}

	// Path segments.
	if opts.PathSegs && opts.Level >= 2 {
		segs := strings.Split(strings.TrimPrefix(req.URL.Path, "/"), "/")
		for i, seg := range segs {
			if seg == "" || (!wanted(seg) && len(allow) > 0) {
				continue
			}
			if strings.Contains(seg, ".") && i == len(segs)-1 {
				continue // likely a static file name
			}
			p := base
			p.Location = model.LocPath
			p.Name = seg
			p.Original = seg
			p.PathIdx = i
			points = append(points, p)
		}
	}

	return points
}

func reqBody(req *http.Request) []byte {
	if req == nil || req.Body == nil {
		return nil
	}
	if req.GetBody == nil {
		return nil
	}
	rc, err := req.GetBody()
	if err != nil {
		return nil
	}
	defer rc.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(rc); err != nil {
		return nil
	}
	return buf.Bytes()
}

func looksLikeForm(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") || strings.HasPrefix(s, "<") {
		return false
	}
	parts := strings.Split(s, "&")
	if len(parts) == 0 {
		return false
	}
	for _, p := range parts {
		if !strings.Contains(p, "=") {
			return false
		}
	}
	return true
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		it = strings.ToLower(strings.TrimSpace(it))
		if it != "" {
			m[it] = true
		}
	}
	return m
}

func sortedKeys(v url.Values) []string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// JSONPaths returns the dotted paths of all scalar values in a JSON document.
func JSONPaths(body []byte) ([][]string, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}
	var out [][]string
	var walk func(node any, path []string)
	walk = func(node any, path []string) {
		switch v := node.(type) {
		case map[string]any:
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(v[k], append(append([]string(nil), path...), k))
			}
		case []any:
			for i, item := range v {
				walk(item, append(append([]string(nil), path...), strconv.Itoa(i)))
			}
		case string, json.Number, bool, nil:
			if len(path) > 0 {
				out = append(out, path)
			}
		}
	}
	walk(root, nil)
	return out, nil
}

func jsonValueAt(body []byte, path []string) string {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var node any
	if err := dec.Decode(&node); err != nil {
		return ""
	}
	for _, key := range path {
		switch v := node.(type) {
		case map[string]any:
			node = v[key]
		case []any:
			idx, err := strconv.Atoi(key)
			if err != nil || idx < 0 || idx >= len(v) {
				return ""
			}
			node = v[idx]
		default:
			return ""
		}
	}
	switch v := node.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

// ParseHTML extracts links and forms from an HTML document.
func ParseHTML(body []byte, base *url.URL) Page {
	tokens := tokenize(body)
	page := Page{}
	var current *Form
	var selectName string

	for _, tok := range tokens {
		switch tok.kind {
		case tokStart, tokSelf:
			name := strings.ToLower(tok.name)
			switch name {
			case "form":
				action := resolve(base, tok.attr("action"))
				method := strings.ToUpper(tok.attr("method"))
				if method == "" {
					method = http.MethodGet
				}
				page.Forms = append(page.Forms, Form{
					Action:  action,
					Method:  method,
					Enctype: strings.ToLower(tok.attr("enctype")),
				})
				current = &page.Forms[len(page.Forms)-1]
			case "input":
				if current != nil {
					typ := strings.ToLower(tok.attr("type"))
					if typ == "" {
						typ = "text"
					}
					if typ == "submit" || typ == "button" || typ == "reset" || typ == "image" || typ == "file" {
						continue
					}
					current.Inputs = append(current.Inputs, Input{
						Name:  tok.attr("name"),
						Type:  typ,
						Value: tok.attr("value"),
					})
				}
			case "textarea":
				if current != nil {
					current.Inputs = append(current.Inputs, Input{Name: tok.attr("name"), Type: "textarea"})
				}
			case "select":
				if current != nil {
					selectName = tok.attr("name")
				}
			case "option":
				// handled below when the select closes
			case "a", "area":
				if href := tok.attr("href"); href != "" {
					if u := resolve(base, href); u != "" {
						page.Links = append(page.Links, u)
					}
				}
			}
			if name == "select" && current != nil && selectName != "" {
				current.Inputs = append(current.Inputs, Input{Name: selectName, Type: "select"})
				selectName = ""
			}
		case tokEnd:
			switch strings.ToLower(tok.name) {
			case "form":
				current = nil
			}
		}
	}
	return page
}

func resolve(base *url.URL, raw string) string {
	raw = strings.TrimSpace(html.UnescapeString(raw))
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "javascript:") ||
		strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "tel:") ||
		strings.HasPrefix(raw, "data:") {
		return ""
	}
	if base == nil {
		return raw
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u := base.ResolveReference(ref)
	u.Fragment = ""
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	return u.String()
}

type tokenKind int

const (
	tokStart tokenKind = iota
	tokEnd
	tokSelf
)

type token struct {
	kind  tokenKind
	name  string
	attrs map[string]string
}

func (t token) attr(name string) string { return t.attrs[strings.ToLower(name)] }

func tokenize(body []byte) []token {
	var tokens []token
	i := 0
	n := len(body)
	for i < n {
		if body[i] != '<' {
			i++
			continue
		}
		if i+3 < n && string(body[i:i+4]) == "<!--" {
			if end := bytes.Index(body[i+4:], []byte("-->")); end >= 0 {
				i = i + 4 + end + 3
				continue
			}
			break
		}
		if i+1 < n && (body[i+1] == '!' || body[i+1] == '?') {
			if end := bytes.IndexByte(body[i:], '>'); end >= 0 {
				i += end + 1
				continue
			}
			break
		}
		j := i + 1
		isEnd := false
		if j < n && body[j] == '/' {
			isEnd = true
			j++
		}
		for j < n && isSpace(body[j]) {
			j++
		}
		nameStart := j
		for j < n && isNameChar(body[j]) {
			j++
		}
		if j == nameStart {
			i++
			continue
		}
		name := string(body[nameStart:j])
		attrs := map[string]string{}
		selfClose := false
		for j < n {
			for j < n && isSpace(body[j]) {
				j++
			}
			if j >= n {
				break
			}
			if body[j] == '>' {
				j++
				break
			}
			if body[j] == '/' {
				selfClose = true
				j++
				continue
			}
			// attribute name
			aStart := j
			for j < n && !isSpace(body[j]) && body[j] != '=' && body[j] != '>' && body[j] != '/' {
				j++
			}
			attrName := strings.ToLower(string(body[aStart:j]))
			for j < n && isSpace(body[j]) {
				j++
			}
			value := ""
			if j < n && body[j] == '=' {
				j++
				for j < n && isSpace(body[j]) {
					j++
				}
				if j < n && (body[j] == '"' || body[j] == '\'') {
					quote := body[j]
					j++
					vStart := j
					for j < n && body[j] != quote {
						j++
					}
					value = string(body[vStart:j])
					if j < n {
						j++
					}
				} else {
					vStart := j
					for j < n && !isSpace(body[j]) && body[j] != '>' {
						j++
					}
					value = string(body[vStart:j])
				}
			}
			if attrName != "" {
				attrs[attrName] = html.UnescapeString(value)
			}
		}
		i = j

		lower := strings.ToLower(name)
		if !isEnd && (lower == "script" || lower == "style") {
			closeTag := "</" + lower
			if idx := bytes.Index(bytes.ToLower(body[i:]), []byte(closeTag)); idx >= 0 {
				i += idx
				if gt := bytes.IndexByte(body[i:], '>'); gt >= 0 {
					i += gt + 1
				}
			}
			continue
		}

		kind := tokStart
		if isEnd {
			kind = tokEnd
		} else if selfClose || isVoid(lower) {
			kind = tokSelf
		}
		tokens = append(tokens, token{kind: kind, name: name, attrs: attrs})
	}
	return tokens
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

func isNameChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '-' || b == '_' || b == ':' || b == '.'
}

func isVoid(name string) bool {
	switch name {
	case "br", "hr", "img", "input", "meta", "link", "area", "base", "col", "embed", "source", "track", "wbr":
		return true
	}
	return false
}

// FormsToRequests converts a form into an HTTP request for scanning.
func FormsToRequests(form Form) (*http.Request, error) {
	if form.Action == "" {
		return nil, fmt.Errorf("form has no action")
	}
	method := strings.ToUpper(form.Method)
	if method == "" {
		method = http.MethodGet
	}
	values := url.Values{}
	for _, in := range form.Inputs {
		if in.Name == "" {
			continue
		}
		values.Set(in.Name, in.Value)
	}
	if method == http.MethodGet {
		u, err := url.Parse(form.Action)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		for k, v := range values {
			q[k] = v
		}
		u.RawQuery = q.Encode()
		return http.NewRequest(http.MethodGet, u.String(), nil)
	}
	body := values.Encode()
	req, err := http.NewRequest(method, form.Action, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	if form.Enctype == "multipart/form-data" {
		return nil, fmt.Errorf("multipart forms are not supported")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}
