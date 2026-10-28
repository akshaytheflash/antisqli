// Package fingerprint identifies database backends from error messages and
// extracts version information.
package fingerprint

import (
	"html"
	"regexp"
	"sort"
	"strings"
)

// Signature maps a response pattern to a DBMS.
type Signature struct {
	DBMS     string
	Pattern  *regexp.Regexp
	Weight   int
	Evidence string
}

// Match is a single signature hit.
type Match struct {
	DBMS     string
	Evidence string
	Weight   int
}

var signatures = []Signature{
	// MySQL / MariaDB
	{"mysql", regexp.MustCompile(`(?i)you have an error in your sql syntax`), 10, "MySQL syntax error"},
	{"mysql", regexp.MustCompile(`(?i)check the manual that corresponds to your (mysql|mariadb)`), 10, "MySQL manual reference"},
	{"mysql", regexp.MustCompile(`(?i)mysql_fetch_(array|assoc|row)`), 8, "mysql_fetch_*"},
	{"mysql", regexp.MustCompile(`(?i)mysqli?_`), 6, "mysqli API"},
	{"mysql", regexp.MustCompile(`(?i)supplied argument is not a valid (mysql|mariadb)`), 9, "MySQL resource error"},
	{"mysql", regexp.MustCompile(`(?i)mariadb server version`), 9, "MariaDB banner"},

	// PostgreSQL
	{"postgres", regexp.MustCompile(`(?i)postgresql.*(error|syntax)`), 10, "PostgreSQL error"},
	{"postgres", regexp.MustCompile(`(?i)pg_query\(|pg_exec\(|psql:`), 8, "libpq call"},
	{"postgres", regexp.MustCompile(`(?i)syntax error at or near`), 8, "PostgreSQL syntax error"},
	{"postgres", regexp.MustCompile(`(?i)unterminated quoted string at or near`), 9, "PostgreSQL quote error"},
	{"postgres", regexp.MustCompile(`(?i)org\.postgresql\.util\.PSQLException`), 9, "PSQLException"},

	// Microsoft SQL Server
	{"mssql", regexp.MustCompile(`(?i)microsoft (odbc )?sql server`), 10, "MSSQL banner"},
	{"mssql", regexp.MustCompile(`(?i)unclosed quotation mark after the character string`), 10, "MSSQL quote error"},
	{"mssql", regexp.MustCompile(`(?i)incorrect syntax near`), 8, "MSSQL syntax error"},
	{"mssql", regexp.MustCompile(`(?i)system\.data\.sqlclient`), 9, "SqlClient exception"},
	{"mssql", regexp.MustCompile(`(?i)sqlserver\.jdbc`), 8, "MSSQL JDBC"},

	// Oracle
	{"oracle", regexp.MustCompile(`(?i)\bORA-\d{4,5}\b`), 10, "ORA error code"},
	{"oracle", regexp.MustCompile(`(?i)oracle error|oracle.*driver`), 8, "Oracle driver"},
	{"oracle", regexp.MustCompile(`(?i)quoted string not properly terminated`), 8, "Oracle quote error"},
	{"oracle", regexp.MustCompile(`(?i)oracle\.jdbc`), 8, "Oracle JDBC"},

	// SQLite
	{"sqlite", regexp.MustCompile(`(?i)sqlite3?_`), 8, "SQLite API"},
	{"sqlite", regexp.MustCompile(`(?i)sqlite error|sqliteexception`), 10, "SQLite error"},
	{"sqlite", regexp.MustCompile(`(?i)unrecognized token:`), 8, "SQLite tokenizer"},
	{"sqlite", regexp.MustCompile(`(?i)no such (table|column):`), 7, "SQLite schema error"},

	// Generic fallbacks
	{"unknown", regexp.MustCompile(`(?i)SQLSTATE\[\w+\]`), 4, "SQLSTATE code"},
	{"unknown", regexp.MustCompile(`(?i)\bSQL syntax\b`), 4, "generic SQL syntax error"},
	{"unknown", regexp.MustCompile(`(?i)\bdatabase error\b`), 3, "generic database error"},
	{"unknown", regexp.MustCompile(`(?i)\bsyntax error\b.*\bSQL\b`), 3, "generic SQL error"},
	{"unknown", regexp.MustCompile(`(?i)java\.sql\.SQLException`), 4, "JDBC exception"},
}

// Analyze returns all signature matches in body, ordered by weight.
func Analyze(body string) []Match {
	if body == "" {
		return nil
	}
	// Cap analysis to keep regex work bounded on huge pages.
	if len(body) > 1<<20 {
		body = body[:1<<20]
	}
	var matches []Match
	seen := map[string]bool{}
	for _, sig := range signatures {
		if !sig.Pattern.MatchString(body) {
			continue
		}
		key := sig.DBMS + "|" + sig.Evidence
		if seen[key] {
			continue
		}
		seen[key] = true
		matches = append(matches, Match{DBMS: sig.DBMS, Evidence: sig.Evidence, Weight: sig.Weight})
	}
	sort.SliceStable(matches, func(i, j int) bool { return matches[i].Weight > matches[j].Weight })
	return matches
}

// Best returns the most likely DBMS and its evidence.
func Best(body string) (string, string) {
	matches := Analyze(body)
	if len(matches) == 0 {
		return "", ""
	}
	return matches[0].DBMS, matches[0].Evidence
}

var (
	mysqlVersion    = regexp.MustCompile(`(?i)(\d+\.\d+\.\d+(?:-[\w.]+)?)`)
	postgresVersion = regexp.MustCompile(`(?i)PostgreSQL\s+(\d+(?:\.\d+){1,2})`)
	mssqlVersion    = regexp.MustCompile(`(?i)(?:Microsoft SQL Server|SQL Server)\s+(\d{4})`)
	oracleVersion   = regexp.MustCompile(`(?i)Oracle Database\s+(\d+[a-z]?\s*Release\s*[\d.]+)`)
	sqliteVersion   = regexp.MustCompile(`(?i)(\d+\.\d+\.\d+)`)
	tildeValue      = regexp.MustCompile(`~([^\s<>"'&]{1,80})`)
)

// VersionFrom extracts a version string from an error response for dbms.
func VersionFrom(body, dbms string) string {
	if body == "" {
		return ""
	}
	if len(body) > 1<<20 {
		body = body[:1<<20]
	}
	body = html.UnescapeString(body)
	switch strings.ToLower(dbms) {
	case "mysql":
		if m := tildeValue.FindStringSubmatch(body); m != nil {
			return trimVersion(m[1])
		}
		if m := mysqlVersion.FindStringSubmatch(body); m != nil {
			return trimVersion(m[1])
		}
	case "postgres":
		if m := postgresVersion.FindStringSubmatch(body); m != nil {
			return trimVersion(m[1])
		}
	case "mssql":
		if m := mssqlVersion.FindStringSubmatch(body); m != nil {
			return trimVersion(m[1])
		}
	case "oracle":
		if m := oracleVersion.FindStringSubmatch(body); m != nil {
			return trimVersion(m[1])
		}
	case "sqlite":
		if m := sqliteVersion.FindStringSubmatch(body); m != nil {
			return trimVersion(m[1])
		}
	}
	if m := postgresVersion.FindStringSubmatch(body); m != nil {
		return trimVersion(m[1])
	}
	if m := mssqlVersion.FindStringSubmatch(body); m != nil {
		return trimVersion(m[1])
	}
	return ""
}

func trimVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimRight(v, ".,;:)]}'\"&")
	return strings.TrimSpace(v)
}

// NormalizeDBMS maps common aliases to canonical names.
func NormalizeDBMS(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "mysql", "mariadb":
		return "mysql"
	case "postgres", "postgresql", "pgsql":
		return "postgres"
	case "mssql", "sqlserver", "sql server", "microsoft sql server":
		return "mssql"
	case "oracle", "oracledb":
		return "oracle"
	case "sqlite", "sqlite3":
		return "sqlite"
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// DisplayName returns a human friendly DBMS name.
func DisplayName(dbms string) string {
	switch NormalizeDBMS(dbms) {
	case "mysql":
		return "MySQL / MariaDB"
	case "postgres":
		return "PostgreSQL"
	case "mssql":
		return "Microsoft SQL Server"
	case "oracle":
		return "Oracle Database"
	case "sqlite":
		return "SQLite"
	case "":
		return "Unknown"
	}
	return dbms
}
