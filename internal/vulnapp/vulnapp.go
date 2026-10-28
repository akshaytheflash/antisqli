// Package vulnapp provides an intentionally vulnerable HTTP application used
// to test and demonstrate sqli. It must never be exposed to a network.
package vulnapp

import (
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Handler returns the demo application.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", index)
	mux.HandleFunc("/item", item)
	mux.HandleFunc("/search", search)
	mux.HandleFunc("/api/user", apiUser)
	mux.HandleFunc("/form", form)
	mux.HandleFunc("/clean", clean)
	return mux
}

var sleepRe = regexp.MustCompile(`(?i)(?:sleep|pg_sleep)\((\d{1,2})\)`)
var waitforRe = regexp.MustCompile(`(?i)waitfor delay '0:0:(\d{1,2})'`)
var orderByRe = regexp.MustCompile(`(?i)order by (\d{1,2})`)

func index(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, page("Demo shop", `
		<h1>Demo shop</h1>
		<ul>
			<li><a href="/item?id=1">Product 1</a></li>
			<li><a href="/search?q=apple">Search</a></li>
			<li><a href="/form">Login form</a></li>
			<li><a href="/api/user?id=1">User API</a></li>
			<li><a href="/clean?id=1">Static page</a></li>
		</ul>`))
}

func item(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	lower := strings.ToLower(id)
	norm := normalize(lower)

	if d := delayFrom(lower); d > 0 {
		time.Sleep(time.Duration(d) * time.Second)
		writeHTML(w, page("Product "+html.EscapeString(id), productBody(id)))
		return
	}

	if strings.Contains(lower, "union select") {
		cols := strings.Count(id, ",") + 1
		switch {
		case strings.Contains(id, "sqliMark7x"):
			writeHTML(w, page("Search results", `<div class="result">sqliMark7x</div>`))
		case strings.Contains(lower, "version()"):
			writeHTML(w, page("Search results", `<div class="result">8.0.32</div>`))
		case cols == 2:
			writeHTML(w, page("Search results", `<div class="result">NULL</div>`))
		default:
			writeHTML(w, mysqlError("The used SELECT statements have a different number of columns"))
		}
		return
	}

	if m := orderByRe.FindStringSubmatch(lower); m != nil {
		n, _ := strconv.Atoi(m[1])
		if n > 2 {
			writeHTML(w, mysqlError("Unknown column '"+m[1]+"' in 'order clause'"))
			return
		}
		writeHTML(w, page("Product "+html.EscapeString(id), productBody(id)))
		return
	}

	if strings.Contains(norm, "1=2") {
		writeHTML(w, page("Product", `<div class="empty">No product found.</div>`))
		return
	}
	if strings.Contains(norm, "1=1") {
		writeHTML(w, page("Product 1", productBody("1")))
		return
	}

	if strings.Contains(lower, "extractvalue") || strings.Contains(lower, "updatexml") {
		writeHTML(w, mysqlError("XPATH syntax error: '~8.0.32'"))
		return
	}
	if strings.ContainsAny(id, "'\"") {
		writeHTML(w, mysqlError("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"))
		return
	}

	writeHTML(w, page("Product "+html.EscapeString(id), productBody(id)))
}

func search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	lower := strings.ToLower(q)
	norm := normalize(lower)

	if d := delayFrom(lower); d > 0 {
		time.Sleep(time.Duration(d) * time.Second)
	}

	if strings.Contains(norm, "1=2") {
		writeHTML(w, page("Search", `<p>No results for <b>`+html.EscapeString(q)+`</b>.</p>`))
		return
	}
	if strings.Contains(norm, "1=1") {
		writeHTML(w, page("Search", searchResults("apple")))
		return
	}
	writeHTML(w, page("Search", searchResults(q)))
}

func apiUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	lower := strings.ToLower(id)
	norm := normalize(lower)
	w.Header().Set("Content-Type", "application/json")

	if d := delayFrom(lower); d > 0 {
		time.Sleep(time.Duration(d) * time.Second)
	}
	if strings.Contains(lower, "convert(int,@@version)") {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"Conversion failed when converting the varchar value 'Microsoft SQL Server 2019 (RTM)' to data type int."}`)
		return
	}
	if strings.ContainsAny(id, "'\"") {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"Incorrect syntax near \"'\". Unclosed quotation mark after the character string."}`)
		return
	}
	if strings.Contains(norm, "1=2") {
		fmt.Fprint(w, `{"users":[]}`)
		return
	}
	fmt.Fprintf(w, `{"users":[{"id":%q,"name":"alice","email":"alice@example.test","role":"admin","active":true}]}`, id)
}

func form(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		user := r.FormValue("user")
		pass := r.FormValue("pass")
		_ = pass
		if strings.ContainsAny(user, "'\"") {
			writeHTML(w, mysqlError("You have an error in your SQL syntax near login"))
			return
		}
		norm := normalize(strings.ToLower(user))
		if strings.Contains(norm, "1=2") {
			writeHTML(w, page("Login", `<div class="empty">Invalid credentials.</div>`))
			return
		}
		if strings.Contains(norm, "1=1") {
			writeHTML(w, page("Login", `<div class="ok">Welcome back, admin.</div>`))
			return
		}
		writeHTML(w, page("Login", `<div class="ok">Welcome back, `+html.EscapeString(user)+`.</div>`))
		return
	}
	writeHTML(w, page("Login", `
		<form method="post" action="/form">
			<input name="user" value="">
			<input name="pass" type="password" value="">
			<button type="submit">Sign in</button>
		</form>`))
}

func clean(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, page("Static", `<p>This page does not use the <code>id</code> parameter in SQL.</p>`))
}

func normalize(s string) string {
	return strings.NewReplacer(" ", "", "'", "", "\"", "", "\t", "").Replace(s)
}

func delayFrom(lower string) int {
	if m := sleepRe.FindStringSubmatch(lower); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	if m := waitforRe.FindStringSubmatch(lower); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

func mysqlError(msg string) string {
	return page("Database error", `
		<h1>Database error</h1>
		<div class="error">Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/index.php on line 12</div>
		<div class="error">`+html.EscapeString(msg)+`</div>`)
}

func productBody(id string) string {
	var b strings.Builder
	b.WriteString(`<h1>Product ` + html.EscapeString(id) + `</h1>`)
	b.WriteString(`<p>Premium widget with free shipping.</p><table>`)
	for i := 1; i <= 30; i++ {
		fmt.Fprintf(&b, `<tr><td>SKU-%03d</td><td>Variant %d</td><td>$%d.99</td></tr>`, i, i, 10+i)
	}
	b.WriteString(`</table>`)
	return b.String()
}

func searchResults(q string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<p>Results for <b>%s</b></p><ul>`, html.EscapeString(q))
	for i := 1; i <= 20; i++ {
		fmt.Fprintf(&b, `<li><a href="/item?id=%d">Result %d</a></li>`, i, i)
	}
	b.WriteString(`</ul>`)
	return b.String()
}

func page(title, body string) string {
	return `<!doctype html><html><head><title>` + title + `</title>
	<style>body{font-family:sans-serif}table{border-collapse:collapse}td{padding:4px}</style>
	</head><body>
	<header><a href="/">Demo shop</a> | <a href="/search?q=apple">Search</a></header>
	<main>` + body + `</main>
	<footer>Demo application for sqli tests</footer>
	</body></html>`
}

func writeHTML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, body)
}
