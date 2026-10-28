// Package ui implements terminal presentation: colors, tables, progress and
// prompts. It degrades gracefully when stdout is not a TTY.
package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ANSI color codes.
const (
	reset   = "\x1b[0m"
	bold    = "\x1b[1m"
	dim     = "\x1b[2m"
	red     = "\x1b[31m"
	green   = "\x1b[32m"
	yellow  = "\x1b[33m"
	blue    = "\x1b[34m"
	magenta = "\x1b[35m"
	cyan    = "\x1b[36m"
	white   = "\x1b[37m"
)

// UI writes formatted output to a writer.
type UI struct {
	out     io.Writer
	err     io.Writer
	color   bool
	quiet   bool
	verbose bool
	mu      sync.Mutex
}

// Options controls UI construction.
type Options struct {
	Out     io.Writer
	Err     io.Writer
	Color   bool
	Quiet   bool
	Verbose bool
}

// New builds a UI.
func New(o Options) *UI {
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.Err == nil {
		o.Err = os.Stderr
	}
	return &UI{out: o.Out, err: o.Err, color: o.Color, quiet: o.Quiet, verbose: o.Verbose}
}

// Configure updates presentation settings after configuration is loaded.
func (u *UI) Configure(color, quiet, verbose bool) {
	u.mu.Lock()
	u.color = color
	u.quiet = quiet
	u.verbose = verbose
	u.mu.Unlock()
}

// WithQuiet returns a view of the UI with a different quiet setting.
func (u *UI) WithQuiet(quiet bool) *UI {
	return &UI{out: u.out, err: u.err, color: u.color, quiet: quiet, verbose: u.verbose}
}

// ColorEnabled reports whether ANSI styling is active.
func (u *UI) ColorEnabled() bool { return u.color }

// Quiet reports whether normal output is suppressed.
func (u *UI) Quiet() bool { return u.quiet }

// Verbose reports whether debug output is enabled.
func (u *UI) Verbose() bool { return u.verbose }

func (u *UI) paint(code, s string) string {
	if !u.color {
		return s
	}
	return code + s + reset
}

// Bold renders bold text.
func (u *UI) Bold(s string) string { return u.paint(bold, s) }

// Dim renders dim text.
func (u *UI) Dim(s string) string { return u.paint(dim, s) }

// Red renders red text.
func (u *UI) Red(s string) string { return u.paint(red, s) }

// Green renders green text.
func (u *UI) Green(s string) string { return u.paint(green, s) }

// Yellow renders yellow text.
func (u *UI) Yellow(s string) string { return u.paint(yellow, s) }

// Blue renders blue text.
func (u *UI) Blue(s string) string { return u.paint(blue, s) }

// Cyan renders cyan text.
func (u *UI) Cyan(s string) string { return u.paint(cyan, s) }

// Magenta renders magenta text.
func (u *UI) Magenta(s string) string { return u.paint(magenta, s) }

// Write prints a line to stdout.
func (u *UI) Write(format string, args ...any) {
	u.mu.Lock()
	defer u.mu.Unlock()
	fmt.Fprintf(u.out, format+"\n", args...)
}

// Raw writes without a trailing newline.
func (u *UI) Raw(format string, args ...any) {
	u.mu.Lock()
	defer u.mu.Unlock()
	fmt.Fprintf(u.out, format, args...)
}

// Printf prints when not quiet.
func (u *UI) Printf(format string, args ...any) {
	if u.quiet {
		return
	}
	u.Write(format, args...)
}

// Debug prints only in verbose mode.
func (u *UI) Debug(format string, args ...any) {
	if !u.verbose {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	fmt.Fprintf(u.err, u.Dim("  · ")+format+"\n", args...)
}

// Info prints an informational line.
func (u *UI) Info(format string, args ...any) {
	u.Printf("%s %s", u.Cyan("›"), fmt.Sprintf(format, args...))
}

// Success prints a success line.
func (u *UI) Success(format string, args ...any) {
	u.Printf("%s %s", u.Green("✔"), fmt.Sprintf(format, args...))
}

// Warn prints a warning line to stderr.
func (u *UI) Warn(format string, args ...any) {
	u.mu.Lock()
	defer u.mu.Unlock()
	fmt.Fprintf(u.err, "%s %s\n", u.Yellow("!"), fmt.Sprintf(format, args...))
}

// Error prints an error line to stderr.
func (u *UI) Error(format string, args ...any) {
	u.mu.Lock()
	defer u.mu.Unlock()
	fmt.Fprintf(u.err, "%s %s\n", u.Red("✘"), fmt.Sprintf(format, args...))
}

// Banner prints the application header.
func (u *UI) Banner(name, tagline, version string) {
	if u.quiet {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	logo := []string{
		"  ███████╗ ██████╗ ██╗     ██╗",
		"  ██╔════╝██╔═══██╗██║     ██║",
		"  ███████╗██║   ██║██║     ██║",
		"  ╚════██║██║▄▄ ██║██║     ██║",
		"  ███████║╚██████╔╝███████╗██║",
		"  ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝",
	}
	for _, line := range logo {
		fmt.Fprintln(u.out, u.paint(cyan, line))
	}
	fmt.Fprintf(u.out, "  %s %s\n", u.Bold(name), u.Dim("v"+version))
	fmt.Fprintf(u.out, "  %s\n\n", u.Dim(tagline))
}

// Section prints a titled divider.
func (u *UI) Section(title string) {
	if u.quiet {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	line := strings.Repeat("─", 62)
	fmt.Fprintf(u.out, "\n%s\n", u.paint(dim, line))
	fmt.Fprintf(u.out, "%s %s\n", u.Bold(u.Cyan("◆")), u.Bold(title))
	fmt.Fprintf(u.out, "%s\n", u.paint(dim, line))
}

// KV prints an aligned key/value pair.
func (u *UI) KV(key, value string) {
	if u.quiet {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	fmt.Fprintf(u.out, "  %s %s\n", u.paint(dim, fmt.Sprintf("%-12s", key)), value)
}

// Status renders a colored status badge.
func (u *UI) Status(kind string) string {
	switch strings.ToLower(kind) {
	case "critical":
		return u.paint(bold+red, " CRITICAL ")
	case "high":
		return u.paint(bold+red, " HIGH ")
	case "medium":
		return u.paint(bold+yellow, " MEDIUM ")
	case "low":
		return u.paint(bold+blue, " LOW ")
	case "info":
		return u.paint(bold+cyan, " INFO ")
	case "ok", "safe":
		return u.paint(bold+green, " SAFE ")
	}
	return strings.ToUpper(kind)
}

// Table renders a simple aligned table. Headers are uppercased and dimmed.
func (u *UI) Table(headers []string, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = displayWidth(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) {
				if w := displayWidth(cell); w > widths[i] {
					widths[i] = w
				}
			}
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	var b strings.Builder
	for i, h := range headers {
		b.WriteString(u.paint(dim, pad(strings.ToUpper(h), widths[i])))
		if i < len(headers)-1 {
			b.WriteString("  ")
		}
	}
	fmt.Fprintln(u.out, b.String())
	for _, row := range rows {
		var rb strings.Builder
		for i := range headers {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			rb.WriteString(pad(cell, widths[i]))
			if i < len(headers)-1 {
				rb.WriteString("  ")
			}
		}
		fmt.Fprintln(u.out, strings.TrimRight(rb.String(), " "))
	}
}

// Progress renders a transient progress line on stderr. Safe for concurrent use.
type Progress struct {
	ui      *UI
	label   string
	total   int
	current int
	start   time.Time
	mu      sync.Mutex
	enabled bool
}

// NewProgress creates a progress indicator. When the UI is quiet or stderr is
// not a terminal the indicator only emits start/finish lines.
func (u *UI) NewProgress(label string, total int) *Progress {
	return &Progress{ui: u, label: label, total: total, start: time.Now(), enabled: !u.quiet}
}

// Inc advances the progress counter.
func (p *Progress) Inc() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.current++
	cur := p.current
	p.mu.Unlock()
	p.render(cur)
}

// Set positions the progress counter.
func (p *Progress) Set(current int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.current = current
	p.mu.Unlock()
	p.render(current)
}

func (p *Progress) render(cur int) {
	if !p.enabled {
		return
	}
	pct := 0.0
	if p.total > 0 {
		pct = float64(cur) / float64(p.total) * 100
	}
	width := 24
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	p.ui.mu.Lock()
	fmt.Fprintf(p.ui.err, "\r  %s %s %3.0f%% %s", p.ui.Cyan("▸"), p.label, pct, p.ui.paint(dim, bar))
	p.ui.mu.Unlock()
}

// Done clears the progress line.
func (p *Progress) Done() {
	if p == nil || !p.enabled {
		return
	}
	p.ui.mu.Lock()
	fmt.Fprint(p.ui.err, "\r"+strings.Repeat(" ", 80)+"\r")
	p.ui.mu.Unlock()
}

// Confirm asks a yes/no question. Returns false when not running in a TTY.
func (u *UI) Confirm(question string) bool {
	fmt.Fprintf(u.err, "%s %s [y/N] ", u.Yellow("?"), question)
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}

// Prompt asks for free-form input with a default value.
func (u *UI) Prompt(question, def string) string {
	if def != "" {
		fmt.Fprintf(u.err, "%s %s %s: ", u.Cyan("?"), question, u.Dim("["+def+"]"))
	} else {
		fmt.Fprintf(u.err, "%s %s: ", u.Cyan("?"), question)
	}
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return def
	}
	answer = strings.TrimSpace(answer)
	if answer == "" {
		return def
	}
	return answer
}

func pad(s string, width int) string {
	w := displayWidth(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

// displayWidth approximates terminal width, ignoring ANSI escapes and counting
// wide runes as two cells.
func displayWidth(s string) int {
	width := 0
	inEscape := false
	for _, r := range s {
		if r == '\x1b' {
			inEscape = true
			continue
		}
		if inEscape {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
			continue
		}
		if r == utf8.RuneError {
			continue
		}
		if isWide(r) {
			width += 2
		} else {
			width++
		}
	}
	return width
}

func isWide(r rune) bool {
	return (r >= 0x1100 && r <= 0x115F) ||
		(r >= 0x2E80 && r <= 0xA4CF) ||
		(r >= 0xAC00 && r <= 0xD7A3) ||
		(r >= 0xF900 && r <= 0xFAFF) ||
		(r >= 0xFE30 && r <= 0xFE6F) ||
		(r >= 0xFF00 && r <= 0xFF60) ||
		(r >= 0xFFE0 && r <= 0xFFE6)
}

// IsTTY reports whether f is attached to a terminal (best effort).
func IsTTY(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
