package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/akshaytheflash/antisqli/internal/config"
	"github.com/akshaytheflash/antisqli/internal/payload"
	"github.com/akshaytheflash/antisqli/internal/ui"
	"github.com/akshaytheflash/antisqli/internal/version"
)

func runPayloads(u *ui.UI, args []string) int {
	u.Banner(version.Name, version.Tagline, version.String())
	u.Section("Payload library")
	u.KV("Techniques", "error · boolean · time · union")
	u.KV("Backends", "MySQL/MariaDB · PostgreSQL · MSSQL · Oracle · SQLite")
	u.KV("Boolean pairs", fmt.Sprintf("%d / %d / %d  (level 1/2/3)",
		len(payload.BooleanPairs(1, 1)),
		len(payload.BooleanPairs(2, 1)),
		len(payload.BooleanPairs(3, 2))))
	u.KV("Time payloads", fmt.Sprintf("%d at level 1 (per backend set)",
		len(payload.TimePayloads("", 5, 1))))
	u.KV("Error payloads", fmt.Sprintf("%d (all backends)",
		len(payload.ErrorPayloads(""))))
	u.KV("Union", "ORDER BY column counting (1-12) + version read")
	u.KV("Tampers", fmt.Sprintf("%d (run 'sqli tampers')", len(payload.TamperNames())))

	u.Section("Sample payloads")
	samples := [][2]string{
		{"error", "' AND extractvalue(1,concat(0x7e,version()))-- -"},
		{"boolean", "' AND '1'='1'-- -   /   ' AND '1'='2'-- -"},
		{"time", "' AND SLEEP(5)-- -"},
		{"union", "' UNION SELECT NULL,NULL-- -"},
	}
	for _, s := range samples {
		u.Printf("  %s %s", u.Cyan(fmt.Sprintf("%-8s", s[0])), u.Dim(s[1]))
	}
	u.Printf("\n  %s\n", u.Dim("All payloads are read-only: no data modification or DDL."))
	return 0
}

func runTampers(u *ui.UI, args []string) int {
	u.Banner(version.Name, version.Tagline, version.String())
	u.Section("Tamper scripts")
	rows := make([][]string, 0)
	for _, d := range payload.TamperDocs() {
		rows = append(rows, []string{d.Name, d.Description})
	}
	u.Table([]string{"Name", "Effect"}, rows)
	u.Printf("\n  %s\n", u.Dim("Usage: sqli scan ... --tamper space2comment,randomcase"))
	return 0
}

func runConfig(u *ui.UI, args []string) int {
	sub := "show"
	if len(args) > 0 {
		sub = args[0]
		args = args[1:]
	}
	path, err := config.Path()
	if err != nil {
		u.Error("%v", err)
		return 2
	}
	if env := os.Getenv("SQLI_CONFIG"); env != "" {
		path = env
	}

	switch sub {
	case "path":
		fmt.Println(path)
		return 0

	case "init":
		fs := flag.NewFlagSet("config init", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		force := fs.Bool("force", false, "overwrite an existing config")
		if err := fs.Parse(args); err != nil {
			return 2
		}
		if _, err := os.Stat(path); err == nil && !*force {
			u.Warn("config already exists at %s (use --force to overwrite)", path)
			return 0
		}
		if err := config.Save(path, config.Default()); err != nil {
			u.Error("%v", err)
			return 2
		}
		u.Success("Wrote default configuration to %s", path)
		return 0

	case "show":
		cfg, loadedPath, err := config.Load(path)
		if err != nil {
			u.Error("%v", err)
			return 2
		}
		u.Section("Configuration")
		u.KV("File", loadedPath)
		u.KV("Platform", config.Platform())
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			u.Error("%v", err)
			return 2
		}
		u.Printf("\n%s\n", string(data))
		return 0

	default:
		u.Error("unknown config command %q (use show, init or path)", sub)
		return 2
	}
}
