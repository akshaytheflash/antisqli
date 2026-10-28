package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SQLI_HOME", dir)
	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.Concurrency = 3
	cfg.Level = 2
	cfg.AllowedHosts = []string{"example.test"}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, loadedPath, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loadedPath != path {
		t.Fatalf("path = %s, want %s", loadedPath, path)
	}
	if loaded.Concurrency != 3 || loaded.Level != 2 {
		t.Fatalf("values not persisted: %+v", loaded)
	}
	if len(loaded.AllowedHosts) != 1 || loaded.AllowedHosts[0] != "example.test" {
		t.Fatalf("allowed hosts = %v", loaded.AllowedHosts)
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SQLI_HOME", dir)
	cfg, _, err := Load(filepath.Join(dir, "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout != Default().Timeout || cfg.Samples != Default().Samples {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestNormalizeFillsZeroValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "partial.json")
	if err := os.WriteFile(path, []byte(`{"concurrency":0,"level":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Concurrency != Default().Concurrency || cfg.Level != Default().Level {
		t.Fatalf("zero values not normalized: %+v", cfg)
	}
}

func TestValidate(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	cfg.Concurrency = 1000
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected concurrency error")
	}
	cfg = Default()
	cfg.Level = 9
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected level error")
	}
}
