// Package config handles persistent user configuration stored as JSON.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Config holds user-tunable defaults. Zero values are replaced with sane
// defaults by Default().
type Config struct {
	Timeout         int               `json:"timeout_seconds"`
	Concurrency     int               `json:"concurrency"`
	DelayMS         int               `json:"delay_ms"`
	Rate            float64           `json:"rate_per_second"`
	Retries         int               `json:"retries"`
	Samples         int               `json:"time_samples"`
	TimeDelay       int               `json:"time_delay_seconds"`
	Level           int               `json:"level"`
	Risk            int               `json:"risk"`
	UserAgent       string            `json:"user_agent"`
	Proxy           string            `json:"proxy"`
	Insecure        bool              `json:"insecure"`
	NoColor         bool              `json:"no_color"`
	FollowRedirects bool              `json:"follow_redirects"`
	MaxRequests     int64             `json:"max_requests"`
	AllowedHosts    []string          `json:"allowed_hosts"`
	Headers         map[string]string `json:"headers"`
	Tampers         []string          `json:"tampers"`
	Techniques      []string          `json:"techniques"`
	Output          string            `json:"output"`
	Format          string            `json:"format"`
}

// Default returns a configuration with conservative, fast defaults.
func Default() Config {
	return Config{
		Timeout:         15,
		Concurrency:     8,
		DelayMS:         0,
		Rate:            0,
		Retries:         2,
		Samples:         3,
		TimeDelay:       5,
		Level:           1,
		Risk:            1,
		UserAgent:       DefaultUserAgent,
		FollowRedirects: true,
		MaxRequests:     5000,
		Headers:         map[string]string{},
		Tampers:         []string{},
		Techniques:      []string{"error", "boolean", "time"},
	}
}

// DefaultUserAgent is used unless overridden.
const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// Dir returns the configuration directory, creating it if needed.
func Dir() (string, error) {
	if env := os.Getenv("SQLI_HOME"); env != "" {
		if err := os.MkdirAll(env, 0o755); err != nil {
			return "", err
		}
		return env, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	dir := filepath.Join(base, "sqli")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// Path returns the default configuration file path.
func Path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// Load reads configuration from path. A missing file yields defaults.
func Load(path string) (Config, string, error) {
	cfg := Default()
	if path == "" {
		p, err := Path()
		if err != nil {
			return cfg, "", err
		}
		path = p
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, path, nil
		}
		return cfg, path, err
	}
	// Start from defaults so new fields keep working after upgrades.
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Default(), path, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.normalize()
	return cfg, path, nil
}

func (c *Config) normalize() {
	def := Default()
	if c.Timeout <= 0 {
		c.Timeout = def.Timeout
	}
	if c.Concurrency <= 0 {
		c.Concurrency = def.Concurrency
	}
	if c.Samples <= 0 {
		c.Samples = def.Samples
	}
	if c.TimeDelay <= 0 {
		c.TimeDelay = def.TimeDelay
	}
	if c.Level <= 0 {
		c.Level = def.Level
	}
	if c.Risk <= 0 {
		c.Risk = def.Risk
	}
	if c.MaxRequests <= 0 {
		c.MaxRequests = def.MaxRequests
	}
	if c.UserAgent == "" {
		c.UserAgent = def.UserAgent
	}
	if c.Headers == nil {
		c.Headers = map[string]string{}
	}
}

// Save writes the configuration to path, creating parent directories.
func Save(path string, cfg Config) error {
	if path == "" {
		p, err := Path()
		if err != nil {
			return err
		}
		path = p
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

// Validate checks that values are within supported ranges.
func (c Config) Validate() error {
	var problems []string
	if c.Concurrency < 1 || c.Concurrency > 128 {
		problems = append(problems, "concurrency must be between 1 and 128")
	}
	if c.Level < 1 || c.Level > 3 {
		problems = append(problems, "level must be 1, 2 or 3")
	}
	if c.Risk < 1 || c.Risk > 3 {
		problems = append(problems, "risk must be 1, 2 or 3")
	}
	if c.Timeout < 1 || c.Timeout > 300 {
		problems = append(problems, "timeout must be between 1 and 300 seconds")
	}
	if c.TimeDelay < 1 || c.TimeDelay > 30 {
		problems = append(problems, "time delay must be between 1 and 30 seconds")
	}
	if c.Rate < 0 {
		problems = append(problems, "rate cannot be negative")
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// Describe renders a short summary of the effective configuration.
func (c Config) Describe() string {
	return fmt.Sprintf("timeout=%ds concurrency=%d level=%d risk=%d samples=%d",
		c.Timeout, c.Concurrency, c.Level, c.Risk, c.Samples)
}

// Platform returns a human readable platform string.
func Platform() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}
