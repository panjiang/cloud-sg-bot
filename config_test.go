package main

import (
	"testing"
	"time"
)

func TestConfigComplete(t *testing.T) {
	t.Run("valid multiple jobs and targets", func(t *testing.T) {
		cfg := validConfig()
		if err := cfg.Complete(); err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
		if cfg.CheckInterval != defaultCheckInterval {
			t.Fatalf("CheckInterval = %v, want %v", cfg.CheckInterval, defaultCheckInterval)
		}
		if cfg.Jobs[0].IPSource.Timeout != defaultIPSourceTimeout {
			t.Fatalf("IPSource.Timeout = %v, want %v", cfg.Jobs[0].IPSource.Timeout, defaultIPSourceTimeout)
		}
		if cfg.RemarkPrefix != defaultRemarkPrefix {
			t.Fatalf("RemarkPrefix = %q, want %q", cfg.RemarkPrefix, defaultRemarkPrefix)
		}
	})

	t.Run("custom remark prefix", func(t *testing.T) {
		cfg := validConfig()
		cfg.RemarkPrefix = " bot:server238 "
		if err := cfg.Complete(); err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
		if cfg.RemarkPrefix != "bot:server238" {
			t.Fatalf("RemarkPrefix = %q, want %q", cfg.RemarkPrefix, "bot:server238")
		}
	})

	t.Run("minimum check interval", func(t *testing.T) {
		cfg := validConfig()
		cfg.CheckIntervalStr = "10s"
		if err := cfg.Complete(); err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
		if cfg.CheckInterval != 10*time.Second {
			t.Fatalf("CheckInterval = %v, want 10s", cfg.CheckInterval)
		}
	})

	t.Run("check interval below minimum", func(t *testing.T) {
		cfg := validConfig()
		cfg.CheckIntervalStr = "9s"
		if err := cfg.Complete(); err == nil {
			t.Fatal("Complete() expected error")
		}
	})

	for _, tt := range []struct {
		name string
		edit func(*Config)
	}{
		{name: "missing secret id", edit: func(c *Config) { c.ProviderConfigs.TencentCloud.SecretID = "" }},
		{name: "missing secret key", edit: func(c *Config) { c.ProviderConfigs.TencentCloud.SecretKey = "" }},
		{name: "missing job name", edit: func(c *Config) { c.Jobs[0].Name = "" }},
		{name: "missing ip source url", edit: func(c *Config) { c.Jobs[0].IPSource.URL = "" }},
		{name: "missing rules", edit: func(c *Config) { c.Jobs[0].Rules = nil }},
		{name: "empty rule", edit: func(c *Config) { c.Jobs[0].Rules = []string{"TCP:22", ""} }},
		{name: "duplicate rule protocol", edit: func(c *Config) { c.Jobs[0].Rules = []string{"TCP:22", "TCP:443"} }},
		{name: "missing targets", edit: func(c *Config) { c.Jobs[0].Targets = nil }},
		{name: "missing region", edit: func(c *Config) { c.Jobs[0].Targets[0].Region = "" }},
		{name: "missing security group id", edit: func(c *Config) { c.Jobs[0].Targets[0].SecurityGroupID = "" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.edit(cfg)
			if err := cfg.Complete(); err == nil {
				t.Fatal("Complete() expected error")
			}
		})
	}
}

func validConfig() *Config {
	return &Config{
		ProviderConfigs: ProviderConfigs{
			TencentCloud: TencentCloudConfig{
				SecretID:  "sid",
				SecretKey: "skey",
			},
		},
		Jobs: []JobConfig{
			{
				Name:     "dev",
				IPSource: IPSourceConfig{URL: "http://dev.yourdomain.com:55555/"},
				Rules:    []string{"TCP:22,4646", "UDP:53"},
				Targets: []TargetConfig{
					{Name: "dev-web", Region: "ap-guangzhou", SecurityGroupID: "sg-dev"},
					{Name: "dev-db", Region: "ap-guangzhou", SecurityGroupID: "sg-db"},
				},
			},
			{
				Name:     "prod",
				IPSource: IPSourceConfig{URL: "http://prod.yourdomain.com:55555/", TimeoutStr: "3s"},
				Rules:    []string{"ICMP"},
				Targets: []TargetConfig{
					{Region: "ap-singapore", SecurityGroupID: "sg-prod"},
				},
			},
		},
	}
}

func TestParseDurationDays(t *testing.T) {
	d, err := ParseDuration("1d")
	if err != nil {
		t.Fatalf("ParseDuration() error = %v", err)
	}
	if d != 24*time.Hour {
		t.Fatalf("duration = %v, want %v", d, 24*time.Hour)
	}
}
