package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultCheckInterval       = 10 * time.Minute
	defaultCheckIntervalString = "10m"
	defaultIPSourceTimeout     = 5 * time.Second
	defaultIPSourceTimeoutText = "5s"
	defaultRemarkPrefix        = "bot"
	minCheckInterval           = 10 * time.Second
)

type Config struct {
	CheckIntervalStr string          `yaml:"checkInterval"`
	CheckInterval    time.Duration   `yaml:"-"`
	RemarkPrefix     string          `yaml:"remarkPrefix"`
	Log              LogConfig       `yaml:"log"`
	ProviderConfigs  ProviderConfigs `yaml:"providerConfigs"`
	Jobs             []JobConfig     `yaml:"jobs"`
}

type LogConfig struct {
	Level string `yaml:"level"`
}

type ProviderConfigs struct {
	TencentCloud TencentCloudConfig `yaml:"tencentcloud"`
}

type TencentCloudConfig struct {
	SecretID  string `yaml:"secretId"`
	SecretKey string `yaml:"secretKey"`
}

type JobConfig struct {
	Name     string         `yaml:"name"`
	IPSource IPSourceConfig `yaml:"ipSource"`
	Rules    []string       `yaml:"rules"`
	Targets  []TargetConfig `yaml:"targets"`
}

type IPSourceConfig struct {
	URL        string        `yaml:"url"`
	TimeoutStr string        `yaml:"timeout"`
	Timeout    time.Duration `yaml:"-"`
}

type TargetConfig struct {
	Name            string `yaml:"name"`
	Region          string `yaml:"region"`
	SecurityGroupID string `yaml:"securityGroupId"`
}

func LoadConfig(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := cfg.Complete(); err != nil {
		return nil, fmt.Errorf("complete config: %w", err)
	}
	return &cfg, nil
}

func (c *Config) Complete() error {
	c.Log.Level = normalizeLogLevel(c.Log.Level)
	if err := validateLogLevel(c.Log.Level); err != nil {
		return err
	}

	c.CheckIntervalStr = strings.TrimSpace(c.CheckIntervalStr)
	if c.CheckIntervalStr == "" {
		c.CheckIntervalStr = defaultCheckIntervalString
	}
	checkInterval, err := ParseDuration(c.CheckIntervalStr)
	if err != nil {
		return fmt.Errorf("invalid checkInterval: %w", err)
	}
	if checkInterval < minCheckInterval {
		return fmt.Errorf("invalid checkInterval: should be greater than or equal to 10 seconds")
	}
	c.CheckInterval = checkInterval

	c.RemarkPrefix = strings.TrimSpace(c.RemarkPrefix)
	if c.RemarkPrefix == "" {
		c.RemarkPrefix = defaultRemarkPrefix
	}

	c.ProviderConfigs.TencentCloud.SecretID = strings.TrimSpace(c.ProviderConfigs.TencentCloud.SecretID)
	if c.ProviderConfigs.TencentCloud.SecretID == "" {
		return fmt.Errorf("providerConfigs.tencentcloud.secretId is required")
	}
	c.ProviderConfigs.TencentCloud.SecretKey = strings.TrimSpace(c.ProviderConfigs.TencentCloud.SecretKey)
	if c.ProviderConfigs.TencentCloud.SecretKey == "" {
		return fmt.Errorf("providerConfigs.tencentcloud.secretKey is required")
	}

	if len(c.Jobs) == 0 {
		return fmt.Errorf("jobs is required")
	}
	seenJobs := make(map[string]struct{}, len(c.Jobs))
	for i := range c.Jobs {
		if err := c.Jobs[i].complete(); err != nil {
			return fmt.Errorf("invalid jobs[%d]: %w", i, err)
		}
		if _, exists := seenJobs[c.Jobs[i].Name]; exists {
			return fmt.Errorf("duplicate job name: %s", c.Jobs[i].Name)
		}
		seenJobs[c.Jobs[i].Name] = struct{}{}
	}
	return nil
}

func (j *JobConfig) complete() error {
	j.Name = strings.TrimSpace(j.Name)
	if j.Name == "" {
		return fmt.Errorf("name is required")
	}

	j.IPSource.URL = strings.TrimSpace(j.IPSource.URL)
	if j.IPSource.URL == "" {
		return fmt.Errorf("ipSource.url is required")
	}
	if _, err := url.ParseRequestURI(j.IPSource.URL); err != nil {
		return fmt.Errorf("invalid ipSource.url: %w", err)
	}
	j.IPSource.TimeoutStr = strings.TrimSpace(j.IPSource.TimeoutStr)
	if j.IPSource.TimeoutStr == "" {
		j.IPSource.TimeoutStr = defaultIPSourceTimeoutText
	}
	timeout, err := ParseDuration(j.IPSource.TimeoutStr)
	if err != nil {
		return fmt.Errorf("invalid ipSource.timeout: %w", err)
	}
	if timeout <= 0 {
		return fmt.Errorf("invalid ipSource.timeout: should be greater than 0")
	}
	j.IPSource.Timeout = timeout

	if len(j.Rules) == 0 {
		return fmt.Errorf("rules is required")
	}
	seenRuleProtocols := make(map[string]struct{}, len(j.Rules))
	for i := range j.Rules {
		j.Rules[i] = strings.TrimSpace(j.Rules[i])
		if j.Rules[i] == "" {
			return fmt.Errorf("rules[%d] is empty", i)
		}
		rule, err := ParseRuleExpression(j.Rules[i])
		if err != nil {
			return fmt.Errorf("invalid rules[%d]: %w", i, err)
		}
		descriptionProtocol := rule.DescriptionProtocol()
		if _, exists := seenRuleProtocols[descriptionProtocol]; exists {
			return fmt.Errorf("duplicate rule protocol for managed description: %s", descriptionProtocol)
		}
		seenRuleProtocols[descriptionProtocol] = struct{}{}
	}

	if len(j.Targets) == 0 {
		return fmt.Errorf("targets is required")
	}
	seenTargets := make(map[string]struct{}, len(j.Targets))
	for i := range j.Targets {
		if err := j.Targets[i].complete(); err != nil {
			return fmt.Errorf("invalid targets[%d]: %w", i, err)
		}
		key := j.Targets[i].Region + "/" + j.Targets[i].SecurityGroupID
		if _, exists := seenTargets[key]; exists {
			return fmt.Errorf("duplicate target: %s", key)
		}
		seenTargets[key] = struct{}{}
	}
	return nil
}

func (t *TargetConfig) complete() error {
	t.Name = strings.TrimSpace(t.Name)
	t.Region = strings.TrimSpace(t.Region)
	t.SecurityGroupID = strings.TrimSpace(t.SecurityGroupID)
	if t.Region == "" {
		return fmt.Errorf("region is required")
	}
	if t.SecurityGroupID == "" {
		return fmt.Errorf("securityGroupId is required")
	}
	return nil
}

func normalizeLogLevel(level string) string {
	level = strings.TrimSpace(strings.ToLower(level))
	if level == "" {
		return "info"
	}
	return level
}

func validateLogLevel(level string) error {
	switch normalizeLogLevel(level) {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return fmt.Errorf("invalid log.level: %s", level)
	}
}
