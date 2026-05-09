package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
)

var configFilePath string
var showVersion bool

func init() {
	flag.StringVar(&configFilePath, "config", "config.yaml", "Config file path")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
}

func main() {
	flag.Parse()
	os.Exit(run())
}

func run() int {
	if showVersion {
		_, _ = fmt.Fprintln(os.Stdout, Version())
		return 0
	}

	if err := initGlobalLogger("info"); err != nil {
		_, _ = os.Stderr.WriteString("init logger: " + err.Error() + "\n")
		return 1
	}
	defer syncLoggerBestEffort(zap.L())

	cfg, err := LoadConfig(configFilePath)
	if err != nil {
		zap.L().Error("load config failed", zap.Error(err), zap.String("config", configFilePath))
		return 1
	}
	if err := initGlobalLogger(cfg.Log.Level); err != nil {
		zap.L().Error("reconfigure logger failed", zap.Error(err), zap.String("level", cfg.Log.Level))
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	provider := NewTencentCloudProvider(cfg.ProviderConfigs.TencentCloud)
	updater := NewUpdater(cfg, provider)

	zap.L().Info("starting cloud-sg-bot",
		zap.String("config", configFilePath),
		zap.String("remarkPrefix", cfg.RemarkPrefix),
		zap.Duration("checkInterval", cfg.CheckInterval),
		zap.Int("jobs", len(cfg.Jobs)))
	logConfiguredJobs(cfg)

	runAndLog(ctx, updater)
	ticker := time.NewTicker(cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			zap.L().Info("stopping cloud-sg-bot")
			return 0
		case <-ticker.C:
			runAndLog(ctx, updater)
		}
	}
}

func logConfiguredJobs(cfg *Config) {
	for _, job := range cfg.Jobs {
		zap.L().Debug("configured job",
			zap.String("remarkPrefix", cfg.RemarkPrefix),
			zap.String("job", job.Name),
			zap.String("ipSourceUrl", job.IPSource.URL),
			zap.Duration("ipSourceTimeout", job.IPSource.Timeout),
			zap.Strings("rules", job.Rules),
			zap.Int("targets", len(job.Targets)))
	}
}

func runAndLog(ctx context.Context, updater *Updater) {
	result := updater.RunOnce(ctx)
	if result.Failures > 0 {
		zap.L().Warn("sync round finished with failures",
			zap.Int("jobs", result.Jobs),
			zap.Int("targets", result.Targets),
			zap.Int("changedTargets", result.ChangedTargets),
			zap.Int("createdPolicies", result.CreatedPolicies),
			zap.Int("deletedPolicies", result.DeletedPolicies),
			zap.Int("failures", result.Failures))
		return
	}

	fields := []zap.Field{
		zap.Int("jobs", result.Jobs),
		zap.Int("targets", result.Targets),
		zap.Int("changedTargets", result.ChangedTargets),
		zap.Int("createdPolicies", result.CreatedPolicies),
		zap.Int("deletedPolicies", result.DeletedPolicies),
	}
	if result.Changed() {
		zap.L().Info("sync round finished", fields...)
		return
	}
	zap.L().Debug("sync round finished", fields...)
}
