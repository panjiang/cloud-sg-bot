package main

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

type securityGroupSyncer interface {
	SyncSecurityGroup(ctx context.Context, job JobConfig, target TargetConfig, rules []RuleExpression, cidrBlock, remarkPrefix string) (SecurityGroupSyncResult, error)
}

type Updater struct {
	cfg      *Config
	provider securityGroupSyncer
}

type SecurityGroupSyncResult struct {
	CreatedPolicies int
	DeletedPolicies int
}

func (r SecurityGroupSyncResult) Changed() bool {
	return r.CreatedPolicies > 0 || r.DeletedPolicies > 0
}

type SyncResult struct {
	Jobs            int
	Targets         int
	ChangedTargets  int
	CreatedPolicies int
	DeletedPolicies int
	Failures        int
}

func (r SyncResult) Changed() bool {
	return r.ChangedTargets > 0 || r.CreatedPolicies > 0 || r.DeletedPolicies > 0
}

func NewUpdater(cfg *Config, provider securityGroupSyncer) *Updater {
	return &Updater{cfg: cfg, provider: provider}
}

func (u *Updater) RunOnce(ctx context.Context) SyncResult {
	var result SyncResult
	for _, job := range u.cfg.Jobs {
		result.Jobs++
		if err := u.runJob(ctx, job, &result); err != nil {
			result.Failures++
			zap.L().Error("sync job failed", zap.String("job", job.Name), zap.Error(err))
		}
	}
	return result
}

func (u *Updater) runJob(ctx context.Context, job JobConfig, result *SyncResult) error {
	fetcher := NewIPFetcher(job.IPSource.Timeout)
	ip, err := fetcher.FetchIPv4(ctx, job.IPSource.URL)
	if err != nil {
		return fmt.Errorf("fetch public ip: %w", err)
	}
	cidrBlock := ip + "/32"

	rules := make([]RuleExpression, 0, len(job.Rules))
	for _, raw := range job.Rules {
		rule, err := ParseRuleExpression(raw)
		if err != nil {
			return err
		}
		rules = append(rules, rule)
	}

	descriptions := managedDescriptions(u.cfg.RemarkPrefix, job.Name, rules)
	zap.L().Debug("fetched public ip",
		zap.String("job", job.Name),
		zap.String("ip", ip),
		zap.String("cidrBlock", cidrBlock),
		zap.Strings("rules", job.Rules),
		zap.Strings("managedDescriptions", descriptions))

	var failedTargets int
	for _, target := range job.Targets {
		result.Targets++
		syncResult, err := u.provider.SyncSecurityGroup(ctx, job, target, rules, cidrBlock, u.cfg.RemarkPrefix)
		if err != nil {
			failedTargets++
			zap.L().Error("sync target failed",
				zap.String("job", job.Name),
				zap.String("region", target.Region),
				zap.String("securityGroupId", target.SecurityGroupID),
				zap.Error(err))
			continue
		}
		result.CreatedPolicies += syncResult.CreatedPolicies
		result.DeletedPolicies += syncResult.DeletedPolicies
		if syncResult.Changed() {
			result.ChangedTargets++
		}

		fields := []zap.Field{
			zap.String("job", job.Name),
			zap.String("region", target.Region),
			zap.String("securityGroupId", target.SecurityGroupID),
			zap.String("cidrBlock", cidrBlock),
			zap.Strings("rules", job.Rules),
			zap.Strings("managedDescriptions", descriptions),
			zap.Bool("changed", syncResult.Changed()),
			zap.Int("createdPolicies", syncResult.CreatedPolicies),
			zap.Int("deletedPolicies", syncResult.DeletedPolicies),
		}
		if syncResult.Changed() {
			zap.L().Info("updated target", fields...)
			continue
		}
		zap.L().Debug("synced target", fields...)
	}
	if failedTargets > 0 {
		return fmt.Errorf("%d target(s) failed", failedTargets)
	}
	return nil
}
