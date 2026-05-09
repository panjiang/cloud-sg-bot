package main

import (
	"context"
	"errors"
	"testing"

	vpc "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/vpc/v20170312"
)

type fakeSecurityGroupAPI struct {
	ingress []*vpc.SecurityGroupPolicy
	created []*vpc.SecurityGroupPolicy
	deleted []*vpc.SecurityGroupPolicy

	createErr error
	deleteErr error
}

func (f *fakeSecurityGroupAPI) DescribeSecurityGroupPoliciesWithContext(context.Context, *vpc.DescribeSecurityGroupPoliciesRequest) (*vpc.DescribeSecurityGroupPoliciesResponse, error) {
	return &vpc.DescribeSecurityGroupPoliciesResponse{
		Response: &vpc.DescribeSecurityGroupPoliciesResponseParams{
			SecurityGroupPolicySet: &vpc.SecurityGroupPolicySet{Ingress: f.ingress},
		},
	}, nil
}

func (f *fakeSecurityGroupAPI) CreateSecurityGroupPoliciesWithContext(_ context.Context, req *vpc.CreateSecurityGroupPoliciesRequest) (*vpc.CreateSecurityGroupPoliciesResponse, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.created = append(f.created, req.SecurityGroupPolicySet.Ingress...)
	return &vpc.CreateSecurityGroupPoliciesResponse{Response: &vpc.CreateSecurityGroupPoliciesResponseParams{}}, nil
}

func (f *fakeSecurityGroupAPI) DeleteSecurityGroupPoliciesWithContext(_ context.Context, req *vpc.DeleteSecurityGroupPoliciesRequest) (*vpc.DeleteSecurityGroupPoliciesResponse, error) {
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	f.deleted = append(f.deleted, req.SecurityGroupPolicySet.Ingress...)
	return &vpc.DeleteSecurityGroupPoliciesResponse{Response: &vpc.DeleteSecurityGroupPoliciesResponseParams{}}, nil
}

func TestSyncSecurityGroupReplacesOnlyManagedOldIP(t *testing.T) {
	api := &fakeSecurityGroupAPI{}
	provider := testProvider(api)
	job := JobConfig{Name: "prod"}
	target := TargetConfig{Region: "ap-singapore", SecurityGroupID: "sg-prod"}
	rule := mustRule(t, "TCP:22,4646")
	desc := managedDescription("bot", job.Name, rule)
	otherJobDesc := managedDescription("bot", "dev", rule)
	otherPrefixDesc := managedDescription("bot:server239", job.Name, rule)
	oldFormatDesc := "tencent-sg-updater:prod:TCP"
	api.ingress = []*vpc.SecurityGroupPolicy{
		rule.ToPolicy("2.2.2.2/32", desc),
		rule.ToPolicy("3.3.3.3/32", otherJobDesc),
		rule.ToPolicy("3.3.3.4/32", otherPrefixDesc),
		rule.ToPolicy("3.3.3.5/32", oldFormatDesc),
		rule.ToPolicy("4.4.4.4/32", "manual"),
	}

	result, err := provider.SyncSecurityGroup(context.Background(), job, target, []RuleExpression{rule}, "1.1.1.1/32", "bot")
	if err != nil {
		t.Fatalf("SyncSecurityGroup() error = %v", err)
	}
	if !result.Changed() || result.DeletedPolicies != 1 || result.CreatedPolicies != 1 {
		t.Fatalf("result = %#v, want 1 deleted and 1 created", result)
	}
	if len(api.deleted) != 1 {
		t.Fatalf("deleted = %d, want 1", len(api.deleted))
	}
	if stringValue(api.deleted[0].CidrBlock) != "2.2.2.2/32" || stringValue(api.deleted[0].PolicyDescription) != desc {
		t.Fatalf("deleted policy = %#v", api.deleted[0])
	}
	if api.deleted[0].PolicyIndex != nil || api.deleted[0].Priority != nil || api.deleted[0].ModifyTime != nil {
		t.Fatalf("delete policy contains dynamic fields: %#v", api.deleted[0])
	}
	if len(api.created) != 1 {
		t.Fatalf("created = %d, want 1", len(api.created))
	}
	if stringValue(api.created[0].CidrBlock) != "1.1.1.1/32" || stringValue(api.created[0].PolicyDescription) != desc {
		t.Fatalf("created policy = %#v", api.created[0])
	}
}

func TestSyncSecurityGroupOmitsEmptyTencentCloudFieldsOnDelete(t *testing.T) {
	api := &fakeSecurityGroupAPI{}
	provider := testProvider(api)
	job := JobConfig{Name: "prod"}
	target := TargetConfig{Region: "ap-singapore", SecurityGroupID: "sg-prod"}
	rule := mustRule(t, "TCP:22")
	desc := managedDescription("bot", job.Name, rule)
	api.ingress = []*vpc.SecurityGroupPolicy{
		{
			Protocol: stringPtr("TCP"),
			Port:     stringPtr("22"),
			ServiceTemplate: &vpc.ServiceTemplateSpecification{
				ServiceId:      stringPtr(""),
				ServiceGroupId: stringPtr(""),
			},
			CidrBlock:     stringPtr("2.2.2.2/32"),
			Ipv6CidrBlock: stringPtr(""),
			AddressTemplate: &vpc.AddressTemplateSpecification{
				AddressId:      stringPtr(""),
				AddressGroupId: stringPtr(""),
			},
			Action:            stringPtr("ACCEPT"),
			PolicyDescription: stringPtr(desc),
		},
	}

	result, err := provider.SyncSecurityGroup(context.Background(), job, target, []RuleExpression{rule}, "1.1.1.1/32", "bot")
	if err != nil {
		t.Fatalf("SyncSecurityGroup() error = %v", err)
	}
	if !result.Changed() || result.DeletedPolicies != 1 || result.CreatedPolicies != 1 {
		t.Fatalf("result = %#v, want 1 deleted and 1 created", result)
	}
	if len(api.deleted) != 1 {
		t.Fatalf("deleted = %d, want 1", len(api.deleted))
	}
	deleted := api.deleted[0]
	if deleted.ServiceTemplate != nil || deleted.Ipv6CidrBlock != nil || deleted.AddressTemplate != nil {
		t.Fatalf("delete policy contains empty fields: %#v", deleted)
	}
	if stringValue(deleted.Protocol) != "TCP" || stringValue(deleted.Port) != "22" || stringValue(deleted.CidrBlock) != "2.2.2.2/32" {
		t.Fatalf("delete policy = %#v", deleted)
	}
}

func TestSyncSecurityGroupKeepsCurrentManagedRule(t *testing.T) {
	api := &fakeSecurityGroupAPI{}
	provider := testProvider(api)
	job := JobConfig{Name: "prod"}
	target := TargetConfig{Region: "ap-singapore", SecurityGroupID: "sg-prod"}
	rule := mustRule(t, "UDP:53")
	desc := managedDescription("bot", job.Name, rule)
	api.ingress = []*vpc.SecurityGroupPolicy{rule.ToPolicy("1.1.1.1/32", desc)}

	result, err := provider.SyncSecurityGroup(context.Background(), job, target, []RuleExpression{rule}, "1.1.1.1/32", "bot")
	if err != nil {
		t.Fatalf("SyncSecurityGroup() error = %v", err)
	}
	if result.Changed() || result.DeletedPolicies != 0 || result.CreatedPolicies != 0 {
		t.Fatalf("result = %#v, want no changes", result)
	}
	if len(api.deleted) != 0 || len(api.created) != 0 {
		t.Fatalf("deleted=%d created=%d, want no changes", len(api.deleted), len(api.created))
	}
}

func TestSyncSecurityGroupKeepsCurrentManagedRuleWithNormalizedConfigPorts(t *testing.T) {
	api := &fakeSecurityGroupAPI{}
	provider := testProvider(api)
	job := JobConfig{Name: "prod"}
	target := TargetConfig{Region: "ap-singapore", SecurityGroupID: "sg-prod"}
	rule := mustRule(t, "TCP:443,22,80")
	desc := managedDescription("bot", job.Name, rule)
	api.ingress = []*vpc.SecurityGroupPolicy{
		{
			Protocol:          stringPtr("TCP"),
			Port:              stringPtr("22,80,443"),
			CidrBlock:         stringPtr("1.1.1.1/32"),
			Action:            stringPtr("ACCEPT"),
			PolicyDescription: stringPtr(desc),
		},
	}

	result, err := provider.SyncSecurityGroup(context.Background(), job, target, []RuleExpression{rule}, "1.1.1.1/32", "bot")
	if err != nil {
		t.Fatalf("SyncSecurityGroup() error = %v", err)
	}
	if result.Changed() || result.DeletedPolicies != 0 || result.CreatedPolicies != 0 {
		t.Fatalf("result = %#v, want no changes", result)
	}
	if len(api.deleted) != 0 || len(api.created) != 0 {
		t.Fatalf("deleted=%d created=%d, want no changes", len(api.deleted), len(api.created))
	}
}

func TestSyncSecurityGroupKeepsCurrentManagedRuleWithNormalizedCloudPorts(t *testing.T) {
	api := &fakeSecurityGroupAPI{}
	provider := testProvider(api)
	job := JobConfig{Name: "prod"}
	target := TargetConfig{Region: "ap-singapore", SecurityGroupID: "sg-prod"}
	rule := mustRule(t, "TCP:22,80,443")
	desc := managedDescription("bot", job.Name, rule)
	api.ingress = []*vpc.SecurityGroupPolicy{
		{
			Protocol:          stringPtr("TCP"),
			Port:              stringPtr("443,22,80"),
			CidrBlock:         stringPtr("1.1.1.1/32"),
			Action:            stringPtr("ACCEPT"),
			PolicyDescription: stringPtr(desc),
		},
	}

	result, err := provider.SyncSecurityGroup(context.Background(), job, target, []RuleExpression{rule}, "1.1.1.1/32", "bot")
	if err != nil {
		t.Fatalf("SyncSecurityGroup() error = %v", err)
	}
	if result.Changed() || result.DeletedPolicies != 0 || result.CreatedPolicies != 0 {
		t.Fatalf("result = %#v, want no changes", result)
	}
	if len(api.deleted) != 0 || len(api.created) != 0 {
		t.Fatalf("deleted=%d created=%d, want no changes", len(api.deleted), len(api.created))
	}
}

func TestSyncSecurityGroupKeepsCurrentManagedRuleWithCloudFieldCasing(t *testing.T) {
	api := &fakeSecurityGroupAPI{}
	provider := testProvider(api)
	job := JobConfig{Name: "prod"}
	target := TargetConfig{Region: "ap-singapore", SecurityGroupID: "sg-prod"}
	rule := mustRule(t, "TCP:22,80,443")
	desc := managedDescription("bot", job.Name, rule)
	api.ingress = []*vpc.SecurityGroupPolicy{
		{
			Protocol:          stringPtr("tcp"),
			Port:              stringPtr("443,22,80"),
			CidrBlock:         stringPtr("1.1.1.1/32"),
			Action:            stringPtr("accept"),
			PolicyDescription: stringPtr(desc),
		},
	}

	result, err := provider.SyncSecurityGroup(context.Background(), job, target, []RuleExpression{rule}, "1.1.1.1/32", "bot")
	if err != nil {
		t.Fatalf("SyncSecurityGroup() error = %v", err)
	}
	if result.Changed() || result.DeletedPolicies != 0 || result.CreatedPolicies != 0 {
		t.Fatalf("result = %#v, want no changes", result)
	}
	if len(api.deleted) != 0 || len(api.created) != 0 {
		t.Fatalf("deleted=%d created=%d, want no changes", len(api.deleted), len(api.created))
	}
}

func TestSyncSecurityGroupKeepsCurrentManagedRuleWithHostCIDR(t *testing.T) {
	api := &fakeSecurityGroupAPI{}
	provider := testProvider(api)
	job := JobConfig{Name: "prod"}
	target := TargetConfig{Region: "ap-singapore", SecurityGroupID: "sg-prod"}
	rule := mustRule(t, "TCP:22")
	desc := managedDescription("bot", job.Name, rule)
	api.ingress = []*vpc.SecurityGroupPolicy{
		{
			Protocol:          stringPtr("TCP"),
			Port:              stringPtr("22"),
			CidrBlock:         stringPtr("1.1.1.1"),
			Action:            stringPtr("ACCEPT"),
			PolicyDescription: stringPtr(desc),
		},
	}

	result, err := provider.SyncSecurityGroup(context.Background(), job, target, []RuleExpression{rule}, "1.1.1.1/32", "bot")
	if err != nil {
		t.Fatalf("SyncSecurityGroup() error = %v", err)
	}
	if result.Changed() || result.DeletedPolicies != 0 || result.CreatedPolicies != 0 {
		t.Fatalf("result = %#v, want no changes", result)
	}
	if len(api.deleted) != 0 || len(api.created) != 0 {
		t.Fatalf("deleted=%d created=%d, want no changes", len(api.deleted), len(api.created))
	}
}

func TestSyncSecurityGroupKeepsCurrentManagedAllRuleWithoutCloudPort(t *testing.T) {
	api := &fakeSecurityGroupAPI{}
	provider := testProvider(api)
	job := JobConfig{Name: "prod"}
	target := TargetConfig{Region: "ap-singapore", SecurityGroupID: "sg-prod"}
	rule := mustRule(t, "ALL")
	desc := managedDescription("bot", job.Name, rule)
	api.ingress = []*vpc.SecurityGroupPolicy{
		{
			Protocol:          stringPtr("all"),
			CidrBlock:         stringPtr("1.1.1.1/32"),
			Action:            stringPtr("ACCEPT"),
			PolicyDescription: stringPtr(desc),
		},
	}

	result, err := provider.SyncSecurityGroup(context.Background(), job, target, []RuleExpression{rule}, "1.1.1.1/32", "bot")
	if err != nil {
		t.Fatalf("SyncSecurityGroup() error = %v", err)
	}
	if result.Changed() || result.DeletedPolicies != 0 || result.CreatedPolicies != 0 {
		t.Fatalf("result = %#v, want no changes", result)
	}
	if len(api.deleted) != 0 || len(api.created) != 0 {
		t.Fatalf("deleted=%d created=%d, want no changes", len(api.deleted), len(api.created))
	}
}

func TestSyncSecurityGroupReplacesChangedRuleFields(t *testing.T) {
	api := &fakeSecurityGroupAPI{}
	provider := testProvider(api)
	job := JobConfig{Name: "prod"}
	target := TargetConfig{Region: "ap-singapore", SecurityGroupID: "sg-prod"}
	rule := mustRule(t, "TCP:22,4646")
	desc := managedDescription("bot", job.Name, rule)
	api.ingress = []*vpc.SecurityGroupPolicy{
		{
			Protocol:          stringPtr("TCP"),
			Port:              stringPtr("22"),
			CidrBlock:         stringPtr("1.1.1.1/32"),
			Action:            stringPtr("ACCEPT"),
			PolicyDescription: stringPtr(desc),
		},
	}

	result, err := provider.SyncSecurityGroup(context.Background(), job, target, []RuleExpression{rule}, "1.1.1.1/32", "bot")
	if err != nil {
		t.Fatalf("SyncSecurityGroup() error = %v", err)
	}
	if !result.Changed() || result.DeletedPolicies != 1 || result.CreatedPolicies != 1 {
		t.Fatalf("result = %#v, want 1 deleted and 1 created", result)
	}
	if len(api.deleted) != 1 || len(api.created) != 1 {
		t.Fatalf("deleted=%d created=%d, want 1 and 1", len(api.deleted), len(api.created))
	}
}

func TestSyncSecurityGroupReplacesManagedRuleMissingPort(t *testing.T) {
	api := &fakeSecurityGroupAPI{}
	provider := testProvider(api)
	job := JobConfig{Name: "prod"}
	target := TargetConfig{Region: "ap-singapore", SecurityGroupID: "sg-prod"}
	rule := mustRule(t, "TCP:22,80,443")
	desc := managedDescription("bot", job.Name, rule)
	api.ingress = []*vpc.SecurityGroupPolicy{
		{
			Protocol:          stringPtr("TCP"),
			Port:              stringPtr("22,80"),
			CidrBlock:         stringPtr("1.1.1.1/32"),
			Action:            stringPtr("ACCEPT"),
			PolicyDescription: stringPtr(desc),
		},
	}

	result, err := provider.SyncSecurityGroup(context.Background(), job, target, []RuleExpression{rule}, "1.1.1.1/32", "bot")
	if err != nil {
		t.Fatalf("SyncSecurityGroup() error = %v", err)
	}
	if !result.Changed() || result.DeletedPolicies != 1 || result.CreatedPolicies != 1 {
		t.Fatalf("result = %#v, want 1 deleted and 1 created", result)
	}
	if len(api.deleted) != 1 || len(api.created) != 1 {
		t.Fatalf("deleted=%d created=%d, want 1 and 1", len(api.deleted), len(api.created))
	}
}

func TestSyncSecurityGroupPropagatesCreateDeleteErrors(t *testing.T) {
	for _, tt := range []struct {
		name      string
		createErr error
		deleteErr error
	}{
		{name: "create error", createErr: errors.New("create failed")},
		{name: "delete error", deleteErr: errors.New("delete failed")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := &fakeSecurityGroupAPI{createErr: tt.createErr, deleteErr: tt.deleteErr}
			provider := testProvider(api)
			job := JobConfig{Name: "prod"}
			target := TargetConfig{Region: "ap-singapore", SecurityGroupID: "sg-prod"}
			rule := mustRule(t, "TCP:22")
			if tt.deleteErr != nil {
				desc := managedDescription("bot", job.Name, rule)
				api.ingress = []*vpc.SecurityGroupPolicy{rule.ToPolicy("2.2.2.2/32", desc)}
			}
			if _, err := provider.SyncSecurityGroup(context.Background(), job, target, []RuleExpression{rule}, "1.1.1.1/32", "bot"); err == nil {
				t.Fatal("SyncSecurityGroup() expected error")
			}
		})
	}
}

func testProvider(api securityGroupAPI) *TencentCloudProvider {
	provider := NewTencentCloudProvider(TencentCloudConfig{SecretID: "sid", SecretKey: "skey"})
	provider.factory = func(string) (securityGroupAPI, error) { return api, nil }
	return provider
}

func mustRule(t *testing.T, raw string) RuleExpression {
	t.Helper()
	rule, err := ParseRuleExpression(raw)
	if err != nil {
		t.Fatalf("ParseRuleExpression() error = %v", err)
	}
	return rule
}
