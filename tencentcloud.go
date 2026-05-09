package main

import (
	"context"
	"fmt"
	"sync"

	tccommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	vpc "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/vpc/v20170312"
	"go.uber.org/zap"
)

type securityGroupAPI interface {
	DescribeSecurityGroupPoliciesWithContext(context.Context, *vpc.DescribeSecurityGroupPoliciesRequest) (*vpc.DescribeSecurityGroupPoliciesResponse, error)
	CreateSecurityGroupPoliciesWithContext(context.Context, *vpc.CreateSecurityGroupPoliciesRequest) (*vpc.CreateSecurityGroupPoliciesResponse, error)
	DeleteSecurityGroupPoliciesWithContext(context.Context, *vpc.DeleteSecurityGroupPoliciesRequest) (*vpc.DeleteSecurityGroupPoliciesResponse, error)
}

type TencentCloudProvider struct {
	cfg     TencentCloudConfig
	mu      sync.Mutex
	clients map[string]securityGroupAPI
	factory func(region string) (securityGroupAPI, error)
}

func NewTencentCloudProvider(cfg TencentCloudConfig) *TencentCloudProvider {
	provider := &TencentCloudProvider{
		cfg:     cfg,
		clients: make(map[string]securityGroupAPI),
	}
	provider.factory = provider.newClient
	return provider
}

func (p *TencentCloudProvider) SyncSecurityGroup(ctx context.Context, job JobConfig, target TargetConfig, rules []RuleExpression, cidrBlock, remarkPrefix string) (SecurityGroupSyncResult, error) {
	client, err := p.clientForRegion(target.Region)
	if err != nil {
		return SecurityGroupSyncResult{}, err
	}

	policies, err := p.describeIngressPolicies(ctx, client, target.SecurityGroupID)
	if err != nil {
		return SecurityGroupSyncResult{}, err
	}

	var toDelete []*vpc.SecurityGroupPolicy
	var toCreate []*vpc.SecurityGroupPolicy
	for _, rule := range rules {
		description := managedDescription(remarkPrefix, job.Name, rule)
		managed := findManagedPolicies(policies, description)
		hasCurrent := false
		for _, policy := range managed {
			if policyIsCurrent(rule, policy, cidrBlock) {
				hasCurrent = true
				continue
			}
			logManagedPolicyMismatch(job, target, rule, policy, cidrBlock, description)
			if deletePolicy := clonePolicyForDelete(policy); deletePolicy != nil {
				toDelete = append(toDelete, deletePolicy)
			}
		}
		if !hasCurrent {
			toCreate = append(toCreate, rule.ToPolicy(cidrBlock, description))
		}
	}

	if len(toDelete) > 0 {
		if err := p.deleteIngressPolicies(ctx, client, target.SecurityGroupID, toDelete); err != nil {
			return SecurityGroupSyncResult{}, err
		}
	}
	if len(toCreate) > 0 {
		if err := p.createIngressPolicies(ctx, client, target.SecurityGroupID, toCreate); err != nil {
			return SecurityGroupSyncResult{}, err
		}
	}
	return SecurityGroupSyncResult{
		CreatedPolicies: len(toCreate),
		DeletedPolicies: len(toDelete),
	}, nil
}

func policyIsCurrent(rule RuleExpression, policy *vpc.SecurityGroupPolicy, cidrBlock string) bool {
	return normalizeIPv4CIDR(stringValue(policy.CidrBlock)) == normalizeIPv4CIDR(cidrBlock) &&
		normalizeAction(stringValue(policy.Action)) == "ACCEPT" &&
		ruleMatchesPolicy(rule, policy)
}

func logManagedPolicyMismatch(job JobConfig, target TargetConfig, rule RuleExpression, policy *vpc.SecurityGroupPolicy, cidrBlock, description string) {
	if policy == nil {
		return
	}
	zap.L().Debug("managed policy differs",
		zap.String("job", job.Name),
		zap.String("region", target.Region),
		zap.String("securityGroupId", target.SecurityGroupID),
		zap.String("managedDescription", description),
		zap.String("expectedCidrBlock", cidrBlock),
		zap.String("normalizedExpectedCidrBlock", normalizeIPv4CIDR(cidrBlock)),
		zap.String("policyCidrBlock", stringValue(policy.CidrBlock)),
		zap.String("normalizedPolicyCidrBlock", normalizeIPv4CIDR(stringValue(policy.CidrBlock))),
		zap.String("expectedAction", "ACCEPT"),
		zap.String("policyAction", stringValue(policy.Action)),
		zap.String("normalizedPolicyAction", normalizeAction(stringValue(policy.Action))),
		zap.String("expectedProtocol", rule.Protocol),
		zap.String("policyProtocol", stringValue(policy.Protocol)),
		zap.String("normalizedPolicyProtocol", normalizeProtocol(stringValue(policy.Protocol))),
		zap.String("expectedPort", rule.Port),
		zap.String("policyPort", stringValue(policy.Port)),
		zap.String("normalizedPolicyPort", normalizePortExpression(stringValue(policy.Port))))
}

func (p *TencentCloudProvider) clientForRegion(region string) (securityGroupAPI, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if client, ok := p.clients[region]; ok {
		return client, nil
	}
	client, err := p.factory(region)
	if err != nil {
		return nil, fmt.Errorf("init tencent cloud vpc client region=%s: %w", region, err)
	}
	p.clients[region] = client
	return client, nil
}

func (p *TencentCloudProvider) newClient(region string) (securityGroupAPI, error) {
	cred := tccommon.NewCredential(p.cfg.SecretID, p.cfg.SecretKey)
	prof := profile.NewClientProfile()
	prof.HttpProfile.Endpoint = "vpc.tencentcloudapi.com"
	return vpc.NewClient(cred, region, prof)
}

func (p *TencentCloudProvider) describeIngressPolicies(ctx context.Context, client securityGroupAPI, securityGroupID string) ([]*vpc.SecurityGroupPolicy, error) {
	req := vpc.NewDescribeSecurityGroupPoliciesRequest()
	req.SecurityGroupId = stringPtr(securityGroupID)
	resp, err := client.DescribeSecurityGroupPoliciesWithContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("describe security group policies securityGroupId=%s: %w", securityGroupID, err)
	}
	if resp == nil || resp.Response == nil || resp.Response.SecurityGroupPolicySet == nil {
		return nil, nil
	}
	return resp.Response.SecurityGroupPolicySet.Ingress, nil
}

func (p *TencentCloudProvider) deleteIngressPolicies(ctx context.Context, client securityGroupAPI, securityGroupID string, policies []*vpc.SecurityGroupPolicy) error {
	req := vpc.NewDeleteSecurityGroupPoliciesRequest()
	req.SecurityGroupId = stringPtr(securityGroupID)
	req.SecurityGroupPolicySet = &vpc.SecurityGroupPolicySet{Ingress: policies}
	if _, err := client.DeleteSecurityGroupPoliciesWithContext(ctx, req); err != nil {
		return fmt.Errorf("delete security group policies securityGroupId=%s: %w", securityGroupID, err)
	}
	return nil
}

func (p *TencentCloudProvider) createIngressPolicies(ctx context.Context, client securityGroupAPI, securityGroupID string, policies []*vpc.SecurityGroupPolicy) error {
	req := vpc.NewCreateSecurityGroupPoliciesRequest()
	req.SecurityGroupId = stringPtr(securityGroupID)
	req.SecurityGroupPolicySet = &vpc.SecurityGroupPolicySet{Ingress: policies}
	if _, err := client.CreateSecurityGroupPoliciesWithContext(ctx, req); err != nil {
		return fmt.Errorf("create security group policies securityGroupId=%s: %w", securityGroupID, err)
	}
	return nil
}

func findManagedPolicies(policies []*vpc.SecurityGroupPolicy, description string) []*vpc.SecurityGroupPolicy {
	var matches []*vpc.SecurityGroupPolicy
	for _, policy := range policies {
		if stringValue(policy.PolicyDescription) == description {
			matches = append(matches, policy)
		}
	}
	return matches
}

func clonePolicyForDelete(policy *vpc.SecurityGroupPolicy) *vpc.SecurityGroupPolicy {
	if policy == nil {
		return nil
	}
	clone := &vpc.SecurityGroupPolicy{
		Action:            policy.Action,
		PolicyDescription: policy.PolicyDescription,
	}
	if serviceID(policy.ServiceTemplate) != "" || serviceGroupID(policy.ServiceTemplate) != "" {
		clone.ServiceTemplate = &vpc.ServiceTemplateSpecification{}
		if serviceID(policy.ServiceTemplate) != "" {
			clone.ServiceTemplate.ServiceId = policy.ServiceTemplate.ServiceId
		}
		if serviceGroupID(policy.ServiceTemplate) != "" {
			clone.ServiceTemplate.ServiceGroupId = policy.ServiceTemplate.ServiceGroupId
		}
	} else {
		if stringValue(policy.Protocol) != "" {
			clone.Protocol = policy.Protocol
		}
		if stringValue(policy.Port) != "" {
			clone.Port = policy.Port
		}
	}
	if stringValue(policy.CidrBlock) != "" {
		clone.CidrBlock = policy.CidrBlock
	} else if stringValue(policy.Ipv6CidrBlock) != "" {
		clone.Ipv6CidrBlock = policy.Ipv6CidrBlock
	} else if addressID(policy.AddressTemplate) != "" || addressGroupID(policy.AddressTemplate) != "" {
		clone.AddressTemplate = &vpc.AddressTemplateSpecification{}
		if addressID(policy.AddressTemplate) != "" {
			clone.AddressTemplate.AddressId = policy.AddressTemplate.AddressId
		}
		if addressGroupID(policy.AddressTemplate) != "" {
			clone.AddressTemplate.AddressGroupId = policy.AddressTemplate.AddressGroupId
		}
	}
	return clone
}

func serviceID(template *vpc.ServiceTemplateSpecification) string {
	if template == nil {
		return ""
	}
	return stringValue(template.ServiceId)
}

func serviceGroupID(template *vpc.ServiceTemplateSpecification) string {
	if template == nil {
		return ""
	}
	return stringValue(template.ServiceGroupId)
}

func addressID(template *vpc.AddressTemplateSpecification) string {
	if template == nil {
		return ""
	}
	return stringValue(template.AddressId)
}

func addressGroupID(template *vpc.AddressTemplateSpecification) string {
	if template == nil {
		return ""
	}
	return stringValue(template.AddressGroupId)
}
