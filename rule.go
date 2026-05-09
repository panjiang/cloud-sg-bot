package main

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	vpc "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/vpc/v20170312"
)

type RuleExpression struct {
	Raw            string
	Normalized     string
	Protocol       string
	Port           string
	ServiceID      string
	ServiceGroupID string
}

func ParseRuleExpression(raw string) (RuleExpression, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return RuleExpression{}, fmt.Errorf("rule is empty")
	}

	rule := RuleExpression{Raw: raw}
	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, "ppmg-"):
		rule.ServiceGroupID = raw
		rule.Normalized = strings.ToLower(raw)
	case strings.HasPrefix(lower, "ppm-"):
		rule.ServiceID = raw
		rule.Normalized = strings.ToLower(raw)
	case strings.Contains(raw, ":"):
		parts := strings.SplitN(raw, ":", 2)
		rule.Protocol = strings.ToUpper(strings.TrimSpace(parts[0]))
		rule.Port = normalizePortExpression(parts[1])
		rule.Normalized = rule.Protocol + ":" + rule.Port
	default:
		rule.Protocol = strings.ToUpper(raw)
		if rule.Protocol == "ALL" {
			rule.Port = "all"
		}
		rule.Normalized = rule.Protocol
	}
	return rule, nil
}

func (r RuleExpression) ToPolicy(cidrBlock, description string) *vpc.SecurityGroupPolicy {
	policy := &vpc.SecurityGroupPolicy{
		CidrBlock:         stringPtr(cidrBlock),
		Action:            stringPtr("ACCEPT"),
		PolicyDescription: stringPtr(description),
	}
	if r.ServiceID != "" || r.ServiceGroupID != "" {
		policy.ServiceTemplate = &vpc.ServiceTemplateSpecification{}
		if r.ServiceID != "" {
			policy.ServiceTemplate.ServiceId = stringPtr(r.ServiceID)
		}
		if r.ServiceGroupID != "" {
			policy.ServiceTemplate.ServiceGroupId = stringPtr(r.ServiceGroupID)
		}
		return policy
	}
	policy.Protocol = stringPtr(r.Protocol)
	if r.Port != "" || r.Protocol == "ALL" {
		policy.Port = stringPtr(r.Port)
	}
	return policy
}

func ruleMatchesPolicy(rule RuleExpression, policy *vpc.SecurityGroupPolicy) bool {
	if policy == nil {
		return false
	}
	if rule.ServiceID != "" || rule.ServiceGroupID != "" {
		if policy.ServiceTemplate == nil {
			return false
		}
		return stringValue(policy.ServiceTemplate.ServiceId) == rule.ServiceID &&
			stringValue(policy.ServiceTemplate.ServiceGroupId) == rule.ServiceGroupID
	}
	return normalizeProtocol(stringValue(policy.Protocol)) == rule.Protocol &&
		normalizedPolicyPortMatches(rule, stringValue(policy.Port))
}

func normalizedPolicyPortMatches(rule RuleExpression, policyPort string) bool {
	if rule.Protocol == "ALL" {
		policyPort = strings.TrimSpace(policyPort)
		return policyPort == "" || strings.EqualFold(policyPort, rule.Port)
	}
	return normalizePortExpression(policyPort) == rule.Port
}

func normalizeProtocol(protocol string) string {
	return strings.ToUpper(strings.TrimSpace(protocol))
}

func normalizeAction(action string) string {
	return strings.ToUpper(strings.TrimSpace(action))
}

func normalizeIPv4CIDR(cidrBlock string) string {
	cidrBlock = strings.TrimSpace(cidrBlock)
	if cidrBlock == "" {
		return cidrBlock
	}
	ip := net.ParseIP(cidrBlock)
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String() + "/32"
	}
	parsedIP, network, err := net.ParseCIDR(cidrBlock)
	if err != nil {
		return cidrBlock
	}
	if parsedIP.To4() == nil {
		return cidrBlock
	}
	return network.String()
}

func normalizePortExpression(port string) string {
	port = strings.TrimSpace(port)
	if port == "" {
		return port
	}

	rawParts := strings.Split(port, ",")
	seen := make(map[string]struct{}, len(rawParts))
	parts := make([]portExpressionPart, 0, len(rawParts))
	for _, rawPart := range rawParts {
		part := strings.TrimSpace(rawPart)
		if part == "" {
			continue
		}
		parsed, ok := parsePortExpressionPart(part)
		if !ok {
			return port
		}
		if _, exists := seen[parsed.text]; exists {
			continue
		}
		seen[parsed.text] = struct{}{}
		parts = append(parts, parsed)
	}
	if len(parts) == 0 {
		return port
	}

	sort.Slice(parts, func(i, j int) bool {
		if parts[i].start != parts[j].start {
			return parts[i].start < parts[j].start
		}
		if parts[i].end != parts[j].end {
			return parts[i].end < parts[j].end
		}
		return parts[i].text < parts[j].text
	})

	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized = append(normalized, part.text)
	}
	return strings.Join(normalized, ",")
}

type portExpressionPart struct {
	text  string
	start int
	end   int
}

func parsePortExpressionPart(part string) (portExpressionPart, bool) {
	if strings.Contains(part, "-") {
		rangeParts := strings.Split(part, "-")
		if len(rangeParts) != 2 {
			return portExpressionPart{}, false
		}
		start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
		if err != nil {
			return portExpressionPart{}, false
		}
		end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
		if err != nil {
			return portExpressionPart{}, false
		}
		return portExpressionPart{
			text:  strconv.Itoa(start) + "-" + strconv.Itoa(end),
			start: start,
			end:   end,
		}, true
	}

	port, err := strconv.Atoi(part)
	if err != nil {
		return portExpressionPart{}, false
	}
	return portExpressionPart{text: strconv.Itoa(port), start: port, end: port}, true
}

func managedDescription(remarkPrefix, jobName string, rule RuleExpression) string {
	return fmt.Sprintf("%s:%s:%s", remarkPrefix, jobName, rule.DescriptionProtocol())
}

func managedDescriptions(remarkPrefix, jobName string, rules []RuleExpression) []string {
	descriptions := make([]string, 0, len(rules))
	for _, rule := range rules {
		descriptions = append(descriptions, managedDescription(remarkPrefix, jobName, rule))
	}
	return descriptions
}

func (r RuleExpression) DescriptionProtocol() string {
	if r.Protocol != "" {
		return r.Protocol
	}
	if r.ServiceID != "" {
		return "SERVICE"
	}
	if r.ServiceGroupID != "" {
		return "SERVICE_GROUP"
	}
	return "UNKNOWN"
}

func stringPtr(value string) *string {
	return &value
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
