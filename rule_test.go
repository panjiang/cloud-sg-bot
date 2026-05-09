package main

import "testing"

func TestParseRuleExpression(t *testing.T) {
	tests := []struct {
		name             string
		raw              string
		protocol         string
		port             string
		serviceID        string
		serviceGroupID   string
		expectPolicyPort bool
	}{
		{name: "tcp multiple ports", raw: "TCP:22,4646", protocol: "TCP", port: "22,4646", expectPolicyPort: true},
		{name: "tcp unordered ports", raw: "TCP:443,22,80", protocol: "TCP", port: "22,80,443", expectPolicyPort: true},
		{name: "tcp ports with spaces trailing comma and duplicate", raw: "TCP: 22, 443,22, ", protocol: "TCP", port: "22,443", expectPolicyPort: true},
		{name: "udp multiple ports", raw: "UDP:80,443", protocol: "UDP", port: "80,443", expectPolicyPort: true},
		{name: "tcp range", raw: "TCP:3306-20000", protocol: "TCP", port: "3306-20000", expectPolicyPort: true},
		{name: "tcp range sorted with ports", raw: "TCP:1000-2000,22,80-90", protocol: "TCP", port: "22,80-90,1000-2000", expectPolicyPort: true},
		{name: "unsafe port syntax passes through", raw: "TCP:22,abc,80", protocol: "TCP", port: "22,abc,80", expectPolicyPort: true},
		{name: "all", raw: "ALL", protocol: "ALL", port: "all", expectPolicyPort: true},
		{name: "icmp", raw: "ICMP", protocol: "ICMP"},
		{name: "icmpv6", raw: "ICMPv6", protocol: "ICMPV6"},
		{name: "gre", raw: "GRE", protocol: "GRE"},
		{name: "service template", raw: "ppm-1234ilbd", serviceID: "ppm-1234ilbd"},
		{name: "service template group", raw: "ppmg-1234ilbd", serviceGroupID: "ppmg-1234ilbd"},
		{name: "non standard protocol passes through", raw: "FOO:bar", protocol: "FOO", port: "bar", expectPolicyPort: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := ParseRuleExpression(tt.raw)
			if err != nil {
				t.Fatalf("ParseRuleExpression() error = %v", err)
			}
			if rule.Protocol != tt.protocol || rule.Port != tt.port || rule.ServiceID != tt.serviceID || rule.ServiceGroupID != tt.serviceGroupID {
				t.Fatalf("rule = %#v", rule)
			}
			policy := rule.ToPolicy("1.2.3.4/32", "desc")
			if tt.serviceID != "" {
				if policy.ServiceTemplate == nil || stringValue(policy.ServiceTemplate.ServiceId) != tt.serviceID {
					t.Fatalf("ServiceTemplate.ServiceId = %#v, want %q", policy.ServiceTemplate, tt.serviceID)
				}
				return
			}
			if tt.serviceGroupID != "" {
				if policy.ServiceTemplate == nil || stringValue(policy.ServiceTemplate.ServiceGroupId) != tt.serviceGroupID {
					t.Fatalf("ServiceTemplate.ServiceGroupId = %#v, want %q", policy.ServiceTemplate, tt.serviceGroupID)
				}
				return
			}
			if stringValue(policy.Protocol) != tt.protocol {
				t.Fatalf("Protocol = %q, want %q", stringValue(policy.Protocol), tt.protocol)
			}
			if tt.expectPolicyPort && stringValue(policy.Port) != tt.port {
				t.Fatalf("Port = %q, want %q", stringValue(policy.Port), tt.port)
			}
			if !tt.expectPolicyPort && policy.Port != nil {
				t.Fatalf("Port = %q, want nil", stringValue(policy.Port))
			}
		})
	}
}

func TestParseRuleExpressionEmpty(t *testing.T) {
	if _, err := ParseRuleExpression(" "); err == nil {
		t.Fatal("ParseRuleExpression() expected error")
	}
}

func TestManagedDescriptionUsesJobAndRuleProtocol(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "TCP:22,4646", want: "bot:dev:TCP"},
		{raw: "UDP:53", want: "bot:dev:UDP"},
		{raw: "ICMP", want: "bot:dev:ICMP"},
		{raw: "ppm-1234ilbd", want: "bot:dev:SERVICE"},
		{raw: "ppmg-1234ilbd", want: "bot:dev:SERVICE_GROUP"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			rule, err := ParseRuleExpression(tt.raw)
			if err != nil {
				t.Fatalf("ParseRuleExpression() error = %v", err)
			}
			if got := managedDescription(defaultRemarkPrefix, "dev", rule); got != tt.want {
				t.Fatalf("managedDescription() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestManagedDescriptionAllowsColonInRemarkPrefix(t *testing.T) {
	rule, err := ParseRuleExpression("TCP:22")
	if err != nil {
		t.Fatalf("ParseRuleExpression() error = %v", err)
	}
	if got, want := managedDescription("bot:server238", "dev", rule), "bot:server238:dev:TCP"; got != want {
		t.Fatalf("managedDescription() = %q, want %q", got, want)
	}
}
