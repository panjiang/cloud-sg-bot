package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeSyncer struct {
	calls       []syncCall
	errByTarget map[string]error
}

type syncCall struct {
	remarkPrefix string
	job          string
	target       string
	cidr         string
	rules        []RuleExpression
}

func (f *fakeSyncer) SyncSecurityGroup(_ context.Context, job JobConfig, target TargetConfig, rules []RuleExpression, cidrBlock, remarkPrefix string) (SecurityGroupSyncResult, error) {
	f.calls = append(f.calls, syncCall{
		remarkPrefix: remarkPrefix,
		job:          job.Name,
		target:       target.SecurityGroupID,
		cidr:         cidrBlock,
		rules:        append([]RuleExpression(nil), rules...),
	})
	if f.errByTarget != nil {
		return SecurityGroupSyncResult{}, f.errByTarget[target.SecurityGroupID]
	}
	return SecurityGroupSyncResult{}, nil
}

func TestUpdaterRunOnceContinuesAfterTargetFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Client IP: 8.8.8.8"))
	}))
	defer server.Close()

	cfg := &Config{
		RemarkPrefix: "bot:server238",
		Jobs: []JobConfig{
			{
				Name:     "prod",
				IPSource: IPSourceConfig{URL: server.URL, Timeout: defaultIPSourceTimeout},
				Rules:    []string{"TCP:22,4646"},
				Targets: []TargetConfig{
					{Region: "ap-singapore", SecurityGroupID: "sg-fail"},
					{Region: "ap-singapore", SecurityGroupID: "sg-ok"},
				},
			},
		},
	}
	syncer := &fakeSyncer{errByTarget: map[string]error{"sg-fail": errors.New("boom")}}
	result := NewUpdater(cfg, syncer).RunOnce(context.Background())

	if result.Jobs != 1 || result.Targets != 2 || result.Failures != 1 {
		t.Fatalf("result = %#v", result)
	}
	if len(syncer.calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(syncer.calls))
	}
	for _, call := range syncer.calls {
		if call.remarkPrefix != "bot:server238" {
			t.Fatalf("remarkPrefix = %q, want bot:server238", call.remarkPrefix)
		}
		if call.cidr != "8.8.8.8/32" {
			t.Fatalf("cidr = %q, want 8.8.8.8/32", call.cidr)
		}
		if len(call.rules) != 1 || call.rules[0].Protocol != "TCP" || call.rules[0].Port != "22,4646" {
			t.Fatalf("rules = %#v", call.rules)
		}
	}
}
