package policy

import (
	"sync"
	"testing"
)

func TestPolicyEngine_StrictEvaluationConformance(t *testing.T) {
	t.Run("unconfigured engine fails closed", func(t *testing.T) {
		e := NewEngine(nil)
		decision := e.Evaluate(Request{Protocol: "tcp", Domain: "api.example.com", Port: 443})
		if decision.Allow {
			t.Fatal("unconfigured engine allowed request")
		}
	})

	t.Run("org deny wins over local allow", func(t *testing.T) {
		e := NewEngine(&Snapshot{
			OrgDeny: []Rule{
				{ID: "org-block-analytics", Protocol: "tcp", Domain: "*.evil-analytics.test", Port: 443},
			},
			LocalAllow: []Rule{
				{ID: "local-allow-analytics", Protocol: "tcp", Domain: "tracker.evil-analytics.test", Port: 443},
			},
		})

		decision := e.Evaluate(Request{Protocol: "tcp", Domain: "tracker.evil-analytics.test", Port: 443})
		if decision.Allow {
			t.Fatalf("local allow overrode org deny: %+v", decision)
		}
		if decision.RuleID != "org-block-analytics" {
			t.Fatalf("expected org deny ruleID, got: %s", decision.RuleID)
		}
	})

	t.Run("local deny wins over local allow", func(t *testing.T) {
		e := NewEngine(&Snapshot{
			LocalDeny: []Rule{
				{ID: "local-block-dev", Protocol: "tcp", Domain: "staging.internal.test", Port: 80},
			},
			LocalAllow: []Rule{
				{ID: "local-allow-wildcard", Protocol: "tcp", Domain: "*.internal.test", Port: 80},
			},
		})

		decision := e.Evaluate(Request{Protocol: "tcp", Domain: "staging.internal.test", Port: 80})
		if decision.Allow {
			t.Fatalf("local allow overrode local deny: %+v", decision)
		}
		if decision.RuleID != "local-block-dev" {
			t.Fatalf("expected local deny ruleID, got: %s", decision.RuleID)
		}
	})

	t.Run("default deny on unmatched traffic", func(t *testing.T) {
		e := NewEngine(&Snapshot{
			LocalAllow: []Rule{
				{ID: "allow-specific", Protocol: "tcp", Domain: "api.allowed.test", Port: 443},
			},
		})

		decision := e.Evaluate(Request{Protocol: "tcp", Domain: "other.test", Port: 443})
		if decision.Allow {
			t.Fatalf("unmatched traffic was allowed: %+v", decision)
		}
		if decision.Reason != "default deny" {
			t.Fatalf("expected default deny, got: %s", decision.Reason)
		}
	})

	t.Run("atomic update replaces snapshot safely under concurrent evaluation", func(t *testing.T) {
		e := NewEngine(&Snapshot{
			LocalAllow: []Rule{{ID: "init", Protocol: "tcp", Domain: "api.v1.test", Port: 443}},
		})

		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					e.Evaluate(Request{Protocol: "tcp", Domain: "api.v1.test", Port: 443})
					if idx%2 == 0 {
						e.Update(Snapshot{
							LocalAllow: []Rule{{ID: "updated", Protocol: "tcp", Domain: "api.v1.test", Port: 443}},
						})
					}
				}
			}(i)
		}
		wg.Wait()
	})
}
