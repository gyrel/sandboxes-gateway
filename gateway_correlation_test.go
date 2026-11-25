package gateway

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/rheic/sandboxes-gateway/policy"
)

func TestValidCorrelationID(t *testing.T) {
	for _, id := range []string{"a", "A", "0", "-", "_", "aZ-9_", strings.Repeat("a", 64)} {
		if !validCorrelationID(id) {
			t.Fatalf("valid correlation id %q rejected", id)
		}
	}
	for _, id := range []string{"", strings.Repeat("a", 65), "a.b", "a b", "a/b", "a:b", "a\x00b", "a+b", "*"} {
		if validCorrelationID(id) {
			t.Fatalf("invalid correlation id %q accepted", id)
		}
	}
}

func TestRenderConfigCorrelationIDs(t *testing.T) {
	// Valid ids are rendered next to sandboxID.
	cfg := renderConfig(policy.Policy{
		Revision:  2,
		SandboxID: "dev",
		AuditPath: "/tmp/dev.audit.jsonl",
		OpID:      "op-123",
		ReqID:     "req_456",
	}, "", false)
	for _, want := range []string{`opID: "op-123"`, `reqID: "req_456"`} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("missing %q in config:\n%s", want, cfg)
		}
	}

	// Absent ids are omitted entirely.
	cfg = renderConfig(policy.Policy{Revision: 2, SandboxID: "dev", AuditPath: "/tmp/dev.audit.jsonl"}, "", false)
	if strings.Contains(cfg, "opID:") || strings.Contains(cfg, "reqID:") {
		t.Fatalf("correlation ids rendered when absent:\n%s", cfg)
	}

	// Invalid ids are omitted, never sanitized into the config.
	cfg = renderConfig(policy.Policy{
		Revision:  2,
		SandboxID: "dev",
		AuditPath: "/tmp/dev.audit.jsonl",
		OpID:      "bad.id",
		ReqID:     strings.Repeat("x", 65),
	}, "", false)
	for _, forbidden := range []string{"bad.id", "opID:", "reqID:", strings.Repeat("x", 65)} {
		if strings.Contains(cfg, forbidden) {
			t.Fatalf("invalid correlation id leaked into config %q:\n%s", forbidden, cfg)
		}
	}
}

func TestGatewayEgressPolicyCorrelationIDs(t *testing.T) {
	// Valid ids are present in the JSON wire payload.
	payload := gatewayEgressPolicyFor(policy.Policy{
		Revision: 2, SandboxID: "dev", OpID: "op-123", ReqID: "req_456",
	})
	if payload.OpID != "op-123" || payload.ReqID != "req_456" {
		t.Fatalf("correlation ids not carried: %+v", payload)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"opID":"op-123"`, `"reqID":"req_456"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing %q in payload:\n%s", want, data)
		}
	}

	// Invalid ids are omitted from the struct and the marshaled JSON, never
	// sanitized into it.
	payload = gatewayEgressPolicyFor(policy.Policy{
		Revision: 2, SandboxID: "dev", OpID: "bad.id", ReqID: strings.Repeat("x", 65),
	})
	if payload.OpID != "" || payload.ReqID != "" {
		t.Fatalf("invalid correlation ids were sanitized into the struct: %+v", payload)
	}
	data, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(data)
	for _, forbidden := range []string{"bad.id", strings.Repeat("x", 65), `"opID"`, `"reqID"`} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("invalid correlation id leaked into JSON %q:\n%s", forbidden, raw)
		}
	}
}

func TestEffectiveCorrelationFallback(t *testing.T) {
	tests := []struct {
		name                    string
		policyOp, policyReq     string
		recordedOp, recordedReq string
		wantOp, wantReq         string
	}{
		{name: "policy wins", policyOp: "op-1", policyReq: "req-1", recordedOp: "op-0", recordedReq: "req-0", wantOp: "op-1", wantReq: "req-1"},
		{name: "recorded fallback", policyOp: "", policyReq: "", recordedOp: "op-0", recordedReq: "req-0", wantOp: "op-0", wantReq: "req-0"},
		{name: "partial fallback", policyOp: "op-1", policyReq: "", recordedOp: "op-0", recordedReq: "req-0", wantOp: "op-1", wantReq: "req-0"},
		{name: "all empty", policyOp: "", policyReq: "", recordedOp: "", recordedReq: "", wantOp: "", wantReq: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, req := effectiveCorrelation(tt.policyOp, tt.policyReq, tt.recordedOp, tt.recordedReq)
			if op != tt.wantOp || req != tt.wantReq {
				t.Fatalf("effectiveCorrelation() = %q, %q; want %q, %q", op, req, tt.wantOp, tt.wantReq)
			}
		})
	}
}

func TestSetCorrelationRecords(t *testing.T) {
	m := &Manager{procs: map[string]process{"dev": {}}}
	m.SetCorrelation("dev", "op-1", "req-1")
	m.SetCorrelation("missing", "op-x", "req-x") // ignored: no such sandbox
	m.mu.Lock()
	got := m.procs["dev"]
	m.mu.Unlock()
	if got.opID != "op-1" || got.reqID != "req-1" {
		t.Fatalf("recorded correlation = %q, %q; want op-1, req-1", got.opID, got.reqID)
	}
}

func TestSetCorrelationConcurrent(t *testing.T) {
	m := &Manager{procs: map[string]process{"dev": {}}}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				m.SetCorrelation("dev", fmt.Sprintf("op-%d-%d", i, j), fmt.Sprintf("req-%d-%d", i, j))
			}
		}(i)
	}
	wg.Wait()
	m.mu.Lock()
	op := m.procs["dev"].opID
	req := m.procs["dev"].reqID
	m.mu.Unlock()
	if !strings.HasPrefix(op, "op-") || !strings.HasPrefix(req, "req-") {
		t.Fatalf("correlation ids not recorded: op=%q req=%q", op, req)
	}
}
