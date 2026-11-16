package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rheic/sandboxes-gateway/policy"
)

func TestWriteConfigRendersHTTPConditions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.yaml")
	p := policy.Policy{
		SandboxID: "http-conditions",
		Allow: []policy.Rule{{
			ID:       "allow-read",
			Protocol: "tcp",
			Domain:   "api.example.test",
			Port:     443,
			Methods:  []string{"HEAD", "GET"},
			Path:     "/v1/**",
			Query:    []policy.QueryParam{{Name: "tag", Value: "v1"}},
		}},
		Deny: []policy.Rule{{
			ID:       "deny-admin",
			Protocol: "tcp",
			Domain:   "api.example.test",
			Port:     443,
			Methods:  []string{"ANY"},
			Path:     "/admin/**",
			Query:    []policy.QueryParam{{Name: "admin", Value: "1"}, {Name: "mode", Value: "r*"}},
		}},
	}
	if err := writeConfig(path, p, "1.1.1.1:53", false, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	config := string(data)
	for _, want := range []string{
		`methods:`, `"GET"`, `"HEAD"`, `path: "/v1/**"`,
		`name: "tag"`, `value: "v1"`, `path: "/admin/**"`, `"ANY"`,
		`name: "admin"`, `name: "mode"`,
	} {
		if !strings.Contains(config, want) {
			t.Errorf("config does not contain %q:\n%s", want, config)
		}
	}
	if strings.Index(config, `name: "admin"`) > strings.Index(config, `name: "mode"`) {
		t.Errorf("query condition order was not preserved:\n%s", config)
	}
}

func TestValidatePolicyRejectsUnparseableHTTPConditions(t *testing.T) {
	tests := []policy.Rule{
		{Protocol: "tcp", Domain: "api.example.test", Port: 443, Path: "v1/**"},
		{Protocol: "tcp", Domain: "api.example.test", Port: 443, Methods: []string{"GE T"}},
		{Protocol: "tcp", Domain: "api.example.test", Port: 443, Methods: []string{"PROPFIND"}},
		{Protocol: "tcp", Domain: "api.example.test", Port: 443, Path: "/v1?debug=1"},
		{Protocol: "tcp", Domain: "api.example.test", Port: 443, Query: []policy.QueryParam{{Name: "ta*g", Value: "v1"}}},
		{Protocol: "tcp", Domain: "api.example.test", Port: 443, Query: []policy.QueryParam{{Name: "tag", Value: "["}}},
	}
	for _, rule := range tests {
		err := validatePolicy(policy.Policy{SandboxID: "http", Allow: []policy.Rule{rule}}, false)
		if err == nil {
			t.Fatalf("invalid HTTP conditions were accepted: %+v", rule)
		}
	}
}
