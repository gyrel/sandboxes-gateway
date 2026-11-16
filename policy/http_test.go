package policy

import (
	"errors"
	"strings"
	"testing"
)

func TestParseHTTPConditions(t *testing.T) {
	methodTests := []struct {
		raw  string
		want []string
		ok   bool
	}{
		{"GET,HEAD", []string{"GET", "HEAD"}, true},
		{"get, head ,GET", []string{"GET", "HEAD"}, true},
		{"ANY", []string{"ANY"}, true},
		{"GET,ANY", []string{"ANY"}, true},
		{"", nil, true},
		{"GET,,POST", nil, false},
		{"*", nil, false},
		{"GE T", nil, false},
		{"PROPFIND", nil, false},
	}
	for _, tt := range methodTests {
		got, err := ParseMethods(tt.raw)
		if (err == nil) != tt.ok {
			t.Errorf("ParseMethods(%q) error = %v, ok=%v", tt.raw, err, tt.ok)
			continue
		}
		if tt.ok && strings.Join(got, ",") != strings.Join(tt.want, ",") {
			t.Errorf("ParseMethods(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}

	pathTests := []struct {
		raw  string
		want string
		ok   bool
	}{
		{"", "/**", true},
		{"/v1/**", "/v1/**", true},
		{"/repos/*/issues", "/repos/*/issues", true},
		{"/repos/[!1]/issues", "/repos/[!1]/issues", true},
		{"/a/**/z", "/a/**/z", true},
		{"v1/**", "", false},
		{"/v1/[", "", false},
		{`/v1/\*`, "", false},
		{"/v1?debug=1", "", false},
		{"/v1#fragment", "", false},
		{"/a/../b", "", false},
		{"/v1/a b", "", false},
	}
	for _, tt := range pathTests {
		got, err := ParsePath(tt.raw)
		if (err == nil) != tt.ok {
			t.Errorf("ParsePath(%q) error = %v, ok=%v", tt.raw, err, tt.ok)
			continue
		}
		if tt.ok && got != tt.want {
			t.Errorf("ParsePath(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}

	queryTests := []struct {
		raw  string
		want QueryParam
		ok   bool
	}{
		{"tag=v1", QueryParam{Name: "tag", Value: "v1"}, true},
		{"tag=v*", QueryParam{Name: "tag", Value: "v*"}, true},
		{"tag=", QueryParam{Name: "tag", Value: ""}, true},
		{"tag", QueryParam{}, false},
		{"=v1", QueryParam{}, false},
		{"ta g=v1", QueryParam{}, false},
		{"ta*g=v1", QueryParam{}, false},
		{"tag=[", QueryParam{}, false},
	}
	for _, tt := range queryTests {
		got, err := ParseQuery(tt.raw)
		if (err == nil) != tt.ok {
			t.Errorf("ParseQuery(%q) error = %v, ok=%v", tt.raw, err, tt.ok)
			continue
		}
		if tt.ok && got != tt.want {
			t.Errorf("ParseQuery(%q) = %+v, want %+v", tt.raw, got, tt.want)
		}
	}
}

func TestQueryConditionsPreserveOrder(t *testing.T) {
	got, err := ParseQueryList([]string{"b=2", "a=1", "b=2"})
	if err != nil {
		t.Fatal(err)
	}
	want := []QueryParam{{Name: "b", Value: "2"}, {Name: "a", Value: "1"}}
	if len(got) != len(want) {
		t.Fatalf("ParseQueryList() = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ParseQueryList() = %+v, want %+v", got, want)
		}
	}
}

func TestHTTPPathMatching(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"/**", "/", true},
		{"/**", "/v1/repos/42", true},
		{"/v1/**", "/v1", true},
		{"/v1/**", "/v1/repos", true},
		{"/v1/**", "/v2/repos", false},
		{"/repos/*/issues", "/repos/acme/issues", true},
		{"/repos/*/issues", "/repos/acme/pulls", false},
		{"/repos/*/issues", "/repos/acme/sub/issues", false},
		{"/a/**/z", "/a/z", true},
		{"/a/**/z", "/a/b/c/z", true},
		{"/a/**/z", "/a/b/c/y", false},
		{"/repos/[!1]/issues", "/repos/2/issues", true},
		{"/repos/[!1]/issues", "/repos/1/issues", false},
		{"/repos/[a-c]/issues", "/repos/b/issues", true},
	}
	for _, tt := range tests {
		if got := pathMatches(tt.pattern, tt.path); got != tt.want {
			t.Errorf("pathMatches(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestCheckHTTPConditionsAndDenyPrecedence(t *testing.T) {
	allow := []Rule{
		{ID: "read", Action: Allow, Protocol: "tcp", Domain: "api.example.test", Port: 443, Methods: []string{"GET", "HEAD"}, Path: "/v1/**"},
		{ID: "plain", Action: Allow, Protocol: "tcp", Domain: "plain.example.test", Port: 443},
	}
	deny := []Rule{
		{ID: "write", Action: Deny, Protocol: "tcp", Domain: "api.example.test", Port: 443, Methods: []string{"POST"}, Path: "/admin/**"},
		{ID: "token", Action: Deny, Protocol: "tcp", Domain: "api.example.test", Port: 443, Path: "/v1/**", Query: []QueryParam{{Name: "debug", Value: "1"}}},
	}
	tests := []struct {
		name string
		req  Request
		want bool
		rule string
	}{
		{"method and path allow", Request{Protocol: "tcp", Domain: "api.example.test", Port: 443, Method: "GET", Path: "/v1/repos"}, true, "read"},
		{"method mismatch", Request{Protocol: "tcp", Domain: "api.example.test", Port: 443, Method: "DELETE", Path: "/v1/repos"}, false, ""},
		{"path mismatch", Request{Protocol: "tcp", Domain: "api.example.test", Port: 443, Method: "GET", Path: "/v2/repos"}, false, ""},
		{"deny wins over matching allow", Request{Protocol: "tcp", Domain: "api.example.test", Port: 443, Method: "POST", Path: "/admin/users"}, false, "write"},
		{"deny query wins", Request{Protocol: "tcp", Domain: "api.example.test", Port: 443, Method: "GET", Path: "/v1/repos", RawQuery: "debug=1"}, false, "token"},
		{"query mismatch keeps allow", Request{Protocol: "tcp", Domain: "api.example.test", Port: 443, Method: "GET", Path: "/v1/repos", RawQuery: "debug=0"}, true, "read"},
		{"http rule does not match non-http", Request{Protocol: "tcp", Domain: "api.example.test", Port: 443}, false, ""},
		{"plain rule matches any request", Request{Protocol: "tcp", Domain: "plain.example.test", Port: 443, Method: "GET", Path: "/anything"}, true, "plain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Check(allow, deny, tt.req)
			if got.Allow != tt.want || got.RuleID != tt.rule {
				t.Fatalf("Check() = %+v, want allow=%v rule=%q", got, tt.want, tt.rule)
			}
		})
	}
}

func TestHTTPMethodCaseInsensitivityAndAny(t *testing.T) {
	allow := []Rule{
		{ID: "any-method", Action: Allow, Protocol: "tcp", Domain: "any.example.test", Port: 443, Methods: []string{"ANY"}},
		{ID: "get", Action: Allow, Protocol: "tcp", Domain: "get.example.test", Port: 443, Methods: []string{"GET"}},
		{ID: "path-only", Action: Allow, Protocol: "tcp", Domain: "path.example.test", Port: 443, Path: "/**"},
	}
	tests := []struct {
		name string
		req  Request
		rule string
	}{
		{"lower-case request method matches", Request{Protocol: "tcp", Domain: "get.example.test", Port: 443, Method: "get", Path: "/v1"}, "get"},
		{"ANY matches a concrete method", Request{Protocol: "tcp", Domain: "any.example.test", Port: 443, Method: "DELETE", Path: "/v1"}, "any-method"},
		{"ANY matches an extension method", Request{Protocol: "tcp", Domain: "any.example.test", Port: 443, Method: "PROPFIND", Path: "/v1"}, "any-method"},
		{"ANY does not match a non-HTTP flow", Request{Protocol: "tcp", Domain: "any.example.test", Port: 443}, ""},
		{"explicit path condition does not match a non-HTTP flow", Request{Protocol: "tcp", Domain: "path.example.test", Port: 443}, ""},
		{"explicit path condition matches an HTTP flow", Request{Protocol: "tcp", Domain: "path.example.test", Port: 443, Method: "GET", Path: "/v1"}, "path-only"},
		{"tcp HTTP rule does not match UDP", Request{Protocol: "udp", Domain: "get.example.test", Port: 443, Method: "GET", Path: "/v1"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Check(allow, nil, tt.req)
			if got.RuleID != tt.rule || got.Allow != (tt.rule != "") {
				t.Fatalf("Check() = %+v, want rule %q", got, tt.rule)
			}
		})
	}
}

func TestHTTPQueryConditionsAreOrderIndependentSubsets(t *testing.T) {
	allow := []Rule{{
		ID: "query", Action: Allow, Protocol: "tcp", Domain: "api.example.test", Port: 443,
		Query: []QueryParam{{Name: "tag", Value: "v*"}, {Name: "mode", Value: "read"}},
	}}
	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{"same order", "tag=v1&mode=read", true},
		{"different order with extra parameter", "extra=1&mode=read&tag=v2", true},
		{"missing required parameter", "tag=v1", false},
		{"value glob mismatch", "tag=other&mode=read", false},
		{"duplicate name matches any value", "tag=no&tag=v3&mode=read", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Check(allow, nil, Request{
				Protocol: "tcp", Domain: "api.example.test", Port: 443,
				Method: "GET", Path: "/v1", RawQuery: tt.query,
			})
			if got.Allow != tt.want {
				t.Fatalf("Check(query=%q) = %+v, want allow=%v", tt.query, got, tt.want)
			}
		})
	}
}

func TestHTTPQueryNameIsExact(t *testing.T) {
	allow := []Rule{{
		ID: "query", Action: Allow, Protocol: "tcp", Domain: "api.example.test", Port: 443,
		Query: []QueryParam{{Name: "tag", Value: "v*"}},
	}}
	got := Check(allow, nil, Request{
		Protocol: "tcp", Domain: "api.example.test", Port: 443,
		Method: "GET", Path: "/v1", RawQuery: "taX=v1",
	})
	if got.Allow {
		t.Fatalf("query name glob matched a different name: %+v", got)
	}
}

func TestParseHTTPRequestHead(t *testing.T) {
	tests := []struct {
		name    string
		head    string
		method  string
		path    string
		raw     string
		wantErr bool
	}{
		{"origin form", "GET /v1/repos?tag=v1 HTTP/1.1\r\nHost: api.example.test\r\n\r\n", "GET", "/v1/repos", "tag=v1", false},
		{"lower-case method is normalized", "get / HTTP/1.1\r\n\r\n", "GET", "/", "", false},
		{"absolute form", "POST http://api.example.test/v1?x=1 HTTP/1.0\r\n\r\n", "POST", "/v1", "x=1", false},
		{"escaped separator is preserved", "GET /a%2Fb HTTP/1.1\r\n\r\n", "GET", "/a%2Fb", "", false},
		{"missing request line terminator", "GET / HTTP/1.1", "", "", "", true},
		{"relative target", "GET v1 HTTP/1.1\r\n\r\n", "", "", "", true},
		{"asterisk target", "OPTIONS * HTTP/1.1\r\n\r\n", "", "", "", true},
		{"extension method", "PROPFIND / HTTP/1.1\r\n\r\n", "PROPFIND", "/", "", false},
		{"fragment target", "GET /v1#frag HTTP/1.1\r\n\r\n", "", "", "", true},
		{"bad version", "GET / HTTP/9.9\r\n\r\n", "", "", "", true},
		{"invalid query escape", "GET /?x=%ZZ HTTP/1.1\r\n\r\n", "", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := ParseHTTPRequestHead([]byte(tt.head))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseHTTPRequestHead() error = %v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if req.Protocol != "tcp" || req.Method != tt.method || req.Path != tt.path || req.RawQuery != tt.raw {
				t.Fatalf("ParseHTTPRequestHead() = %+v", req)
			}
		})
	}
	if _, err := ParseHTTPRequestHead(make([]byte, MaxHTTPRequestHeadBytes+1)); err == nil {
		t.Fatal("oversized request head was accepted")
	}
}

func TestUnparseableHTTPConditionsFailClosed(t *testing.T) {
	allow := []Rule{{ID: "bad", Action: Allow, Protocol: "tcp", Domain: "api.example.test", Port: 443, Path: "not-absolute"}}
	if err := ValidateEnforcement(allow, nil); err == nil {
		t.Fatal("unparseable path was accepted")
	}
	if got := Check(allow, nil, Request{Protocol: "tcp", Domain: "api.example.test", Port: 443, Method: "GET", Path: "/v1"}); got.Allow {
		t.Fatalf("unparseable condition allowed traffic: %+v", got)
	}
	badRules := []Rule{
		{ID: "bad-method", Action: Allow, Protocol: "tcp", Domain: "api.example.test", Port: 443, Methods: []string{"GE T"}},
		{ID: "unknown-method", Action: Allow, Protocol: "tcp", Domain: "api.example.test", Port: 443, Methods: []string{"PROPFIND"}},
		{ID: "empty-method", Action: Allow, Protocol: "tcp", Domain: "api.example.test", Port: 443, Methods: []string{""}},
		{ID: "bad-query-value", Action: Allow, Protocol: "tcp", Domain: "api.example.test", Port: 443, Query: []QueryParam{{Name: "tag", Value: "["}}},
		{ID: "bad-query-name", Action: Allow, Protocol: "tcp", Domain: "api.example.test", Port: 443, Query: []QueryParam{{Name: "ta*g", Value: "v1"}}},
		{ID: "dotdot-path", Action: Allow, Protocol: "tcp", Domain: "api.example.test", Port: 443, Path: "/a/../b"},
	}
	for _, rule := range badRules {
		if err := ValidateEnforcement([]Rule{rule}, nil); err == nil {
			t.Errorf("invalid HTTP conditions were accepted: %+v", rule)
		}
		if got := Check([]Rule{rule}, nil, Request{Protocol: "tcp", Domain: "api.example.test", Port: 443, Method: "GET", Path: "/"}); got.Allow {
			t.Errorf("invalid HTTP conditions allowed traffic: %+v", got)
		}
	}
}

func TestConflictDetectionMatrix(t *testing.T) {
	base := Rule{Action: Allow, Protocol: "tcp", Domain: "api.example.test", Port: 443, Methods: []string{"GET"}, Path: "/v1/**"}
	tests := []struct {
		name     string
		existing Rule
		incoming Rule
		conflict bool
	}{
		{"identical allow and deny", base, func() Rule { r := base; r.Action = Deny; return r }(), true},
		{"same action duplicate is not opposite", base, base, false},
		{"different method", base, func() Rule { r := base; r.Action = Deny; r.Methods = []string{"POST"}; return r }(), false},
		{"different path", base, func() Rule { r := base; r.Action = Deny; r.Path = "/v2/**"; return r }(), false},
		{"different query", base, func() Rule {
			r := base
			r.Action = Deny
			r.Query = []QueryParam{{Name: "debug", Value: "1"}}
			return r
		}(), false},
		{"query order is normalized", func() Rule {
			r := base
			r.Query = []QueryParam{{Name: "a", Value: "1"}, {Name: "b", Value: "2"}}
			return r
		}(), func() Rule {
			r := base
			r.Action = Deny
			r.Query = []QueryParam{{Name: "b", Value: "2"}, {Name: "a", Value: "1"}}
			return r
		}(), true},
		{"method order and case are normalized", base, func() Rule {
			r := base
			r.Action = Deny
			r.Methods = []string{"get", "HEAD"}
			return r
		}(), false},
		{"different port", base, func() Rule { r := base; r.Action = Deny; r.Port = 8443; return r }(), false},
		{"different domain", base, func() Rule { r := base; r.Action = Deny; r.Domain = "other.example.test"; return r }(), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckConflict("global", []Rule{tt.existing}, tt.incoming)
			if (err != nil) != tt.conflict {
				t.Fatalf("CheckConflict() = %v, conflict=%v", err, tt.conflict)
			}
			if !tt.conflict {
				return
			}
			if !errors.Is(err, ErrRuleConflict) {
				t.Fatalf("error %v does not wrap ErrRuleConflict", err)
			}
			var conflict *ConflictError
			if !errors.As(err, &conflict) {
				t.Fatalf("error %T is not *ConflictError", err)
			}
			if !strings.Contains(err.Error(), base.Domain) || !strings.Contains(err.Error(), "global") {
				t.Fatalf("error does not name the selector and scope: %v", err)
			}
		})
	}

	existing := []Rule{
		{ID: "allow-id", Action: Allow, Protocol: "tcp", Domain: "api.example.test", Port: 443},
	}
	incoming := Rule{ID: "deny-id", Action: Deny, Protocol: "tcp", Domain: "API.EXAMPLE.TEST.", Port: 443}
	err := CheckConflict("sandbox:one", existing, incoming)
	if err == nil {
		t.Fatal("normalized identical selector did not conflict")
	}
	for _, want := range []string{"allow-id", "deny-id", "sandbox:one"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("conflict error %q does not name %q", err, want)
		}
	}
}

func TestHTTPConditionSelectorsComposeAcrossScopes(t *testing.T) {
	global := []Rule{
		{ID: "global-allow", Action: Allow, Protocol: "tcp", Domain: "api.example.test", Port: 443, Methods: []string{"GET"}},
	}
	sandbox := []Rule{
		{ID: "sandbox-deny", Action: Deny, Protocol: "tcp", Domain: "api.example.test", Port: 443, Methods: []string{"GET"}},
	}
	if err := CheckConflict("global", global, global[0]); err != nil {
		t.Fatalf("duplicate same-scope rule rejected: %v", err)
	}
	if err := CheckConflict("sandbox", sandbox, sandbox[0]); err != nil {
		t.Fatalf("duplicate same-scope rule rejected: %v", err)
	}
	if got := Check(global, sandbox, Request{Protocol: "tcp", Domain: "api.example.test", Port: 443, Method: "GET", Path: "/"}); got.Allow || got.RuleID != "sandbox-deny" {
		t.Fatalf("deny precedence across composed scopes not applied: %+v", got)
	}
}
