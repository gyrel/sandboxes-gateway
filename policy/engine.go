package policy

import (
	"net/netip"
	"strings"
	"sync/atomic"
)

// Snapshot represents an immutable evaluation snapshot with strict precedence layers:
// OrgDeny > LocalDeny > OrgAllow > LocalAllow > DefaultDeny.
type Snapshot struct {
	OrgDeny    []Rule
	LocalDeny  []Rule
	OrgAllow   []Rule
	LocalAllow []Rule
}

// Engine evaluates authorization requests against atomically updated policy snapshots
// with deterministic fail-closed guarantees.
type Engine struct {
	current atomic.Pointer[Snapshot]
}

// NewEngine constructs a new policy Engine. If an initial snapshot is provided,
// it is loaded immediately.
func NewEngine(initial *Snapshot) *Engine {
	e := &Engine{}
	if initial != nil {
		clone := *initial
		e.current.Store(&clone)
	}
	return e
}

// Update atomically replaces the active policy snapshot.
func (e *Engine) Update(snap Snapshot) {
	clone := snap
	e.current.Store(&clone)
}

// Evaluate evaluates req against the active policy snapshot using strict precedence:
// 1. If unconfigured, fails closed (Decision.Allow = false).
// 2. Evaluates Org Deny rules.
// 3. Evaluates Local Deny rules.
// 4. Evaluates Org Allow rules (if present).
// 5. Evaluates Local Allow rules.
// 6. If no rule matches, returns fail-closed Default Deny.
func (e *Engine) Evaluate(req Request) Decision {
	snap := e.current.Load()
	if snap == nil {
		return Decision{Allow: false, Reason: "policy engine unconfigured"}
	}

	allDeny := append(append([]Rule(nil), snap.OrgDeny...), snap.LocalDeny...)
	allAllow := append(append([]Rule(nil), snap.OrgAllow...), snap.LocalAllow...)

	if err := ValidateEnforcement(allAllow, allDeny); err != nil {
		return Decision{Allow: false, Reason: "policy validation failed: " + err.Error()}
	}

	if decision, rejected := validateRequestAddresses(req); rejected {
		return decision
	}

	protocol := strings.ToLower(strings.TrimSpace(req.Protocol))
	if protocol == "" {
		protocol = protocolTCP
	}

	// Strict precedence evaluation layers
	layers := []struct {
		rules  []Rule
		allow  bool
		prefix string
	}{
		{snap.OrgDeny, false, "org deny rule "},
		{snap.LocalDeny, false, "local deny rule "},
		{snap.OrgAllow, true, "org allow rule "},
		{snap.LocalAllow, true, "local allow rule "},
	}

	for _, layer := range layers {
		if decision, matched := matchRuleGroup(layer.rules, protocol, req, layer.prefix, layer.allow); matched {
			return decision
		}
	}

	return Decision{Allow: false, Reason: "default deny"}
}

func validateRequestAddresses(req Request) (Decision, bool) {
	if len(req.DNSAnswers) > 0 {
		if err := ValidateDNSAnswers(req.DNSAnswers); err != nil {
			return Decision{Allow: false, Reason: "DNS answer validation failed: " + err.Error()}, true
		}
	}

	if req.Domain != "" && req.Address != "" {
		if addr, err := netip.ParseAddr(strings.TrimSpace(req.Address)); err == nil {
			if !IsPublicAddress(addr) {
				return Decision{Allow: false, Reason: "resolved domain address is non-public"}, true
			}
		}
	}

	return Decision{}, false
}

func matchRuleGroup(rules []Rule, protocol string, req Request, prefix string, allow bool) (Decision, bool) {
	for i := range rules {
		if ruleMatches(rules[i], protocol, req) {
			return Decision{Allow: allow, RuleID: rules[i].ID, Reason: prefix + target(rules[i])}, true
		}
	}
	return Decision{}, false
}
