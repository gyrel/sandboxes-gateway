package gateway

import (
	"strconv"

	"github.com/gyrel/sandboxes-gateway/policy"
)

// gatewayEgressRule is the wire form of one egress policy rule for the gateway
// services API.
type gatewayEgressRule struct {
	ID       string `json:"id,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	CIDR     string `json:"cidr,omitempty"`
	Port     uint16 `json:"port,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

// gatewayEgressPolicy is the wire form of a per-sandbox egress policy for the
// gateway services API.
type gatewayEgressPolicy struct {
	Revision  string              `json:"revision"`
	SandboxID string              `json:"sandboxID"`
	AllowAny  bool                `json:"allowAny,omitempty"`
	Allow     []gatewayEgressRule `json:"allow,omitempty"`
	Deny      []gatewayEgressRule `json:"deny,omitempty"`
	AuditLog  string              `json:"auditLog,omitempty"`
	OpID      string              `json:"opID,omitempty"`
	ReqID     string              `json:"reqID,omitempty"`
}

func gatewayRule(rule policy.Rule) gatewayEgressRule {
	protocol := rule.Protocol
	if protocol == "" {
		protocol = protocolTCP
	}
	return gatewayEgressRule{ID: rule.ID, Protocol: protocol, CIDR: rule.CIDR, Port: rule.Port, Domain: rule.Domain}
}

// gatewayEgressPolicyFor maps a policy to the gateway's JSON wire form.
// Correlation ids are included only when they match the gateway's correlation
// charset and length; invalid ids are omitted rather than sanitized.
func gatewayEgressPolicyFor(p policy.Policy) gatewayEgressPolicy {
	allow := make([]gatewayEgressRule, 0, len(p.Allow))
	for i := range p.Allow {
		allow = append(allow, gatewayRule(p.Allow[i]))
	}
	deny := make([]gatewayEgressRule, 0, len(p.Deny))
	for i := range p.Deny {
		deny = append(deny, gatewayRule(p.Deny[i]))
	}
	egress := gatewayEgressPolicy{
		Revision:  strconv.Itoa(p.Revision),
		SandboxID: p.SandboxID,
		Allow:     allow,
		Deny:      deny,
		AuditLog:  p.AuditPath,
	}
	if validCorrelationID(p.OpID) {
		egress.OpID = p.OpID
	}
	if validCorrelationID(p.ReqID) {
		egress.ReqID = p.ReqID
	}
	return egress
}
