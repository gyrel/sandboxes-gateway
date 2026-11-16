package policy

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"sort"
	"strings"
)

// ErrRuleConflict reports two rules with the same selector but opposite
// actions in one policy scope. Deny precedence is still applied to policies
// that already contain such a pair, but new mutations are refused.
var ErrRuleConflict = errors.New("opposite policy rule conflict")

const (
	anyMethod = "ANY"
	anyPath   = "/**"

	// MaxHTTPRequestHeadBytes bounds the request-line prefix a datapath may
	// inspect before it must forward or reject the connection. ParseHTTPRequestHead
	// never reads a body.
	MaxHTTPRequestHeadBytes = 16 << 10

	// maxHTTPQueryParams bounds parsed query names to keep glob matching
	// predictable for a hostile request line.
	maxHTTPQueryParams = 256
)

// knownHTTPMethods mirrors the methods the sbx policy grammar accepts. HTTP
// methods are case-insensitive here because policy matching upper-cases them.
var knownHTTPMethods = map[string]struct{}{
	"GET": {}, "HEAD": {}, "POST": {}, "PUT": {}, "PATCH": {},
	"DELETE": {}, "OPTIONS": {}, "CONNECT": {}, "TRACE": {},
}

// QueryParam requires an HTTP query parameter with an exact name and a value
// that matches the supplied glob pattern.
type QueryParam struct {
	Name  string
	Value string
}

// ConflictError names both rules in an opposite-action selector conflict.
type ConflictError struct {
	Scope    string
	Existing Rule
	Incoming Rule
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf(
		"policy conflict in %s scope: %s rule %q (%s) conflicts with %s rule %q (%s)",
		scopeName(e.Scope),
		actionOrUnknown(e.Existing.Action), ruleName(e.Existing), describeRule(e.Existing),
		actionOrUnknown(e.Incoming.Action), ruleName(e.Incoming), describeRule(e.Incoming),
	)
}

// Unwrap lets callers classify the conflict with errors.Is.
func (e *ConflictError) Unwrap() error { return ErrRuleConflict }

func scopeName(scope string) string {
	if scope == "" {
		return "policy"
	}
	return scope
}

func actionOrUnknown(action Action) string {
	if action == "" {
		return "unknown"
	}
	return string(action)
}

func ruleName(rule Rule) string {
	if rule.ID != "" {
		return rule.ID
	}
	return describeRule(rule)
}

// HasHTTPConditions reports whether the rule restricts HTTP method, path or
// query. Such a rule only matches an HTTP request that satisfies every
// condition.
func (r Rule) HasHTTPConditions() bool {
	return len(r.Methods) > 0 || r.Path != "" || len(r.Query) > 0
}

// ParseMethods parses a comma-separated HTTP method list. Methods are exact
// and case-insensitive; ANY means every method but still keeps the rule in the
// HTTP condition set so it never matches a non-HTTP connection. An empty value
// means no method restriction. Unknown methods and empty list entries are
// rejected so a typo cannot create a rule that matches nothing.
func ParseMethods(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	seen := make(map[string]struct{})
	var methods []string
	sawAny := false
	for _, item := range strings.Split(raw, ",") {
		method := strings.ToUpper(strings.TrimSpace(item))
		if method == "" {
			return nil, errors.New("HTTP method list contains an empty entry")
		}
		if method == anyMethod {
			sawAny = true
			continue
		}
		if method == "*" || !validHTTPMethod(method) {
			return nil, fmt.Errorf("unknown HTTP method %q", item)
		}
		if _, ok := seen[method]; ok {
			continue
		}
		seen[method] = struct{}{}
		methods = append(methods, method)
	}
	if sawAny {
		return []string{anyMethod}, nil
	}
	sort.Strings(methods)
	return methods, nil
}

func validHTTPMethod(method string) bool {
	_, ok := knownHTTPMethods[method]
	return ok
}

// validHTTPToken accepts any RFC 9110 method token. Policy rules use the
// narrower known-method set, but a request may legitimately use an extension
// method that an ANY rule should still match.
func validHTTPToken(method string) bool {
	if method == "" {
		return false
	}
	for _, r := range method {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

// ParsePath validates an HTTP path glob and returns its canonical form. An
// empty path means /**, matching every request path. Per path segment, "*"
// matches any run of characters, "?" matches one character, and "[a-z]" or
// "[!a-z]" matches a character class. A segment that is exactly "**" matches
// zero or more path segments.
//
// A path must start with "/". Query strings, fragments, whitespace, escapes
// and ".." segments are rejected so a path cannot silently select a different
// request than the author intended.
func ParsePath(raw string) (string, error) {
	if raw == "" {
		return anyPath, nil
	}
	if raw != strings.TrimSpace(raw) {
		return "", fmt.Errorf("HTTP path %q contains leading or trailing whitespace", raw)
	}
	if !strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("HTTP path %q must start with /", raw)
	}
	if strings.ContainsAny(raw, "\\ \t\r\n?#") {
		return "", fmt.Errorf("HTTP path %q contains an escaped, whitespace, query or fragment character", raw)
	}
	if containsControl(raw) {
		return "", fmt.Errorf("HTTP path %q contains a control character", raw)
	}
	for _, segment := range strings.Split(strings.TrimPrefix(raw, "/"), "/") {
		if segment == ".." {
			return "", fmt.Errorf("HTTP path %q must not contain .. segments", raw)
		}
		if segment == "**" {
			continue
		}
		if _, err := path.Match(normalizeGlob(segment), ""); err != nil {
			return "", fmt.Errorf("invalid HTTP path glob %q: %w", raw, err)
		}
	}
	return raw, nil
}

// normalizeGlob accepts the sbx-style [!...] negated character class and
// converts it to the [^...] form understood by path.Match.
func normalizeGlob(pattern string) string {
	return strings.ReplaceAll(pattern, "[!", "[^")
}

// ParseQuery parses one required query parameter as name=value. The name is
// exact (no glob metacharacters); the value may use the same glob syntax as a
// single path segment. A parameter without "=" is rejected rather than stored
// as a rule that matches nothing.
func ParseQuery(raw string) (QueryParam, error) {
	raw = strings.TrimSpace(raw)
	name, value, ok := strings.Cut(raw, "=")
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if !ok || name == "" {
		return QueryParam{}, fmt.Errorf("query condition %q must be name=value", raw)
	}
	if err := validateQueryParam(name, value); err != nil {
		return QueryParam{}, fmt.Errorf("query condition %q: %w", raw, err)
	}
	return QueryParam{Name: name, Value: value}, nil
}

func validateQueryParam(name, value string) error {
	if name == "" {
		return errors.New("query name must be non-empty")
	}
	if strings.ContainsAny(name, "*?[\\ \t\r\n") || containsControl(name) {
		return errors.New("query name must be exact and must not contain glob, whitespace or control characters")
	}
	if strings.ContainsAny(value, "\\ \t\r\n") || containsControl(value) {
		return errors.New("query value contains an escaped, whitespace or control character")
	}
	if _, err := path.Match(normalizeGlob(value), ""); err != nil {
		return fmt.Errorf("invalid query value glob %q: %w", value, err)
	}
	return nil
}

func containsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// ParseQueryList parses repeated --query values.
func ParseQueryList(raw []string) ([]QueryParam, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]QueryParam, 0, len(raw))
	for _, item := range raw {
		query, err := ParseQuery(item)
		if err != nil {
			return nil, err
		}
		out = append(out, query)
	}
	return CanonicalQuery(out), nil
}

// CanonicalQuery de-duplicates query conditions while preserving their
// authored order. Query matching is a subset check, so order does not affect
// the decision, but keeping it makes rendered and audited rules stable.
func CanonicalQuery(query []QueryParam) []QueryParam {
	if len(query) == 0 {
		return nil
	}
	seen := make(map[QueryParam]struct{}, len(query))
	out := make([]QueryParam, 0, len(query))
	for _, item := range query {
		item.Name = strings.TrimSpace(item.Name)
		item.Value = strings.TrimSpace(item.Value)
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

// CanonicalMethods sorts and de-duplicates HTTP methods. Empty means no method
// restriction. ANY is kept as a single sentinel so an HTTP rule that accepts
// every method remains distinguishable from an unconditional transport rule.
func CanonicalMethods(methods []string) []string {
	if len(methods) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(methods))
	out := make([]string, 0, len(methods))
	for _, method := range methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			continue
		}
		if method == "*" || method == anyMethod {
			return []string{anyMethod}
		}
		if _, ok := seen[method]; ok {
			continue
		}
		seen[method] = struct{}{}
		out = append(out, method)
	}
	sort.Strings(out)
	return out
}

// ValidateHTTPConditions verifies that every condition is well formed. Callers
// fail closed when it returns an error.
func (r Rule) ValidateHTTPConditions() error {
	for _, authored := range r.Methods {
		method := strings.ToUpper(strings.TrimSpace(authored))
		if method == anyMethod {
			continue
		}
		if method == "" {
			return errors.New("HTTP method must not be empty")
		}
		if method == "*" || !validHTTPMethod(method) {
			return fmt.Errorf("unknown HTTP method %q", authored)
		}
	}
	if r.Path != "" {
		if _, err := ParsePath(r.Path); err != nil {
			return err
		}
	}
	for _, query := range r.Query {
		if err := validateQueryParam(query.Name, query.Value); err != nil {
			return fmt.Errorf("query condition %s=%s: %w", query.Name, query.Value, err)
		}
	}
	return nil
}

// SameSelector reports whether two rules select exactly the same traffic.
// Scope and action are deliberately excluded; callers compare rules within one
// scope.
func SameSelector(a, b Rule) bool {
	return selectorKey(a) == selectorKey(b)
}

// FindConflict returns the first rule in existing that has the same selector as
// incoming but the opposite action.
func FindConflict(existing []Rule, incoming Rule) *ConflictError {
	if incoming.Action != Allow && incoming.Action != Deny {
		return nil
	}
	for i := range existing {
		rule := &existing[i]
		if rule.Action != Allow && rule.Action != Deny {
			continue
		}
		if rule.Action == incoming.Action || !SameSelector(*rule, incoming) {
			continue
		}
		return &ConflictError{Existing: *rule, Incoming: incoming}
	}
	return nil
}

// CheckConflict refuses an opposite-action duplicate in one policy scope. Pass
// only rules from that scope; global and sandbox scopes compose independently.
func CheckConflict(scope string, existing []Rule, incoming Rule) error {
	conflict := FindConflict(existing, incoming)
	if conflict == nil {
		return nil
	}
	conflict.Scope = scope
	return conflict
}

func selectorKey(rule Rule) string {
	protocol := normalizedProtocol(rule.Protocol)
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule.Domain), "."))
	cidr := strings.TrimSpace(rule.CIDR)
	if prefix, err := parsePrefix(cidr); err == nil {
		cidr = prefix
	}
	methods := strings.Join(CanonicalMethods(rule.Methods), ",")
	rulePath := rule.Path
	if rulePath == "" {
		rulePath = anyPath
	}
	query := make([]string, 0, len(rule.Query))
	for _, item := range CanonicalQuery(rule.Query) {
		query = append(query, item.Name+"="+item.Value)
	}
	sort.Strings(query)
	return strings.Join([]string{
		protocol, domain, cidr, fmt.Sprint(rule.Port), methods, rulePath, strings.Join(query, "&"),
	}, "\x00")
}

func parsePrefix(cidr string) (string, error) {
	if cidr == "" {
		return "", errors.New("empty CIDR")
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", err
	}
	return prefix.Masked().String(), nil
}

func describeRule(rule Rule) string {
	var parts []string
	switch {
	case rule.Domain != "":
		parts = append(parts, rule.Domain)
	case rule.CIDR != "":
		parts = append(parts, rule.CIDR)
	default:
		parts = append(parts, "<empty selector>")
	}
	if len(rule.Methods) > 0 {
		parts = append(parts, strings.Join(CanonicalMethods(rule.Methods), ","))
	}
	if rule.Path != "" && rule.Path != anyPath {
		parts = append(parts, rule.Path)
	}
	for _, query := range CanonicalQuery(rule.Query) {
		parts = append(parts, query.Name+"="+query.Value)
	}
	if rule.Port != 0 {
		parts = append(parts, fmt.Sprintf("port %d", rule.Port))
	}
	return strings.Join(parts, " ")
}

func httpRequestMatches(rule Rule, protocol string, req Request) bool {
	if !rule.HasHTTPConditions() {
		return true
	}
	// HTTP conditions can only be evaluated from an HTTP request. A UDP or
	// otherwise non-HTTP flow must not fall through to an unconditional match.
	if protocol != protocolTCP {
		return false
	}
	if req.Method == "" && req.Path == "" && req.RawQuery == "" && len(req.Query) == 0 {
		return false
	}
	return methodMatches(rule.Methods, req.Method) &&
		pathMatches(rule.Path, req.Path) &&
		queryMatches(rule.Query, req)
}

func methodMatches(methods []string, requestMethod string) bool {
	methods = CanonicalMethods(methods)
	if len(methods) == 0 {
		return true
	}
	if len(methods) == 1 && methods[0] == anyMethod {
		return true
	}
	requestMethod = strings.ToUpper(strings.TrimSpace(requestMethod))
	if requestMethod == "" {
		return false
	}
	for _, method := range methods {
		if method == requestMethod {
			return true
		}
	}
	return false
}

func pathMatches(pattern, requestPath string) bool {
	if pattern == "" || pattern == anyPath {
		return true
	}
	if requestPath == "" {
		return false
	}
	patternSegments := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	requestSegments := strings.Split(strings.TrimPrefix(requestPath, "/"), "/")
	return matchPathSegments(patternSegments, requestSegments)
}

//nolint:gocognit // one recursive glob matcher is clearer than a state machine.
func matchPathSegments(pattern, request []string) bool {
	for len(pattern) > 0 {
		if pattern[0] == "**" {
			trimmed := pattern[1:]
			for len(trimmed) > 0 && trimmed[0] == "**" {
				trimmed = trimmed[1:]
			}
			if len(trimmed) == 0 {
				return true
			}
			for i := 0; i <= len(request); i++ {
				if matchPathSegments(trimmed, request[i:]) {
					return true
				}
			}
			return false
		}
		if len(request) == 0 {
			return false
		}
		ok, err := path.Match(normalizeGlob(pattern[0]), request[0])
		if err != nil || !ok {
			return false
		}
		pattern = pattern[1:]
		request = request[1:]
	}
	return len(request) == 0
}

func queryMatches(conditions []QueryParam, req Request) bool {
	if len(conditions) == 0 {
		return true
	}
	values := requestQuery(req)
	if len(values) == 0 {
		return false
	}
	for _, condition := range conditions {
		if !queryConditionMatches(condition, values) {
			return false
		}
	}
	return true
}

func queryConditionMatches(condition QueryParam, values map[string][]string) bool {
	// Query names are exact; only the value supports globs.
	for _, item := range values[condition.Name] {
		ok, err := path.Match(normalizeGlob(condition.Value), item)
		if err == nil && ok {
			return true
		}
	}
	return false
}

// ParseHTTPRequestHead parses the request line from a bounded HTTP/1.x request
// head. It reads no body and ignores headers after the first CRLF. The path is
// kept in its escaped form so percent-encoded separators cannot change which
// segment a glob matches. Callers that cannot supply a complete request line
// must treat the request as non-HTTP: a conditional rule then does not match.
func ParseHTTPRequestHead(head []byte) (Request, error) {
	if len(head) == 0 {
		return Request{}, errors.New("HTTP request head is empty")
	}
	if len(head) > MaxHTTPRequestHeadBytes {
		return Request{}, fmt.Errorf("HTTP request head exceeds %d bytes", MaxHTTPRequestHeadBytes)
	}
	lineEnd := bytes.IndexByte(head, '\n')
	if lineEnd < 0 {
		return Request{}, errors.New("HTTP request head has no complete request line")
	}
	method, target, err := parseHTTPRequestLine(bytes.TrimSuffix(head[:lineEnd], []byte{'\r'}))
	if err != nil {
		return Request{}, err
	}
	requestPath, rawQuery, query, err := parseHTTPRequestTarget(target)
	if err != nil {
		return Request{}, err
	}
	return Request{
		Protocol: protocolTCP,
		Method:   method,
		Path:     requestPath,
		Query:    query,
		RawQuery: rawQuery,
	}, nil
}

func parseHTTPRequestLine(line []byte) (method, target string, err error) {
	if len(line) == 0 {
		return "", "", errors.New("HTTP request line is empty")
	}
	if containsControl(string(line)) {
		return "", "", errors.New("HTTP request line contains a control character")
	}
	fields := strings.Split(string(line), " ")
	if len(fields) != 3 || fields[0] == "" || fields[1] == "" || !validHTTPVersion(fields[2]) {
		return "", "", errors.New("malformed HTTP request line")
	}
	method = strings.ToUpper(fields[0])
	if !validHTTPToken(method) {
		return "", "", fmt.Errorf("invalid HTTP request method %q", fields[0])
	}
	return method, fields[1], nil
}

func parseHTTPRequestTarget(target string) (requestPath, rawQuery string, query map[string][]string, err error) {
	if strings.Contains(target, "#") {
		return "", "", nil, fmt.Errorf("HTTP request target %q must not contain a fragment", target)
	}
	parsed, err := url.ParseRequestURI(target)
	if err != nil {
		return "", "", nil, fmt.Errorf("invalid HTTP request target: %w", err)
	}
	if parsed.Opaque != "" {
		return "", "", nil, fmt.Errorf("HTTP request target %q must not use an opaque form", target)
	}
	if parsed.Host != "" && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", "", nil, fmt.Errorf("unsupported absolute HTTP request target %q", target)
	}
	if parsed.Scheme != "" && parsed.Host == "" {
		return "", "", nil, fmt.Errorf("HTTP request target %q has a scheme but no host", target)
	}
	requestPath = parsed.EscapedPath()
	if !strings.HasPrefix(requestPath, "/") {
		return "", "", nil, fmt.Errorf("HTTP request path %q must start with /", requestPath)
	}
	query, err = url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return "", "", nil, fmt.Errorf("invalid HTTP request query: %w", err)
	}
	if len(query) > maxHTTPQueryParams {
		return "", "", nil, fmt.Errorf("HTTP request has more than %d query parameters", maxHTTPQueryParams)
	}
	return requestPath, parsed.RawQuery, query, nil
}

func validHTTPVersion(version string) bool {
	if !strings.HasPrefix(version, "HTTP/1.") || len(version) != len("HTTP/1.1") {
		return false
	}
	minor := version[len(version)-1]
	return minor >= '0' && minor <= '9'
}

func requestQuery(req Request) map[string][]string {
	out := make(map[string][]string, len(req.Query))
	for name, values := range req.Query {
		out[name] = append(out[name], values...)
	}
	if req.RawQuery != "" {
		if parsed, err := url.ParseQuery(req.RawQuery); err == nil {
			for name, values := range parsed {
				out[name] = append(out[name], values...)
			}
		}
	}
	return out
}
