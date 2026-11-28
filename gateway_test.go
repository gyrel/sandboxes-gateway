package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gyrel/sandboxes-gateway/policy"
)

func TestRenderConfig(t *testing.T) {
	cfg := renderConfig(policy.Policy{
		Revision:  2,
		SandboxID: "dev",
		AuditPath: "/tmp/dev.audit.jsonl",
		Allow: []policy.Rule{
			{ID: "rul_allow_cidr", Protocol: "tcp", Domain: "api.example.test", Port: 443},
			{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443},
		},
		Deny: []policy.Rule{
			{Protocol: "udp", CIDR: "10.1.0.0/16", Port: 53},
		},
		Ports: []policy.Port{{Host: 8080, Guest: 3000}},
	}, "1.1.1.1:53", false)
	for _, want := range []string{
		"egressPolicy:",
		`revision: "2"`,
		`sandboxID: "dev"`,
		`auditLog: "/tmp/dev.audit.jsonl"`,
		"    allow:",
		`cidr: "10.0.0.0/8"`,
		`id: "rul_allow_cidr"`,
		`domain: "api.example.test"`,
		"    deny:",
		`protocol: "udp"`,
		`"127.0.0.1:8080": "192.168.127.3:3000"`,
		`dnsUpstream: "1.1.1.1:53"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("missing %q in config:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "ipv6Enabled:") {
		t.Fatal("IPv6 must remain disabled by default")
	}
	if strings.Contains(cfg, ipv6HostServicesGuest) {
		t.Fatal("IPv6 host-services NAT entry must remain disabled by default")
	}
}

func TestRenderConfigEnablesExperimentalIPv6Explicitly(t *testing.T) {
	cfg := renderConfig(policy.Policy{Revision: 1, SandboxID: "ipv6"}, "", true)
	if !strings.Contains(cfg, "  ipv6Enabled: true\n") {
		t.Fatalf("explicit IPv6 config missing:\n%s", cfg)
	}
	if !strings.Contains(cfg, "  nat:\n    192.168.127.254: 127.0.0.1\n") {
		t.Fatalf("IPv4 host-services NAT entry missing:\n%s", cfg)
	}
	wantNAT := "    \"" + ipv6HostServicesGuest + "\": \"" + ipv6HostServicesHost + "\"\n"
	if !strings.Contains(cfg, wantNAT) {
		t.Fatalf("explicit IPv6 host-services NAT entry %q missing:\n%s", wantNAT, cfg)
	}
	if got := strings.Count(cfg, ipv6HostServicesGuest); got != 1 {
		t.Fatalf("IPv6 host-services NAT entry rendered %d times, want 1:\n%s", got, cfg)
	}
	manager, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir(), IPv6Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if !manager.IPv6Enabled() {
		t.Fatal("manager failed to report explicit IPv6 capability")
	}
}

func TestIPv6HostServicesNATAddressDiscipline(t *testing.T) {
	guest := net.ParseIP(ipv6HostServicesGuest)
	if guest == nil || guest.To4() != nil {
		t.Fatalf("host-services guest address %q is not a global-shape IPv6 address", ipv6HostServicesGuest)
	}
	_, guestPrefix, err := net.ParseCIDR("fd72:6865:6963::/64")
	if err != nil {
		t.Fatal(err)
	}
	if guestPrefix.Contains(guest) {
		t.Fatalf("host-services address %s must stay outside the guest /64", ipv6HostServicesGuest)
	}
	_, ula, err := net.ParseCIDR("fc00::/7")
	if err != nil {
		t.Fatal(err)
	}
	if !ula.Contains(guest) {
		t.Fatalf("host-services address %s is not an IPv6 ULA", ipv6HostServicesGuest)
	}
	host := net.ParseIP(ipv6HostServicesHost)
	if host == nil || !host.IsLoopback() {
		t.Fatalf("host-services destination %q is not host loopback", ipv6HostServicesHost)
	}
}

func TestRenderConfigSupportsLoopbackIPv6AndUDP(t *testing.T) {
	cfg := renderConfig(policy.Policy{
		Revision:  3,
		SandboxID: "dev6",
		Ports: []policy.Port{
			{Host: 8080, Guest: 3000, Proto: "tcp", HostIP: "::1"},
			{Host: 8081, Guest: 3001, Proto: "udp", HostIP: "127.0.0.1"},
		},
	}, "", true)
	for _, want := range []string{`"[::1]:8080": "guest-ipv6:3000"`, `"udp:127.0.0.1:8081": "192.168.127.3:3001"`} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("missing %q in config:\n%s", want, cfg)
		}
	}
}

func TestDesiredForwardsKeysIncludeHostIP(t *testing.T) {
	forwards := desiredForwards([]policy.Port{
		{Host: 8080, Guest: 3000, Proto: "tcp"},
		{Host: 8080, Guest: 3001, Proto: "tcp", HostIP: "::1"},
		{Host: 8080, Guest: 3002, Proto: "udp", HostIP: "::1"},
	})
	if len(forwards) != 3 {
		t.Fatalf("forwards=%+v", forwards)
	}
	if forwards["tcp|127.0.0.1:8080"].Remote != "192.168.127.3:3000" || forwards["tcp|[::1]:8080"].Remote != "guest-ipv6:3001" || forwards["udp|[::1]:8080"].Remote != "guest-ipv6:3002" {
		t.Fatalf("forwards=%+v", forwards)
	}
}

func TestValidateGitDaemonForward(t *testing.T) {
	tests := []struct {
		name    string
		forward forwardAPI
		wantErr bool
	}{
		{name: "valid", forward: forwardAPI{Local: "127.0.0.1:49152", Remote: gitDaemonRemote, Protocol: protocolTCP}},
		{name: "public bind", forward: forwardAPI{Local: "0.0.0.0:49152", Remote: gitDaemonRemote, Protocol: protocolTCP}, wantErr: true},
		{name: "IPv6 loopback", forward: forwardAPI{Local: "[::1]:49152", Remote: gitDaemonRemote, Protocol: protocolTCP}, wantErr: true},
		{name: "unassigned port", forward: forwardAPI{Local: "127.0.0.1:0", Remote: gitDaemonRemote, Protocol: protocolTCP}, wantErr: true},
		{name: "wrong guest", forward: forwardAPI{Local: "127.0.0.1:49152", Remote: "192.168.127.3:22", Protocol: protocolTCP}, wantErr: true},
		{name: "wrong protocol", forward: forwardAPI{Local: "127.0.0.1:49152", Remote: gitDaemonRemote, Protocol: protocolUDP}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			port, err := validateGitDaemonForward(test.forward)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateGitDaemonForward(%+v) error = %v", test.forward, err)
			}
			if !test.wantErr && port != 49152 {
				t.Fatalf("allocated port = %d, want 49152", port)
			}
		})
	}
}

func TestAddManagedGitForwardRejectsCollision(t *testing.T) {
	managed := forwardAPI{Local: "127.0.0.1:49152", Remote: gitDaemonRemote, Protocol: protocolTCP}
	desired := map[string]forwardAPI{
		forwardKey(protocolTCP, managed.Local): {Local: managed.Local, Remote: "192.168.127.3:8080", Protocol: protocolTCP},
	}
	if err := addManagedGitForward(desired, managed); err == nil {
		t.Fatal("colliding host port was accepted")
	}
	if got := desired[forwardKey(protocolTCP, managed.Local)].Remote; got != "192.168.127.3:8080" {
		t.Fatalf("existing mapping was overwritten: remote=%q", got)
	}
}

func TestTrackedGitForwardRejectsReplacedGatewayProcess(t *testing.T) {
	stale := forwardAPI{Local: "127.0.0.1:49152", Remote: gitDaemonRemote, Protocol: protocolTCP}
	oldProcess := process{cmd: &exec.Cmd{}, gitForward: &stale, forwardMu: &sync.Mutex{}}
	newProcess := process{cmd: &exec.Cmd{}, forwardMu: &sync.Mutex{}}
	manager := &Manager{procs: map[string]process{"fixture": newProcess}}
	if _, err := manager.trackedGitForward("fixture", oldProcess); err == nil {
		t.Fatal("stale process handle was allowed to reuse Git forward ownership")
	}
	if manager.procs["fixture"].gitForward != nil {
		t.Fatal("replacement gateway inherited the previous process Git forward")
	}
}

type forwardAPIFixture struct {
	mu                     sync.Mutex
	forwards               []forwardAPI
	response               forwardAPI
	replacementAfterRemove *forwardAPI
	unexposeErr            bool
	listErrAfterUnexposure bool
	unexposeCount          int
}

func (f *forwardAPIFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/services/forwarder/all":
		if f.listErrAfterUnexposure && f.unexposeCount > 0 {
			http.Error(w, "verification unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.forwards)
	case "/services/forwarder/expose-git-daemon":
		f.forwards = append(f.forwards, f.response)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.response)
	case "/services/forwarder/unexpose":
		f.unexposeCount++
		if f.unexposeErr {
			http.Error(w, "unexpose unavailable", http.StatusServiceUnavailable)
			return
		}
		var request forwardAPI
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		retained := f.forwards[:0]
		for _, forward := range f.forwards {
			if forward.Local != request.Local || normalizeForwardProtocol(forward.Protocol) != normalizeForwardProtocol(request.Protocol) {
				retained = append(retained, forward)
			}
		}
		f.forwards = retained
		if f.replacementAfterRemove != nil {
			f.forwards = append(f.forwards, *f.replacementAfterRemove)
		}
		w.WriteHeader(http.StatusOK)
	case "/services/forwarder/expose":
		var request forwardAPI
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		f.forwards = append(f.forwards, request)
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}

func newForwardAPIFixture(t *testing.T, response forwardAPI) (*Manager, *forwardAPIFixture) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gw-fwd-")
	if err != nil {
		t.Fatal(err)
	}
	apiPath := filepath.Join(dir, "api.sock")
	listener, err := net.Listen("unix", apiPath)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatal(err)
	}
	fixture := &forwardAPIFixture{response: response}
	server := &http.Server{Handler: fixture}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		_ = os.RemoveAll(dir)
	})
	manager := &Manager{
		procs: map[string]process{
			"fixture": {
				cmd:       &exec.Cmd{},
				done:      closedSignal(),
				apiSocket: apiPath,
				lease:     io.NopCloser(strings.NewReader("")),
				forwardMu: &sync.Mutex{},
			},
		},
		starting: make(map[string]chan struct{}),
	}
	return manager, fixture
}

func closedSignal() chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}

func TestSetGitDaemonAllocatesVerifiesAndWithdrawsOwnedForward(t *testing.T) {
	want := forwardAPI{Local: "127.0.0.1:49152", Remote: gitDaemonRemote, Protocol: protocolTCP}
	manager, fixture := newForwardAPIFixture(t, want)
	port, err := manager.SetGitDaemon(context.Background(), "fixture", true)
	if err != nil || port != 49152 {
		t.Fatalf("SetGitDaemon(enable) = %d, %v; want 49152, nil", port, err)
	}

	if err := manager.SetPorts(context.Background(), "fixture", nil); err != nil {
		t.Fatalf("SetPorts removed managed Git forward: %v", err)
	}
	if got := manager.procs["fixture"].gitForward; got == nil || *got != want {
		t.Fatalf("tracked Git forward = %+v, want %+v", got, want)
	}

	if _, err := manager.SetGitDaemon(context.Background(), "fixture", false); err != nil {
		t.Fatalf("SetGitDaemon(disable): %v", err)
	}
	fixture.mu.Lock()
	remaining := append([]forwardAPI(nil), fixture.forwards...)
	fixture.mu.Unlock()
	if len(remaining) != 0 {
		t.Fatalf("forwards remain after owned unpublish: %+v", remaining)
	}
	if got := manager.procs["fixture"].gitForward; got != nil {
		t.Fatalf("owned Git forward remains tracked after unpublish: %+v", *got)
	}
}

func TestSetGitDaemonRejectsWrongGuestAndCleansAllocatedLoopback(t *testing.T) {
	wrong := forwardAPI{Local: "127.0.0.1:49152", Remote: "192.168.127.3:22", Protocol: protocolTCP}
	manager, fixture := newForwardAPIFixture(t, wrong)
	if _, err := manager.SetGitDaemon(context.Background(), "fixture", true); err == nil {
		t.Fatal("wrong guest endpoint was accepted")
	}
	fixture.mu.Lock()
	remaining := append([]forwardAPI(nil), fixture.forwards...)
	fixture.mu.Unlock()
	if len(remaining) != 0 {
		t.Fatalf("unexpected listener was not withdrawn: %+v", remaining)
	}
}

func TestSetGitDaemonUnpublishFailureStopsOwnedGateway(t *testing.T) {
	assertFailureStopsOwnedGateway(t, func(fixture *forwardAPIFixture) {
		fixture.unexposeErr = true
	})
}

func TestSetGitDaemonUnpublishVerificationFailureStopsOwnedGateway(t *testing.T) {
	assertFailureStopsOwnedGateway(t, func(fixture *forwardAPIFixture) {
		fixture.listErrAfterUnexposure = true
	})
}

func TestSetGitDaemonMismatchedListenerAfterUnpublishStopsOwnedGateway(t *testing.T) {
	assertFailureStopsOwnedGateway(t, func(fixture *forwardAPIFixture) {
		mismatched := forwardAPI{Local: "127.0.0.1:49152", Remote: "192.168.127.3:22", Protocol: protocolTCP}
		fixture.replacementAfterRemove = &mismatched
	})
}

func TestSetGitDaemonCleanupLeavesReplacementGatewayUntouched(t *testing.T) {
	want := forwardAPI{Local: "127.0.0.1:49152", Remote: gitDaemonRemote, Protocol: protocolTCP}
	manager, fixture := newForwardAPIFixture(t, want)
	if _, err := manager.SetGitDaemon(context.Background(), "fixture", true); err != nil {
		t.Fatalf("SetGitDaemon(enable): %v", err)
	}
	fixture.unexposeErr = true
	replacement := process{cmd: &exec.Cmd{}, done: closedSignal(), forwardMu: &sync.Mutex{}}
	manager.procs["fixture"] = process{
		cmd:        manager.procs["fixture"].cmd,
		done:       closedSignal(),
		apiSocket:  manager.procs["fixture"].apiSocket,
		forwardMu:  manager.procs["fixture"].forwardMu,
		gitForward: manager.procs["fixture"].gitForward,
		lease: callbackCloser{callback: func() {
			manager.mu.Lock()
			manager.procs["fixture"] = replacement
			manager.mu.Unlock()
		}},
	}
	old := manager.procs["fixture"]
	if _, err := manager.SetGitDaemon(context.Background(), "fixture", false); err == nil {
		t.Fatal("SetGitDaemon(disable) succeeded despite unexpose failure")
	}
	manager.mu.Lock()
	got := manager.procs["fixture"]
	manager.mu.Unlock()
	if got.cmd != replacement.cmd {
		t.Fatalf("replacement process was modified: got cmd %p, want %p (old=%p)", got.cmd, replacement.cmd, old.cmd)
	}
}

type callbackCloser struct{ callback func() }

func (c callbackCloser) Close() error {
	c.callback()
	return nil
}

func assertFailureStopsOwnedGateway(t *testing.T, configure func(*forwardAPIFixture)) {
	t.Helper()
	want := forwardAPI{Local: "127.0.0.1:49152", Remote: gitDaemonRemote, Protocol: protocolTCP}
	manager, fixture := newForwardAPIFixture(t, want)
	if _, err := manager.SetGitDaemon(context.Background(), "fixture", true); err != nil {
		t.Fatalf("SetGitDaemon(enable): %v", err)
	}
	configure(fixture)
	if _, err := manager.SetGitDaemon(context.Background(), "fixture", false); err == nil {
		t.Fatal("SetGitDaemon(disable) succeeded despite uncertain unpublish state")
	}
	manager.mu.Lock()
	_, stillOwned := manager.procs["fixture"]
	manager.mu.Unlock()
	if stillOwned {
		t.Fatal("gateway process remained running after uncertain Git listener cleanup")
	}
}

func TestApplyForwardDiffReplacesStaleRemoteAtSameLocal(t *testing.T) {
	correct := forwardAPI{Local: "127.0.0.1:49153", Remote: "192.168.127.3:8080", Protocol: protocolTCP}
	wrong := forwardAPI{Local: correct.Local, Remote: "192.168.127.3:22", Protocol: protocolTCP}
	manager, fixture := newForwardAPIFixture(t, correct)
	fixture.forwards = []forwardAPI{wrong}
	if err := applyForwardDiffAuth(context.Background(), manager.procs["fixture"].apiSocket, "", []forwardAPI{wrong}, map[string]forwardAPI{forwardKey(correct.Protocol, correct.Local): correct}); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	got := append([]forwardAPI(nil), fixture.forwards...)
	fixture.mu.Unlock()
	if len(got) != 1 || got[0] != correct {
		t.Fatalf("reconciled forwards = %+v, want %+v", got, correct)
	}
}

func TestStartDoesNotRemoveExistingSocketPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dev.sock")
	if err := os.WriteFile(path, []byte("owned elsewhere"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := New(Config{GVProxy: "/bin/true", RunDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(context.Background(), policy.Policy{SandboxID: "dev"}); err == nil {
		t.Fatal("start accepted an existing socket path")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "owned elsewhere" {
		t.Fatalf("existing file changed: %q, %v", data, err)
	}
}

func TestGatewayFilesRejectLinksWithoutChangingTargets(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		link func(string, string) error
	}{
		{"symlink", os.Symlink},
		{"hardlink", os.Link},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := tc.link(target, path); err != nil {
				t.Fatal(err)
			}
			if err := writeConfig(path, policy.Policy{SandboxID: "dev"}, "", false, false); err == nil {
				t.Fatal("linked config accepted")
			}
			data, err := os.ReadFile(target)
			if err != nil || string(data) != "unchanged" {
				t.Fatalf("target changed: %q, %v", data, err)
			}
		})
	}
	path := filepath.Join(dir, "valid.yaml")
	if err := writeConfig(path, policy.Policy{SandboxID: "dev"}, "", false, false); err != nil {
		t.Fatalf("private regular config rejected: %v", err)
	}
}

func TestMACDeterministic(t *testing.T) {
	first := MAC("dev")
	second := MAC("dev")
	if first != second {
		t.Fatal("MAC must be deterministic")
	}
	if MAC("dev") == MAC("prod") {
		t.Fatal("different sandboxes need different MACs")
	}
}

func TestValidatePolicyFailsClosedForUnsupportedRules(t *testing.T) {
	tests := []struct {
		name string
		rule policy.Rule
	}{
		{name: "domain and cidr", rule: policy.Rule{Protocol: "tcp", Domain: "registry.example", CIDR: "192.0.2.0/24", Port: 443}},
		{name: "invalid domain", rule: policy.Rule{Protocol: "tcp", Domain: "*", Port: 443}},
		{name: "unterminated domain glob", rule: policy.Rule{Protocol: "tcp", Domain: "api[1.example.test", Port: 443}},
		{name: "empty domain glob", rule: policy.Rule{Protocol: "tcp", Domain: "api[!].example.test", Port: 443}},
		{name: "missing cidr", rule: policy.Rule{Protocol: "tcp", Port: 443}},
		{name: "invalid cidr", rule: policy.Rule{Protocol: "tcp", CIDR: "registry.example", Port: 443}},
		{name: "ambiguous mapped cidr", rule: policy.Rule{Protocol: "tcp", CIDR: "::ffff:0:0/95", Port: 443}},
		{name: "invalid protocol", rule: policy.Rule{Protocol: "icmp", CIDR: "192.0.2.1/32"}},
		{name: "ip literal as domain", rule: policy.Rule{Protocol: "tcp", Domain: "192.0.2.10", Port: 443}},
		{name: "unverified UDP domain", rule: policy.Rule{Protocol: "udp", Domain: "h3.example.test", Port: 443}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validatePolicy(policy.Policy{Allow: []policy.Rule{tt.rule}}, false); err == nil {
				t.Fatal("unsupported policy must be rejected")
			}
		})
	}
}

func TestIPv6HostForwardRequiresExplicitCapability(t *testing.T) {
	ports := []policy.Port{{Host: 8080, Guest: 3000, Proto: "tcp", HostIP: "::1"}}
	if err := validateIPv6PortCapability(ports, false); err == nil {
		t.Fatal("IPv6 host forward accepted while the capability is disabled")
	}
	if err := validateIPv6PortCapability(ports, true); err != nil {
		t.Fatalf("explicit IPv6 host forward rejected: %v", err)
	}
	path := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := writeConfig(path, policy.Policy{SandboxID: "ipv6", Ports: ports}, "", false, false); err == nil {
		t.Fatal("disabled IPv6 host forward was rendered")
	}
	if err := writeConfig(path, policy.Policy{SandboxID: "ipv6", Ports: ports}, "", true, false); err != nil {
		t.Fatalf("explicit IPv6 host forward rejected: %v", err)
	}
}

func TestValidatePolicyPortsValidatesShapeNotBindPolicy(t *testing.T) {
	tests := []struct {
		name    string
		port    policy.Port
		wantErr string
	}{
		{name: "ipv4 loopback", port: policy.Port{Host: 8080, Guest: 3000, Proto: "tcp", HostIP: "127.0.0.1"}},
		{name: "ipv6 loopback", port: policy.Port{Host: 8080, Guest: 3000, Proto: "tcp", HostIP: "::1"}},
		{name: "specific non-loopback ipv4", port: policy.Port{Host: 8080, Guest: 3000, Proto: "tcp", HostIP: "100.64.0.8"}},
		{name: "specific non-loopback ipv6", port: policy.Port{Host: 8080, Guest: 3000, Proto: "tcp", HostIP: "2001:db8::8"}},
		{name: "empty host ip", port: policy.Port{Host: 8080, Guest: 3000, Proto: "tcp"}},
		{name: "udp protocol", port: policy.Port{Host: 8080, Guest: 3000, Proto: "udp", HostIP: "100.64.0.8"}},
		{name: "invalid host ip", port: policy.Port{Host: 8080, Guest: 3000, Proto: "tcp", HostIP: "not-an-ip"}, wantErr: "invalid host IP"},
		{name: "unspecified ipv4", port: policy.Port{Host: 8080, Guest: 3000, Proto: "tcp", HostIP: "0.0.0.0"}, wantErr: "specific address"},
		{name: "unspecified ipv6", port: policy.Port{Host: 8080, Guest: 3000, Proto: "tcp", HostIP: "::"}, wantErr: "specific address"},
		{name: "sctp protocol", port: policy.Port{Host: 8080, Guest: 3000, Proto: "sctp", HostIP: "127.0.0.1"}, wantErr: "protocol must be tcp or udp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePolicyPorts([]policy.Port{tt.port})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validatePolicyPorts(%+v) error = %v", tt.port, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validatePolicyPorts(%+v) accepted; want error containing %q", tt.port, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validatePolicyPorts(%+v) error = %q; want containing %q", tt.port, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePolicyPortsPassesSpecificAddressToForwarder(t *testing.T) {
	ports := []policy.Port{{Host: 8080, Guest: 3000, Proto: "tcp", HostIP: "100.64.0.8"}}
	if err := validatePolicyPorts(ports); err != nil {
		t.Fatalf("specific non-loopback address rejected: %v", err)
	}
	forwards := desiredForwards(ports)
	if got := forwards["tcp|100.64.0.8:8080"].Local; got != "100.64.0.8:8080" {
		t.Fatalf("forward local = %q, want specific non-loopback bind passed through", got)
	}
}

func TestIPv6CIDRRuleRequiresExplicitCapability(t *testing.T) {
	rules := []policy.Rule{{Protocol: "tcp", CIDR: "2001:db8::/32", Port: 443}}
	if err := validateIPv6RuleCapability(rules, nil, false); err == nil {
		t.Fatal("IPv6 CIDR accepted while the capability is disabled")
	}
	if err := validateIPv6RuleCapability(rules, nil, true); err != nil {
		t.Fatalf("explicit IPv6 CIDR rejected: %v", err)
	}
	if err := validateIPv6RuleCapability([]policy.Rule{{Protocol: "tcp", CIDR: "192.0.2.0/24", Port: 443}}, nil, false); err != nil {
		t.Fatalf("IPv4 CIDR rejected: %v", err)
	}
	path := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := writeConfig(path, policy.Policy{SandboxID: "ipv6", Allow: rules}, "", false, false); err == nil {
		t.Fatal("disabled IPv6 CIDR rule was rendered")
	}
	cfg, err := os.ReadFile(path)
	if err == nil && strings.Contains(string(cfg), "2001:db8::/32") {
		t.Fatal("disabled IPv6 CIDR rule reached the gateway config")
	}
	if err := writeConfig(path, policy.Policy{SandboxID: "ipv6", Allow: rules}, "", true, false); err != nil {
		t.Fatalf("explicit IPv6 CIDR rule rejected: %v", err)
	}
	cfg, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), `"2001:db8::/32"`) {
		t.Fatalf("IPv6 CIDR rule missing from config:\n%s", cfg)
	}
}

func TestValidatePolicyRejectsDomainDenyOverlappingIPAllow(t *testing.T) {
	p := policy.Policy{
		Allow: []policy.Rule{{Protocol: "tcp", CIDR: "192.0.2.0/24", Port: 443}},
		Deny:  []policy.Rule{{Protocol: "tcp", Domain: "blocked.example.test", Port: 443}},
	}
	if err := validatePolicy(p, false); err == nil {
		t.Fatal("overlapping domain deny and IP allow accepted")
	}
	p.Allow[0].Port = 8443
	if err := validatePolicy(p, false); err != nil {
		t.Fatalf("non-overlapping positive control rejected: %v", err)
	}
}

func TestDomainPolicyRenderAndUpstreamRequirement(t *testing.T) {
	cfg := renderConfig(policy.Policy{
		Revision: 4, SandboxID: "domains",
		Allow: []policy.Rule{{Protocol: "tcp", Domain: "*.example.com", Port: 443}},
	}, "1.1.1.1:53", false)
	if !strings.Contains(cfg, `domain: "*.example.com"`) {
		t.Fatalf("domain missing:\n%s", cfg)
	}
	path := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := writeConfig(path, policy.Policy{SandboxID: "domains", Allow: []policy.Rule{{Protocol: "tcp", Domain: "example.com"}}}, "", false, false); err == nil {
		t.Fatal("domain policy without DNS upstream was accepted")
	}
	if err := writeConfig(path, policy.Policy{SandboxID: "domains", Allow: []policy.Rule{{Protocol: "tcp", Domain: "example.com"}}}, "1.1.1.1:53", false, false); err != nil {
		t.Fatal(err)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected validation error")
	}
	if _, err := New(Config{GVProxy: "/bin/true", RunDir: "/tmp/x"}); err != nil {
		t.Fatal(err)
	}
}

func TestStopUnknownIsSafe(t *testing.T) {
	m, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(context.Background(), "missing"); err != nil {
		t.Fatal(err)
	}
}

func TestCloseRejectsNewStarts(t *testing.T) {
	m, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(context.Background(), policy.Policy{SandboxID: "dev"}); err == nil {
		t.Fatal("closed manager accepted a new gateway")
	}
}

func TestCloseReportsStartupInProgress(t *testing.T) {
	m, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.reserveStart("dev"); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(context.Background()); err == nil {
		t.Fatal("close reported success during gateway startup")
	}
}

func TestReloadWaitsForStartupBeforeFailingClosed(t *testing.T) {
	m, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.reserveStart("dev"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- m.Reload(context.Background(), policy.Policy{SandboxID: "dev"}) }()
	select {
	case <-done:
		t.Fatal("reload returned before startup completed")
	case <-time.After(50 * time.Millisecond):
	}
	m.mu.Lock()
	finished := m.starting["dev"]
	delete(m.starting, "dev")
	close(finished)
	m.mu.Unlock()
	if err := <-done; err == nil {
		t.Fatal("reload reported success without a running gateway")
	}
}

func TestStartRejectsUnsafeSandboxID(t *testing.T) {
	m, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", ".", "..", "../outside", "a/b", `a\b`, "a\x00b", strings.Repeat("a", 64)} {
		t.Run(id, func(t *testing.T) {
			if _, err := m.Start(context.Background(), policy.Policy{SandboxID: id}); err == nil {
				t.Fatal("unsafe sandbox ID accepted")
			}
		})
	}
	for _, id := range []string{"dev", "DEV_1", "a.b-c"} {
		if !validSandboxID(id) {
			t.Fatalf("valid sandbox ID %q rejected", id)
		}
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gwtest")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestStopUntrackedRemovesOwnSockets(t *testing.T) {
	dir := shortTempDir(t)
	m, err := New(Config{GVProxy: "/bin/true", RunDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "dev.sock")
	apiSocket := filepath.Join(dir, "dev.api.sock")
	for _, path := range []string{socket, apiSocket} {
		conn, err := net.ListenPacket("unixgram", path)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Stop(context.Background(), "dev"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{socket, apiSocket} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still exists: %v", path, err)
		}
	}
}

func TestStopUntrackedLeavesForeignSocket(t *testing.T) {
	runDir := shortTempDir(t)
	foreignDir := shortTempDir(t)
	foreign := filepath.Join(foreignDir, "dev.sock")
	conn, err := net.ListenPacket("unixgram", foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	m, err := New(Config{GVProxy: "/bin/true", RunDir: runDir})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(context.Background(), "dev"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(foreign); err != nil {
		t.Fatalf("foreign socket changed: %v", err)
	}
}

func TestWatchReportsUnexpectedExitAndCleansSockets(t *testing.T) {
	dir := shortTempDir(t)
	exited := make(chan string, 1)
	m, err := New(Config{GVProxy: "/bin/true", RunDir: dir, OnExit: func(name string) { exited <- name }})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", "exit 0") // #nosec G204 -- fixed test command
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	socket := filepath.Join(dir, "dev.sock")
	apiSocket := filepath.Join(dir, "dev.api.sock")
	for _, path := range []string{socket, apiSocket} {
		conn, err := net.ListenPacket("unixgram", path)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
	proc := process{cmd: cmd, socket: socket, apiSocket: apiSocket, done: done}
	m.mu.Lock()
	m.procs["dev"] = proc
	m.mu.Unlock()
	m.watch("dev", proc, done)
	select {
	case name := <-exited:
		if name != "dev" {
			t.Fatalf("OnExit name = %q", name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("unexpected gateway exit was not reported")
	}
	m.mu.Lock()
	_, tracked := m.procs["dev"]
	m.mu.Unlock()
	if tracked {
		t.Fatal("exited gateway is still tracked")
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("gateway socket was not cleaned: %v", err)
	}
}

func TestWatchIgnoresOrderlyStop(t *testing.T) {
	dir := shortTempDir(t)
	exited := make(chan string, 1)
	m, err := New(Config{GVProxy: "/bin/true", RunDir: dir, OnExit: func(name string) { exited <- name }})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", "exit 0") // #nosec G204 -- fixed test command
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	proc := process{cmd: cmd, socket: filepath.Join(dir, "dev.sock"), done: done, stopping: true}
	m.mu.Lock()
	m.procs["dev"] = proc
	m.mu.Unlock()
	m.watch("dev", proc, done)
	select {
	case name := <-exited:
		t.Fatalf("orderly stop reported as loss: %s", name)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestQUICDomainPolicyRequiresExplicitCapability(t *testing.T) {
	rule := policy.Rule{Protocol: "udp", Domain: "h3.example.test", Port: 443}
	path := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := writeConfig(path, policy.Policy{SandboxID: "quic", Allow: []policy.Rule{rule}}, "1.1.1.1:53", false, false); err == nil {
		t.Fatal("UDP domain rule accepted without the QUIC capability")
	}
	if err := writeConfig(path, policy.Policy{SandboxID: "quic", Allow: []policy.Rule{rule}}, "1.1.1.1:53", false, true); err != nil {
		t.Fatalf("explicit QUIC UDP domain rule rejected: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`protocol: "udp"`, `domain: "h3.example.test"`, `port: 443`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing %q in config:\n%s", want, data)
		}
	}
	manager, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir(), QUICEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if !manager.QUICEnabled() {
		t.Fatal("manager failed to report the explicit QUIC capability")
	}
	if err := manager.SetQUICEnabled(false); err != nil {
		t.Fatalf("disable QUIC before startup: %v", err)
	}
	if manager.QUICEnabled() {
		t.Fatal("QUIC capability stayed enabled after SetQUICEnabled(false)")
	}
}
