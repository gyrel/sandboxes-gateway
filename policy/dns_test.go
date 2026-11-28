package policy

import (
	"errors"
	"net/netip"
	"testing"
)

func TestIsPublicAddress_ConformanceMatrix(t *testing.T) {
	tests := []struct {
		name    string
		address string
		allowed bool
	}{
		// Public IPv4
		{"public google dns", "8.8.8.8", true},
		{"public cloudflare dns", "1.1.1.1", true},
		{"public routed ip", "142.250.190.46", true},

		// Public IPv6
		{"public google v6", "2001:4860:4860::8888", true},
		{"public cloudflare v6", "2606:4700:4700::1111", true},

		// Negative controls: IPv4 Private and Loopback
		{"loopback ipv4", "127.0.0.1", false},
		{"private 10/8", "10.0.0.1", false},
		{"private 172.16/12", "172.16.0.1", false},
		{"private 192.168/16", "192.168.1.1", false},
		{"carrier grade nat", "100.64.0.1", false},
		{"link local metadata", "169.254.169.254", false},
		{"documentation range 192.0.2.1", "192.0.2.1", false},
		{"documentation range 198.51.100.1", "198.51.100.1", false},
		{"documentation range 203.0.113.1", "203.0.113.1", false},
		{"broadcast", "255.255.255.255", false},
		{"unspecified", "0.0.0.0", false},

		// Negative controls: IPv6 Private and Loopback
		{"loopback ipv6", "::1", false},
		{"unique local address fc00", "fc00::1", false},
		{"unique local address fd00", "fd00::1", false},
		{"link local v6", "fe80::1", false},
		{"documentation range 2001:db8::1", "2001:db8::1", false},
		{"unspecified v6", "::", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tt.address)
			if err != nil {
				t.Fatalf("invalid test fixture address %q: %v", tt.address, err)
			}
			if got := IsPublicAddress(addr); got != tt.allowed {
				t.Errorf("IsPublicAddress(%s) = %v, want %v", tt.address, got, tt.allowed)
			}
		})
	}
}

func TestValidateDNSAnswers_NegativeControls(t *testing.T) {
	t.Run("empty answers fail closed", func(t *testing.T) {
		err := ValidateDNSAnswers(nil)
		if !errors.Is(err, ErrEmptyDNSAnswers) {
			t.Fatalf("got err=%v, want %v", err, ErrEmptyDNSAnswers)
		}
	})

	t.Run("public answers allowed", func(t *testing.T) {
		addrs := []netip.Addr{
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("2606:4700:4700::1111"),
		}
		if err := ValidateDNSAnswers(addrs); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})

	t.Run("mixed public and private answer fails closed", func(t *testing.T) {
		addrs := []netip.Addr{
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("127.0.0.1"), // private loopback vector
		}
		err := ValidateDNSAnswers(addrs)
		if !errors.Is(err, ErrDNSAnswerNonPublic) {
			t.Fatalf("got err=%v, want %v", err, ErrDNSAnswerNonPublic)
		}
	})

	t.Run("cloud metadata address in answer fails closed", func(t *testing.T) {
		addrs := []netip.Addr{
			netip.MustParseAddr("169.254.169.254"),
		}
		err := ValidateDNSAnswers(addrs)
		if !errors.Is(err, ErrDNSAnswerNonPublic) {
			t.Fatalf("got err=%v, want %v", err, ErrDNSAnswerNonPublic)
		}
	})
}
