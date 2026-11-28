package policy

import (
	"errors"
	"net/netip"
)

var (
	// ErrDNSAnswerNonPublic is returned when a domain resolution answers with a
	// non-public or reserved IP address, mitigating unauthorized internal network binding.
	ErrDNSAnswerNonPublic = errors.New("DNS answer contains non-public or reserved IP address")
	// ErrEmptyDNSAnswers is returned when no IP addresses are provided for validation.
	ErrEmptyDNSAnswers = errors.New("DNS response contains no IP addresses")
)

var (
	publicIPv6Prefix = netip.MustParsePrefix("2000::/3")
	reservedPrefixes = [...]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
		// IPv6 reserved/non-public ranges
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
	}
)

// IsPublicAddress returns true if the address is a routable public unicast address.
func IsPublicAddress(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	if addr.Is6() && !publicIPv6Prefix.Contains(addr) {
		return false
	}
	for i := range reservedPrefixes {
		if reservedPrefixes[i].Contains(addr) {
			return false
		}
	}
	return true
}

// ValidateDNSAnswers verifies that all returned addresses are valid public unicast addresses.
// If any address resolves to private, loopback, or reserved ranges, validation fails closed.
func ValidateDNSAnswers(addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return ErrEmptyDNSAnswers
	}
	for _, addr := range addrs {
		if !IsPublicAddress(addr) {
			return ErrDNSAnswerNonPublic
		}
	}
	return nil
}
