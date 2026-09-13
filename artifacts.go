package main

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// chromePolicy disables the built-in DNS client and DNS-over-HTTPS so the
// browser falls back to the OS resolver, which reads /etc/hosts.
const chromePolicy = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>DNSOverHTTPSMode</key>
    <string>off</string>
    <key>BuiltInDnsClientEnabled</key>
    <false/>
</dict>
</plist>
`

const launchDaemon = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.safe.pf</string>
    <key>ProgramArguments</key>
    <array>
        <string>/sbin/pfctl</string>
        <string>-E</string>
        <string>-f</string>
        <string>/etc/pf.conf</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>
`

// cloudflareV4 and cloudflareV6 are Cloudflare's published ranges, fetched from
// https://www.cloudflare.com/ips-v4 and /ips-v6. WARP egress, Gateway DoH, and
// 1.1.1.1 all live inside these. They must never be blocked or the tunnel dies.
// Refresh occasionally; Cloudflare adds ranges rarely.
var cloudflareV4 = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
}

var cloudflareV6 = []string{
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

// renderPFAnchor closes the non-WARP DNS escape hatches while leaving Cloudflare
// (and therefore WARP / Zero Trust Gateway DoH) fully reachable.
//
// Design:
//   - pass everything to Cloudflare ranges: this is the VPN's own traffic.
//   - block TCP 443 to known *third-party* DoH resolver IPs.
//   - block 53/853 to anything outside Cloudflare, so plain DNS and DoT leaks
//     are closed but the tunnel's own resolution still works.
func renderPFAnchor() (string, error) {
	nonCloudflareDoH := []string{
		"8.8.8.8", "8.8.4.4", // Google
		"9.9.9.9", "149.112.112.112", // Quad9
		"94.140.14.14", "94.140.15.15", // AdGuard
		"208.67.222.222", "208.67.220.220", // OpenDNS
		"185.228.168.9", "185.228.169.9", // CleanBrowsing
		"76.76.2.0", "76.76.10.0", // Control D
		"156.154.70.1", "156.154.71.1", // Neustar
		"45.90.28.0", "45.90.30.0", // NextDNS
	}

	var b []byte
	p := func(s string) { b = append(b, []byte(s+"\n")...) }

	p("# safe pf anchor - DNS lock (WARP-aware)")
	p("#")
	p("# Cloudflare ranges are passed wholesale: WARP egress, Zero Trust Gateway")
	p("# DoH, and 1.1.1.1 all live there. Blocking them would kill the tunnel.")
	for _, cidr := range cloudflareV4 {
		p(fmt.Sprintf("pass out quick to %s", cidr))
	}
	for _, cidr := range cloudflareV6 {
		p(fmt.Sprintf("pass out quick to %s", cidr))
	}

	p("#")
	p("# Third-party public DoH resolvers: block HTTPS so browsers/apps can't")
	p("# sidestep the tunnel with their own secure DNS.")
	for _, ip := range nonCloudflareDoH {
		p(fmt.Sprintf("block drop out quick proto tcp to %s port 443", ip))
	}

	p("#")
	p("# Plain DNS (53) and DoT (853) to anything outside Cloudflare. RF")
	p("# (RFC1918) is allowed so local services still resolve.")
	for _, cidr := range localNetworks {
		p(fmt.Sprintf("pass out quick to %s", cidr))
	}
	p("block drop out quick proto udp to any port 53")
	p("block drop out quick proto tcp to any port 53")
	p("block drop out quick proto tcp to any port 853")
	p("block drop out quick proto udp to any port 853")

	return string(b), nil
}

var localNetworks = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
	"fc00::/7", "fe80::/10", "::1",
}

// renderProfile builds a best-effort non-removable content filter profile.
// RemovalDisallowed is honoured on supervised/managed devices; a local admin
// can still remove it otherwise.
//
// Apple caps DenyListURLs at 500 entries, so the bulk of the blocklist lives in
// /etc/hosts instead. This profile carries the built-in automatic adult filter
// for Safari and third-party apps, plus a small curated deny list.
func renderProfile(domains []string, withLegacyFilter bool) string {
	var deny strings.Builder
	limit := len(domains)
	if limit > 500 {
		limit = 500
	}
	for _, d := range domains[:limit] {
		deny.WriteString("                <string>https://" + d + "</string>\n")
		deny.WriteString("                <string>https://www." + d + "</string>\n")
	}

	legacy := ""
	if withLegacyFilter {
		legacy = `
        <dict>
            <key>PayloadDescription</key>
            <string>Legacy parental content filter</string>
            <key>PayloadDisplayName</key>
            <string>safe content filter</string>
            <key>PayloadIdentifier</key>
            <string>com.safe.contentfilter</string>
            <key>PayloadType</key>
            <string>com.apple.familycontrols.contentfilter</string>
            <key>PayloadUUID</key>
            <string>` + uuid() + `</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>restrictWeb</key>
            <true/>
            <key>useContentFilter</key>
            <true/>
        </dict>`
	}

	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadDescription</key>
            <string>safe web content filter</string>
            <key>PayloadDisplayName</key>
            <string>safe content filter</string>
            <key>PayloadIdentifier</key>
            <string>com.safe.webcontentfilter</string>
            <key>PayloadType</key>
            <string>com.apple.webcontent-filter</string>
            <key>PayloadUUID</key>
            <string>` + uuid() + `</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>FilterType</key>
            <string>BuiltIn</string>
            <key>AutoFilterEnabled</key>
            <true/>
            <key>FilterBrowsers</key>
            <true/>
            <key>FilterSockets</key>
            <true/>
            <key>DenyListURLs</key>
            <array>
` + deny.String() + `            </array>
        </dict>` + legacy + `
    </array>
    <key>PayloadDisplayName</key>
    <string>safe</string>
    <key>PayloadIdentifier</key>
    <string>com.safe.profile</string>
    <key>PayloadRemovalDisallowed</key>
    <true/>
    <key>PayloadScope</key>
    <string>System</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>` + uuid() + `</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
`
}

func uuid() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "00000000-0000-0000-0000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
