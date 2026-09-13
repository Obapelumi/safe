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

// renderPFAnchor blocks plain DNS (53) and DNS-over-TLS (853) and the well-known
// DoH resolver endpoints, forcing resolution through the OS resolver.
func renderPFAnchor() (string, error) {
	doh := []string{
		"1.1.1.1", "1.0.0.1", // Cloudflare
		"8.8.8.8", "8.8.4.4", // Google
		"9.9.9.9", "149.112.112.112", // Quad9
		"94.140.14.14", "94.140.15.15", // AdGuard
		"208.67.222.222", "208.67.220.220", // OpenDNS
		"185.228.168.9", "185.228.169.9", // CleanBrowsing
	}
	var b []byte
	b = append(b, []byte("# safe pf anchor - DNS lock\n")...)
	for _, ip := range doh {
		b = append(b, []byte(fmt.Sprintf("block drop out quick proto tcp to %s port 443\n", ip))...)
	}
	b = append(b, []byte("block drop out quick proto udp to any port 53\n")...)
	b = append(b, []byte("block drop out quick proto tcp to any port 53\n")...)
	b = append(b, []byte("block drop out quick proto tcp to any port 853\n")...)
	b = append(b, []byte("block drop out quick proto udp to any port 853\n")...)
	return string(b), nil
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
