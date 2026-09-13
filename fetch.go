package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// stevenBlackPornOnly is the default remote source. It is a hosts-format file
// containing only adult domains, ~76k entries, maintained and released daily.
const stevenBlackPornOnly = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts"

type listSource struct {
	Name string
	URL  string
}

var defaultSource = listSource{Name: "StevenBlack (porn-only)", URL: stevenBlackPornOnly}

// fetchDomains downloads a hosts-format or plain list and returns normalized
// domains. On any failure it falls back to the embedded list so the tool still
// works offline.
func fetchDomains(ctx context.Context, src listSource) ([]string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, "", err
	}
	client := &http.Client{Timeout: 45 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fallbackDomains(), "embedded (remote fetch failed)", nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fallbackDomains(), fmt.Sprintf("embedded (remote returned %d)", resp.StatusCode), nil
	}

	domains, err := parseList(resp.Body)
	if err != nil || len(domains) == 0 {
		return fallbackDomains(), "embedded (remote list unparseable)", nil
	}
	return domains, fmt.Sprintf("%s (%d domains)", src.Name, len(domains)), nil
}

// parseList handles hosts files ("0.0.0.0 domain", "127.0.0.1 domain"), bare
// domain lines, inline comments, and skips localhost/loopback/broadcast names.
func parseList(r interface{ Read([]byte) (int, error) }) ([]string, error) {
	skip := map[string]bool{
		"localhost": true, "localhost.localdomain": true, "local": true,
		"broadcasthost": true, "ip6-localhost": true, "ip6-loopback": true,
		"0.0.0.0": true, "127.0.0.1": true, "::1": true, "255.255.255.255": true,
	}

	seen := make(map[string]struct{}, 1<<16)
	domains := make([]string, 0, 1<<16)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		token := fields[len(fields)-1]
		// Skip lines that are purely an IP (no hostname).
		if len(fields) == 1 && looksLikeIP(token) {
			continue
		}
		d := normalizeDomain(token)
		if d == "" || skip[d] {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		domains = append(domains, d)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}

func normalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	if s == "" || strings.ContainsAny(s, " \t/\\") {
		return ""
	}
	if !strings.Contains(s, ".") {
		return ""
	}
	if strings.Contains(s, ":") { // IPv6 or host:port
		return ""
	}
	return s
}

func looksLikeIP(s string) bool {
	if s == "" {
		return false
	}
	digits, dots := 0, 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '.':
			dots++
		default:
			return false
		}
	}
	return dots == 3 && digits > 0
}

func fallbackDomains() []string {
	data, err := assets.ReadFile("assets/blocklist.txt")
	if err != nil {
		return nil
	}
	d, _ := parseList(strings.NewReader(string(data)))
	return d
}

var errNoDomains = errors.New("no domains parsed")
