package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// applyHosts merges the blocklist into /etc/hosts and locks it.
func applyHosts(r runner, opts options, domains []string) error {
	block := renderHostsBlock(domains)

	if !opts.apply {
		fmt.Printf("  [dry-run] would merge %d domains into /etc/hosts and chflags schg\n", len(domains))
		return os.WriteFile(filepath.Join(opts.out, "hosts.block"), []byte(block), 0o644)
	}

	if err := r.shell("test -f /etc/hosts.safe.bak || cp /etc/hosts /etc/hosts.safe.bak"); err != nil {
		return err
	}

	script := fmt.Sprintf(`
python3 - <<'PY'
import re
p="/etc/hosts"
s=open(p).read()
s=re.sub(r"\n?%s.*?%s\n?", "", s, flags=re.S)
open(p,"w").write(s.rstrip()+"\n")
PY
`, regexpQuote(hostsMarker), regexpQuote("<<< safe blocklist <<<"))
	if err := r.shell(script); err != nil {
		return err
	}

	tmp := "/tmp/safe.hosts.block"
	if err := os.WriteFile(tmp, []byte("\n"+block), 0o644); err != nil {
		return err
	}
	if err := r.shell("cat " + tmp + " >> /etc/hosts"); err != nil {
		return err
	}
	_ = os.Remove(tmp)

	return r.shell("chflags noschg /etc/hosts 2>/dev/null || true; chflags schg /etc/hosts || chflags uchg /etc/hosts")
}

func applyBrowserPolicies(r runner, opts options) error {
	fmt.Println("installing browser managed preferences")
	_ = r.shell("mkdir -p '/Library/Managed Preferences'")
	if err := r.cmd("cp", filepath.Join(opts.out, "com.google.Chrome.plist"), "/Library/Managed Preferences/com.google.Chrome.plist"); err != nil {
		return err
	}
	if err := r.cmd("cp", filepath.Join(opts.out, "com.microsoft.Edge.plist"), "/Library/Managed Preferences/com.microsoft.Edge.plist"); err != nil {
		return err
	}
	for _, id := range []string{"org.mozilla.firefox", "app.zen-browser.zen", "org.mozilla.firefoxdeveloperedition"} {
		_ = r.cmd("defaults", "write", "/Library/Preferences/"+id, "EnterprisePoliciesEnabled", "-bool", "TRUE")
		_ = r.cmd("defaults", "write", "/Library/Preferences/"+id, "DNSOverHTTPS", "-dict", "Enabled", "-bool", "false", "Locked", "-bool", "true")
	}
	return nil
}

func applyPF(r runner, opts options) error {
	fmt.Println("installing pf anchor and daemon")
	_ = r.shell("mkdir -p /etc/pf.anchors")
	if err := r.cmd("cp", filepath.Join(opts.out, "safe.anchor"), "/etc/pf.anchors/safe"); err != nil {
		return err
	}
	if err := r.cmd("cp", filepath.Join(opts.out, "com.safe.pf.plist"), "/Library/LaunchDaemons/com.safe.pf.plist"); err != nil {
		return err
	}
	snippet := "anchor \"safe\"\nload anchor \"safe\" from \"/etc/pf.anchors/safe\"\n"
	if err := os.WriteFile("/tmp/safe.pf.snippet", []byte(snippet), 0o644); err != nil {
		return err
	}
	if err := r.shell("grep -q 'anchor \"safe\"' /etc/pf.conf || cat /tmp/safe.pf.snippet >> /etc/pf.conf"); err != nil {
		return err
	}
	_ = os.Remove("/tmp/safe.pf.snippet")

	_ = r.shell("pfctl -f /etc/pf.conf 2>/dev/null || true")
	if err := r.cmd("launchctl", "load", "-w", "/Library/LaunchDaemons/com.safe.pf.plist"); err != nil {
		return err
	}
	return r.shell("pfctl -E 2>/dev/null || true")
}

func regexpQuote(s string) string {
	return strings.NewReplacer(
		`\`, `\\`, `.`, `\.`, `*`, `\*`, `+`, `\+`, `?`, `\?`,
		`(`, `\(`, `)`, `\)`, `[`, `\[`, `]`, `\]`, `{`, `\{`,
		`}`, `\}`, `^`, `\^`, `$`, `\$`, `|`, `\|`,
	).Replace(s)
}

func printNextSteps(opts options) {
	fmt.Println()
	fmt.Println(warnStyle.Render("Manual steps remaining (macOS cannot do these from a CLI):"))
	fmt.Println("  1. Double-click", filepath.Join(opts.out, "safe.mobileconfig"))
	fmt.Println("     then approve it in System Settings > General > Device Management.")
	fmt.Println("  2. Turn on Screen Time > Content & Privacy > Limit Adult Websites")
	fmt.Println("     on each account that needs it.")
}
