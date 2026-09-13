package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// emitRollback writes the uninstall script, encrypts it with a fresh secret,
// and destroys the secret unless the caller opts out.
func emitRollback(opts options, domains []string) error {
	rollback := renderRollbackScript(opts)

	secret, err := randomSecret(32)
	if err != nil {
		return err
	}
	enc, err := encrypt(secret, []byte(rollback))
	if err != nil {
		return err
	}

	encPath := filepath.Join(opts.out, "rollback.enc")
	if err := os.WriteFile(encPath, enc, 0o644); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(opts.out, "rollback.sh"))

	// Dry run: never prompt or burn, just leave the bundle.
	if !opts.apply {
		fmt.Println("dry run: rollback bundle written to", encPath, "(secret not generated)")
		return nil
	}

	if !opts.burn {
		secPath := filepath.Join(opts.out, "secret.txt")
		if err := os.WriteFile(secPath, []byte(secret+"\n"), 0o600); err != nil {
			return err
		}
		fmt.Println("secret written to", secPath, "(NOT burned)")
		return nil
	}

	fmt.Println()
	fmt.Println(warnStyle.Render("======================================================================"))
	fmt.Println(warnStyle.Render(" ROLLBACK SECRET (shown once, then destroyed)"))
	fmt.Println(warnStyle.Render("======================================================================"))
	fmt.Println(" ", titleStyle.Render(secret))
	fmt.Println()
	fmt.Println(" This secret decrypts rollback.enc, the only clean way to undo safe.")
	fmt.Println(" Store it OFF this machine. It will be destroyed on the next keypress.")
	fmt.Println(warnStyle.Render("======================================================================"))
	fmt.Print("Press Enter to destroy the secret: ")

	var b [1]byte
	_, _ = os.Stdin.Read(b[:])

	secret = ""
	_ = os.Remove(filepath.Join(opts.out, "secret.txt"))
	fmt.Println("secret destroyed.")
	return nil
}

func renderRollbackScript(opts options) string {
	return `#!/bin/sh
# safe rollback - generated. Run as root.
set -e
echo "reverting /etc/hosts"
if [ -f /etc/hosts.safe.bak ]; then
  chflags noschg /etc/hosts 2>/dev/null || chflags nouchg /etc/hosts 2>/dev/null || true
  cp /etc/hosts.safe.bak /etc/hosts
fi
echo "removing browser policies"
rm -f "/Library/Managed Preferences/com.google.Chrome.plist"
rm -f "/Library/Managed Preferences/com.microsoft.Edge.plist"
for id in org.mozilla.firefox app.zen-browser.zen org.mozilla.firefoxdeveloperedition; do
  defaults delete /Library/Preferences/$id DNSOverHTTPS 2>/dev/null || true
  defaults delete /Library/Preferences/$id EnterprisePoliciesEnabled 2>/dev/null || true
done
echo "removing pf anchor"
launchctl unload -w /Library/LaunchDaemons/com.safe.pf.plist 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.safe.pf.plist
rm -f /etc/pf.anchors/safe
python3 - <<'PY'
import re
p="/etc/pf.conf"
s=open(p).read()
s=re.sub(r'\nanchor "safe".*?from "/etc/pf.anchors/safe"\n', '\n', s, flags=re.S)
open(p,"w").write(s)
PY
pfctl -f /etc/pf.conf 2>/dev/null || true
dscacheutil -flushcache; killall -HUP mDNSResponder 2>/dev/null || true
echo "remove safe.mobileconfig manually in System Settings > Device Management"
echo "rollback complete"
`
}

func cmdUninstall(secretHex, out string) error {
	encPath := filepath.Join(out, "rollback.enc")
	enc, err := os.ReadFile(encPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", encPath, err)
	}
	plain, err := decrypt(secretHex, enc)
	if err != nil {
		return fmt.Errorf("wrong secret or corrupt bundle: %w", err)
	}
	scriptPath := filepath.Join(out, "rollback.sh")
	if err := os.WriteFile(scriptPath, plain, 0o700); err != nil {
		return err
	}
	fmt.Println("decrypted rollback to", scriptPath)
	return runner{apply: true}.cmd("sh", scriptPath)
}
