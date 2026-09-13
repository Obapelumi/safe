package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func cmdVerify() error {
	ok := true
	check := func(label, shCmd string, wantNonEmpty bool) {
		out, err := exec.Command("sh", "-c", shCmd).CombinedOutput()
		s := strings.TrimSpace(string(out))
		got := err == nil && s != "" && s != "0"
		status := okStyle.Render("OK  ")
		if got != wantNonEmpty {
			status = errStyle.Render("FAIL")
			ok = false
		}
		fmt.Printf("[%s] %-30s %s\n", status, label, s)
	}

	check("hosts blocklist present", "grep -c 'safe blocklist' /etc/hosts", true)
	check("hosts immutable flag", "ls -lO /etc/hosts | grep -Eo 'schg|uchg'", true)
	check("chrome policy", "test -f '/Library/Managed Preferences/com.google.Chrome.plist' && echo present", true)
	check("edge policy", "test -f '/Library/Managed Preferences/com.microsoft.Edge.plist' && echo present", true)
	check("pf anchor", "test -f /etc/pf.anchors/safe && echo present", true)
	check("pf daemon", "test -f /Library/LaunchDaemons/com.safe.pf.plist && echo present", true)
	check("profile installed", "profiles show 2>/dev/null | grep -c 'com.safe'", true)

	fmt.Println()
	if ok {
		fmt.Println(okStyle.Render("all core checks passed"))
	} else {
		fmt.Println(warnStyle.Render("some checks failed; see above"))
	}
	return nil
}
