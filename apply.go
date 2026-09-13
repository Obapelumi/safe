package main

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
)

type options = plan

//go:embed assets/blocklist.txt assets/templates/*
var assets embed.FS

// runApply executes the plan. In dry-run mode nothing privileged happens.
func runApply(p *plan, domains []string, withContentFilter bool) error {
	opts := options{
		source:      p.source,
		apply:       p.apply,
		burn:        p.burn,
		withProfile: p.withProfile,
		withPF:      p.withPF,
		out:         p.out,
	}

	fmt.Println("safe", version)
	if !opts.apply {
		fmt.Println("mode: " + warnStyle.Render("DRY RUN") + " (use the TUI or --apply to make changes)")
	} else {
		fmt.Println("mode: " + okStyle.Render("APPLY"))
	}
	fmt.Printf("source: %s\n", opts.source.Name)
	fmt.Printf("domains: %d\n\n", len(domains))

	if err := os.MkdirAll(opts.out, 0o755); err != nil {
		return err
	}

	if err := renderArtifacts(opts, domains, withContentFilter); err != nil {
		return err
	}

	r := runner{apply: opts.apply}
	if err := applyHosts(r, opts, domains); err != nil {
		return fmt.Errorf("hosts: %w", err)
	}

	if opts.withProfile {
		if err := applyBrowserPolicies(r, opts); err != nil {
			return fmt.Errorf("browser policy: %w", err)
		}
	} else {
		fmt.Println(dimStyle.Render("skipping browser policies"))
	}

	if opts.withPF {
		if err := applyPF(r, opts); err != nil {
			return fmt.Errorf("pf: %w", err)
		}
	} else {
		fmt.Println(dimStyle.Render("skipping pf"))
	}

	if err := flushDNS(r); err != nil {
		return fmt.Errorf("dns flush: %w", err)
	}

	if err := emitRollback(opts, domains); err != nil {
		return fmt.Errorf("rollback: %w", err)
	}

	fmt.Println()
	if !opts.apply {
		fmt.Println("dry run complete. artifacts in", opts.out)
		fmt.Println("re-run interactively to apply.")
		return nil
	}

	printNextSteps(opts)
	if opts.withProfile && opts.apply {
		pause("Install " + filepath.Join(opts.out, "safe.mobileconfig") + " in System Settings > General > Device Management, then return here.")
		fmt.Println(okStyle.Render("✓") + " profile step acknowledged")
	}
	fmt.Println()
	fmt.Println(okStyle.Render("apply complete."))
	return nil
}

func renderArtifacts(opts options, domains []string, withContentFilter bool) error {
	if err := writeIfChanged(filepath.Join(opts.out, "com.google.Chrome.plist"), []byte(chromePolicy)); err != nil {
		return err
	}
	if err := writeIfChanged(filepath.Join(opts.out, "com.microsoft.Edge.plist"), []byte(chromePolicy)); err != nil {
		return err
	}
	if data, err := assets.ReadFile("assets/templates/zen-policies.json"); err == nil {
		if err := writeIfChanged(filepath.Join(opts.out, "zen-policies.json"), data); err != nil {
			return err
		}
	}
	anchor, err := renderPFAnchor()
	if err != nil {
		return err
	}
	if err := writeIfChanged(filepath.Join(opts.out, "safe.anchor"), []byte(anchor)); err != nil {
		return err
	}
	if err := writeIfChanged(filepath.Join(opts.out, "com.safe.pf.plist"), []byte(launchDaemon)); err != nil {
		return err
	}
	return writeIfChanged(filepath.Join(opts.out, "safe.mobileconfig"), []byte(renderProfile(domains, withContentFilter)))
}

func flushDNS(r runner) error {
	fmt.Println("flushing DNS cache")
	return r.shell("dscacheutil -flushcache; killall -HUP mDNSResponder 2>/dev/null || true")
}
