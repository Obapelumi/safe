package main

import (
	"context"
	"flag"
	"fmt"
	"os"
)

const version = "0.2.0"

func usage() {
	fmt.Fprint(os.Stderr, `safe - lock adult content out of macOS at the OS and network level.

Usage:
  safe                 interactive TUI (recommended)
  safe apply [flags]   non-interactive apply
  safe fetch [flags]   download and count the blocklist
  safe verify          check that layers are in place
  safe uninstall --secret HEX [--out DIR]
  safe version

Interactive mode walks you through the plan and pauses whenever macOS requires
a manual step (installing the configuration profile).

apply flags:
  --apply              execute privileged steps (default: dry run)
  --out DIR            artifact directory (default "out")
  --list URL           blocklist source (default StevenBlack porn-only)
  --no-burn            keep the secret instead of destroying it
  --no-profile         skip browser managed policy
  --no-pf              skip pf firewall rules
  --with-content-filter  also emit the legacy content-filter payload
`)
}

func main() {
	if len(os.Args) < 2 {
		runInteractive()
		return
	}
	switch os.Args[1] {
	case "apply":
		fs := flag.NewFlagSet("apply", flag.ExitOnError)
		apply := fs.Bool("apply", false, "actually execute privileged steps")
		out := fs.String("out", "out", "directory for generated artifacts")
		noBurn := fs.Bool("no-burn", false, "keep the secret instead of destroying it")
		listURL := fs.String("list", stevenBlackPornOnly, "blocklist URL")
		noProfile := fs.Bool("no-profile", false, "skip browser managed policy")
		noPF := fs.Bool("no-pf", false, "skip pf rules")
		cf := fs.Bool("with-content-filter", false, "include the legacy content filter payload")
		_ = fs.Parse(os.Args[2:])
		p := &plan{
			source:      listSource{Name: "custom", URL: *listURL},
			apply:       *apply,
			burn:        !*noBurn,
			withProfile: !*noProfile,
			withPF:      !*noPF,
			out:         *out,
		}
		domains, _, err := fetchDomains(context.Background(), p.source)
		if err != nil && len(domains) == 0 {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		if err := runApply(p, domains, *cf); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "fetch":
		fs := flag.NewFlagSet("fetch", flag.ExitOnError)
		listURL := fs.String("list", stevenBlackPornOnly, "blocklist URL")
		_ = fs.Parse(os.Args[2:])
		domains, desc, _ := fetchDomains(context.Background(), listSource{Name: "remote", URL: *listURL})
		fmt.Printf("source: %s\ncount:  %d\n", desc, len(domains))
	case "verify":
		if err := cmdVerify(); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "uninstall":
		fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
		secret := fs.String("secret", "", "secret hex used to decrypt the rollback bundle")
		out := fs.String("out", "out", "directory holding rollback.enc")
		_ = fs.Parse(os.Args[2:])
		if err := cmdUninstall(*secret, *out); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "version", "-v", "--version":
		fmt.Println("safe", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func runInteractive() {
	p, domains, err := runTUI(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "\n"+errStyle.Render("error: ")+err.Error())
		os.Exit(1)
	}
	if err := runApply(p, domains, false); err != nil {
		fmt.Fprintln(os.Stderr, "\n"+errStyle.Render("error: ")+err.Error())
		os.Exit(1)
	}
}
