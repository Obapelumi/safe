# safe

Lock adult content out of a Mac at the OS and network level, with no external
service and no third-party app. Everything here uses macOS built-ins: `/etc/hosts`,
configuration profiles, browser managed preferences, and `pf`.

## What this actually is

A pile of **speed bumps**, not a wall. As the sole admin of your own machine,
anything you configure you can eventually undo. This tool makes the undo path
cost as much as possible, and burns the one key that would have made it easy.

It is honest about the limits — read [Limits](#limits) before you run it.

## How it blocks

| Layer | What it does | Survives |
|---|---|---|
| `/etc/hosts` blocklist | Blackholes ~77k adult domains at the resolver | `chflags schg` — needs Recovery to edit |
| Browser policy | Forces Chrome/Edge/Firefox/Zen to use the OS resolver (kills DoH bypass) | Machine-level plist, admin can delete |
| `pf` anchor | Blocks plain DNS (53), DoT (853), and known DoH resolver IPs | LaunchDaemon, admin can unload |
| `.mobileconfig` | System content filter for Safari *and* third-party apps | Manual approval; best-effort non-removable |
| Burned secret | AES-encrypts the rollback bundle, then deletes the key | **The real gate** |

## Install

Requires Go 1.24+ and macOS. Internet is used once to fetch the blocklist.

```sh
git clone https://github.com/Obapelumi/safe
cd safe
go run .
```

That opens the interactive TUI. It fetches the list, shows you the plan, and
asks for confirmation before each layer.

### What the TUI does

1. Fetches the blocklist (StevenBlack porn-only, ~77k domains). Falls back to the
   embedded list if offline.
2. Prompts for which layers to install.
3. Runs the privileged steps (one `sudo` prompt).
4. **Pauses** for the steps macOS will not automate — installing the profile.
5. Verifies, then reveals a one-time secret and destroys it on your keypress.

### Non-interactive

```sh
go run . apply --apply            # execute everything
go run . apply                     # dry run: writes artifacts, touches nothing
go run . fetch                     # just download + count the list
go run . verify                    # check which layers are live
```

Flags: `--list URL`, `--no-burn`, `--no-profile`, `--no-pf`,
`--with-content-filter`, `--out DIR`.

## The secret

After applying, `safe` generates a 256-bit secret, encrypts `out/rollback.enc`
with it (AES-256-GCM), prints the secret **once**, and deletes it when you press
Enter.

- That secret is the only clean way to undo `safe`.
- Write it down and store it **off this machine**.
- Lose it and undoing means booting to Recovery, mounting the volume, and
  clearing `/etc/hosts` by hand — plus removing the profile and daemon.

To roll back:

```sh
go run . uninstall --secret <SECRET> --out out
```

Pass `--no-burn` to keep the secret in `out/secret.txt` instead.

## Manual steps you cannot script

macOS 11+ removed `profiles install`, so the tool cannot finish the profile step
for you:

1. Double-click `out/safe.mobileconfig`.
2. Approve it in **System Settings → General → Device Management**.
3. Optionally turn on **Screen Time → Content & Privacy → Limit Adult Websites**
   (Safari only; the profile covers the rest).

There is also no supported way to set the Screen Time passcode from a script, and
profile removal passwords can only be set by MDM or Apple Configurator. That is
why the burned secret gates the *rollback bundle*, not an OS passcode.

## Limits

- **DoH is the whole bypass.** A browser with secure DNS on ignores `/etc/hosts`.
  The browser policy disables it and the `pf` anchor blocks the known resolver
  IPs — which is why they are on by default.
- **A new browser is a new hole.** The policy targets known bundle IDs. Install a
  fresh Chromium fork and it may not be covered until you add its ID.
- **`chflags schg` can be denied** under SIP. The tool falls back to `uchg`
  (weaker — root can clear it with `chflags nouchg`).
- **`PayloadRemovalDisallowed` needs supervision.** On an unsupervised Mac the
  profile is removable in System Settings. Non-removable profiles require MDM
  enrollment via Apple Business Manager, or Apple Configurator supervision.
- **Root + physical access always wins.** Recovery mode, a firmware wipe, or a
  second OS will bypass all of this. Only an MDM-managed device changes that.
- **A ~77k-line `/etc/hosts`** adds a little name-resolution overhead. Noticeable
  on some machines, usually not.

If you want a genuinely non-removable setup, the unscriptable answer is a
managed device: enroll it in MDM so the profile can't be removed, or put the
filter on your router/DNS so the policy lives off the machine.

## Layout

```
main.go        CLI entry + subcommands
tui.go         interactive flow (bubbletea + huh)
fetch.go       blocklist download + parsing
apply.go       orchestration
lock.go        hosts, browser policy, pf
artifacts.go   plist / profile / anchor rendering
rollback.go    secret generation, encryption, burn
verify.go      post-install checks
```

## License

MIT
