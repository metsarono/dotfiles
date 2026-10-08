---
name: dotcortex-gotchas
description: Troubleshooting DotCortex issues — stow conflicts, tangle failures, Guix installer problems, LUKS gotchas, /tmp permissions
---

# DotCortex Known Gotchas

## A stray `all/.hermes` (or any private app-config dir) in the repo hijacks the `~/.hermes` symlink via stow

If a mutable app-config directory that HelmCortex owns — `.hermes` is the canonical case — ever ends up inside a DotCortex overlay (`all/.hermes/`, even untracked), the next `stow all` folds it and repoints `~/.hermes` from its helmstow deployment (`~/HelmCortex/NEXUS/stow/linux/.hermes`) to the empty repo dir, displacing the real symlink into a `~/.hermes.bak.<timestamp>`. The repo copy has no `config.yaml` and no `.env`, so the Hermes gateway reads empty config + zero API keys and silently falls through its default provider catalog to whatever it can find — in the incident that surfaced this (2026-07-12) it misrouted Telegram inference to an *unauthorized* OpenRouter fallback (401) and a dead NVIDIA model id (404), while Telegram itself stayed connected so the only symptom was error replies. Diagnosis: `ls -la ~/.hermes` (is it a symlink, and to where?), then compare `readlink -f ~/.hermes/config.yaml` against the HelmCortex tree. Fix: `ln -sfn HelmCortex/NEXUS/stow/linux/.hermes ~/.hermes`, remove the stray `all/.hermes` from the repo, restart the gateway. Prevention (now in place): `^/\.hermes(/|$)` is in `all/.stow-local-ignore` and `linux/.stow-local-ignore` (sourced from `icons.org`) so stow can never fold it again. Root law: CLAUDE.md rule 20 — DotCortex must never own a secret-bearing mutable app-config tree; those live in HelmCortex NEXUS and deploy via `helmstow`.

## Makefile is tangled output — never edit it directly

The Makefile is tangled from `loom.org`. Any direct edits will be overwritten by the next `make tangle`. Always edit the Makefile template block in `loom.org` instead, then re-tangle.

## First tangle fails with "No rule to make target .mk"

The Makefile includes `.mk` fragment files that don't exist until after the first tangle. `INSTALL.sh` handles this by creating empty stubs. If running manually:

```bash
mkdir -p all/.mk
for mk in flatpak guix guix-substitutes snap appimage cargo homebrew npm pip; do
  [ -f "all/.mk/${mk}.mk" ] || touch "all/.mk/${mk}.mk"
done
make tangle
```

## Loom bootstrap (chicken-and-egg)

`loom` needs `~/.config/maak/maak.scm` (placed by stow) and Guix guile. You CANNOT use `loom stow:x230` for the first stow — use `make safe-stow` directly. `INSTALL.sh` handles this by pre-placing `maak.scm` before stow runs.

After the first `make safe-stow`, loom is functional and can be used for all subsequent stow operations.

## Guix emacs not in SSH PATH

On Guix machines, emacs lives at `~/.guix-extra-profiles/core/core/bin/emacs`. NOT in the default SSH PATH. The `.zshenv` (tangled from `shell.org`) sources Guix profiles for ALL zsh invocations including non-interactive SSH. For bash over SSH:

```bash
export PATH="$HOME/.guix-extra-profiles/core/core/bin:$PATH"
```

## "not owned by stow" after repo rename (.dotfiles -> DotCortex)

If the repo was renamed, all old stow symlinks become foreign (pointing to the old path). Stow reports "existing target is not owned by stow" for every file. Remove dangling symlinks first:

```bash
find ~ -maxdepth 5 -lname "*/.dotfiles/*" -not -path "*/.git/*" -delete
```

Then re-stow. The safe-stow target handles this conflict type automatically with its third sed pattern.

## safe-stow handles three stow conflict message formats

Stow has three different conflict message formats across versions and situations:

1. `existing target is neither a link nor a directory: FILE` (stow <2.4)
2. `cannot stow PKG/FILE over existing target FILE since neither...` (stow 2.4+)
3. `existing target is not owned by stow: FILE` (foreign files/symlinks after repo rename)

The safe-stow target matches all three with sed patterns, filters out HelmCortex, backs up real files, removes them, then stows. If stow still fails, it auto-retries with `--ignore=HelmCortex`.

## "unknown package" for packages that definitely exist — stale guix binary, not channels

If `guix show <pkg>` or a manifest apply rejects packages that demonstrably exist (fastfetch, deskflow, borg at an ancient version), check WHICH guix answered before touching the manifest:

```bash
type -a guix          # fossil: /usr/local/bin/guix (bootstrap seed, frozen at install version)
ls -la ~/.config/guix/current   # per-user current — the real one after guix pull
~/.config/guix/current/bin/guix --version
```

Root cause chain: if the `~/.config/guix/current` symlink is broken or missing, the `.zshenv` `[ -d ... ]` guard silently skips the PATH prepend and every shell — including loom's clean-guix-env wrapper — falls through to the 1.4.0 fossil. The error then looks exactly like channel drift. Fix: `loom guix:pull` (recreates the symlink), then re-validate with the explicit current path before commenting anything out of a manifest. Never gut a manifest on the fossil's testimony (X230, 2026-06-10).

## `nala:apply` / `nala-apply-auto` runs a full `nala upgrade` BEFORE installing manifest packages (sealed 2026-07-24)

Adding one package to `package-nala.org` and running `loom nala:apply` (or `make nala-apply-auto`) to get it installed is NOT a targeted install — the recipe runs `sudo nala upgrade --assume-yes` *first*, upgrading every upgradable package on the system (kernel headers, firefox, python, tailscale…), and only *then* installs the missing manifest entries. That is correct for the `dotcortex-update` sweep, but a trap when you only wanted to add one tool mid-session: a surprise tailscale/python/firefox upgrade can disrupt a live session (tailscale restarts drop the tailnet). To install a single freshly-declared package *without* the upgrade: tangle the manifest, then run the apply SCRIPT directly — `ENFORCE=1 UNINSTALL=0 ~/.local/bin/nala-apply` installs only missing manifest packages, no upgrade — or a plain `sudo nala install <pkg>` once the entry exists in the manifest. If you must abort a runaway upgrade, it is safe ONLY during the download phase: check the output for `Unpacking`/`Setting up`/`Preparing to unpack` first, and never interrupt an in-progress dpkg transaction (kill during download, verify `dpkg --audit` is clean afterward). Surfaced 2026-07-24 adding `unar` for a StuffIt extraction — one package intended, a full system upgrade triggered, caught mid-download.

## Guix installer fails on non-interactive terminal

The official `guix-install.sh` requires interactive stdin. If running via SSH, CI, or piped input, use the manual install method documented in `INSTALL.sh`.

## Guix installer fails with "Missing commands: daemonize"

On Devuan/sysv-init systems, install `daemonize` first: `sudo apt install daemonize`

## Guix ftpmirror SSL errors

The `ftpmirror.gnu.org` redirector sometimes sends you to mirrors with broken SSL certificates. Use `ftp.gnu.org` directly:

```bash
wget https://ftp.gnu.org/gnu/guix/guix-binary-1.5.0.x86_64-linux.tar.xz
```

## LD_PRELOAD libgtk3-nocsd warning

On systems with `libgtk3-nocsd` in `LD_PRELOAD`, Guix commands emit a harmless warning. Ignore it or `unset LD_PRELOAD`.

## Absolute symlinks in overlay dirs abort stow

If an org file tangles an absolute symlink (e.g. `.config/guix/current -> /var/guix/...`), stow will refuse to manage it. Remove such symlinks from overlay dirs before stowing — they are machine-specific. `INSTALL.sh` auto-cleans these.

## /tmp permissions break tangle AND guix pull

If `/tmp` has restrictive permissions (e.g. `755` instead of `1777`), two things break:

1. **Tangle**: emacs `org-persist` can't create temp directories
2. **Guix pull/build**: sandbox can't bind-mount

Fix: `sudo chmod 1777 /tmp`. Tangle-only workaround: `TMPDIR=~/.cache/tmp make tangle`

## pipefail interaction with grep -v

Under `set -euo pipefail`, `grep -v PATTERN` returns exit code 1 when it filters ALL lines. Kills the pipeline. Always wrap: `{ grep -v PATTERN || true; }`

## Guix substituter display bug

`guix package` occasionally crashes with `Wrong type argument in position 1: #f` during substitute download progress display. Cosmetic — retry the command.

## Guix python3 shadows distro tooling via env shebangs

The Guix core profile ships `python3` ahead of `/usr/bin` in PATH, so every `#!/usr/bin/env python3` shebang in distro tools (e.g. Vendefoul Wolf's `gksu`) resolves to Guix Python — which lacks `_tkinter` and crashes with `ModuleNotFoundError`. Fix is declarative, not OS patches: `debian/.local/bin/python3` (tangled from `package-guix.org`) execs `/usr/bin/python3`; `~/.local/bin` precedes the Guix profile in PATH so shells, env-shebangs, and GUI subprocesses all get the distro interpreter. Guix-built apps are unaffected — they reference their interpreter by absolute `/gnu/store/...` path, never through PATH. Guix Python stays reachable at `~/.guix-extra-profiles/core/core/bin/python3` (T480, 2026-06-10).

Related red herring: a session-stale `GUIX_PYTHONPATH` (e.g. `python3.11` site-packages under a `python3.12` profile) looks like a broken profile but is just login env predating a profile rebuild. Check the profile's own `etc/profile` before "fixing" anything — re-login/reboot resolves it.

## Claude settings: shared baseline and userspace hooks share a live union (2026-09-29)

`~/.claude/settings.json` is a live regular file shared by two mergers. DotCortex Stow ignores that exact path; the former ignored `all/.claude/settings.json` is a stale machine-local artifact, never an install target. `agents-hooks.org` tangles the shared baseline into ignored `all/.claude/settings.shared.json`, and `claude-settings-apply` merges it directly into the live file. Baseline keys win; keys absent from the baseline remain local, including `model`, `effortLevel`, and `agentPushNotifEnabled`. `enabledPlugins` deep-merges with shared entries winning. DotCortex replaces only bare `claude-hook-*` command registrations, including obsolete ones; HelmCortex userspace registration groups under `NEXUS/stow/userspace/.claude/hooks/` survive. The HelmCortex userspace compiler merges its hooks into the same live file. Run these mergers serially. To change a shared setting, edit `agents-hooks.org`, then run `loom claude:settings`; a Git pull alone cannot update the live settings. Never copy the live file into public source or hand-edit a tangled artifact.

## ssh ConnectTimeout does NOT bound a hung remote command (mux-session picker hang)

`ssh -o ConnectTimeout=N -o ConnectionAttempts=1` only bounds the TCP/auth handshake. Once the connection succeeds, a remote command that hangs blocks the local `ssh` forever — `ConnectTimeout` never fires. This bit `mux-session`: `build_menu` probes every fleet host sequentially (`tmux`/`zellij`/`wsl.exe ... tmux list-sessions`) before drawing the fzf picker, so one wedged probe meant the picker never rendered. Intermittent because it only bit when a Windows host (gillean/judith) was powered on but its WSL was cold/unresponsive — the `wsl.exe ... tmux list-sessions` command connected, then hung. Symptom looked like "stuck waiting to attach" even though it never got past the listing stage.

Fix pattern: wrap probe SSH in `timeout` — `timeout -k 1 N ssh ...` bounds the whole command no matter where it stalls. Apply to listing/probe SSH only, never the interactive `ssh -t` attach/create path. See `mux.org`'s `ssh_probe` helper (T480s, 2026-06-25).

## `ethtool -t <iface> offline` is destructive — never run it as a diagnostic

`ethtool -t` is a hardware self-test, not a query. It resets the adapter, and on an e1000e whose TX ring is already hung it NULL-derefs in `e1000_flush_desc_rings()`; the `ethtool` process then exits with IRQs disabled, wedging userspace and forcing a power cycle. Read-only ethtool verbs: `-S` (stats), `-a` (pause), `-k` (offloads), `-i` (driver), `-g` (rings), `--show-eee`, and bare `ethtool <iface>`. Everything else — `-t`, `-A`, `-K`, `-G`, `-r`, `--set-eee` — mutates adapter state. Ask before running any of them (T480s, 2026-07-09).

## Link up at full speed but zero packets sent: read the pause-frame counters first

Carrier at 1000/full, `tx_errors=0`, `rx_crc_errors=0`, no PCIe AER, yet `tx_packets` never increments — check `ethtool -S <iface> | grep flow_control` before blaming the NIC, the driver, or the kernel. A link partner jamming PAUSE stops the MAC transmitting exactly this way: thousands of `rx_flow_control_xoff` against almost no `xon`, ~30/s (the 33.5ms max pause quanta at 1 Gbps, refreshed just before expiry). Fix the switch, not the host — power-cycling a wedged unmanaged switch clears it.

The discriminator against a real driver bug is the **absence** of `Detected Hardware Unit Hang`: a genuine e1000e TX-ring stall always prints it with TDH/TDT register dumps, whereas a pause deadlock only trips the generic `NETDEV WATCHDOG: transmit queue 0 timed out`. Ignore the internet's universal `ethtool -K <iface> tso off` advice for I219 — the driver already disables TSO at probe, so it is always already in effect. A pause storm also **masks** any genuine TX hang underneath it; re-check once the link is quiet (T480s + T480, 2026-07-09).

## An I219 MAC can stay wedged across `modprobe -r e1000e`

Reloading the driver does not reset I219 MAC/PHY state — it is shared with the Intel ME. If a freshly loaded e1000e still hangs on the very first packet (`TDH <0>` / `TDT <1>`, one descriptor queued, head never advances) on an idle link, cold-power-off the machine before suspecting dead silicon. A warm reboot may not clear it; a full power-off does (T480s, 2026-07-09).

## `err -30` (EROFS) after a forced shutdown is not evidence of a failing disk

`EXT4-fs (dm-0): ext4_do_writepages: jbd2_start: ... err -30` only means writes hit a read-only filesystem. An operator SysRq remount-read-only (the `U` in REISUB) produces it *byte-identically* to a journal abort. Two discriminators settle it: ext4 records `FS Error count` / `First error time` permanently in the superblock (`dumpe2fs -h <dev>`) on any real filesystem error, and a genuine abort *always* logs `Aborting journal`. If both are absent, no abort occurred. Grep the log for `sysrq: Emergency Remount R/O` before raising a failing-drive alarm, and confirm with `smartctl -H -A`. A `jbd2` token inside a kernel oops backtrace's `Modules linked in:` line is not an error message (T480s, 2026-07-09).

## Neovim "No parser for language X" under heavy load is not a config bug

When load average is very high (rustc/Guix builds + llama-server + stacked agent processes), Neovim 0.12's dlopen-based treesitter parser attach can fail transiently and NON-DETERMINISTICALLY for parsers that are installed and correctly declared — same command succeeds and fails across consecutive runs, hitting bash/python/json/yaml alike while lua/vim/markdown (rtp-bundled) never fail. Before editing lazy.lua's ensure_installed, check `uptime`: if load is in the tens, reopen the file or wait for the build storm to pass. Proven by falsification 2026-07-10 (three config hypotheses tested and reverted; pristine config reproduced the failure identically at load ~29, T480s).

## X230 guix "corrupt input while restoring archive" / "mkdir: File exists" is ZFS unicode normalization, not corruption

The X230's root pool (`rpool/ROOT/ubuntu_n72ogo`, holding `/gnu/store`) has `normalization=formD` + `utf8only=on` — both immutable after dataset creation. Any nar/archive containing filenames that differ only by UTF-8 normalization form CANNOT be restored there: the second name collapses onto the first and mkdir fails with `File exists`, which guix reports as `corrupt input while restoring archive from socket`. It is not a corrupt substitute, not transient, and no server/retry/`--fallback`/`guix gc -D` cycle will ever fix it. Known carrier: `libsass-3.6.4-checkout` (test fixtures `test/e2e/unicode-pwd/Sáss-UŢF8` in NFC and NFD), retained as a runtime reference by guix's `hugo` package output — so hugo (and anything else whose closure contains such an archive) cannot exist in the X230 store at all; `guix copy` from a healthy machine fails identically at unpack. Remedies are topology-level only: per-host manifest exclusion of the affected package, or a store dataset without formD (means recreating the dataset). Burned a full day of substitute-corruption theories 2026-07-10 before `guix copy`'s verbose unpack error named the colliding path.

## guix-daemon won't start on sysv-init: `--substitute-urls` shell-quoting bug, plus a false-positive liveness check

If `guix package` / `loom guix:apply` fails with `failed to connect to /var/guix/daemon-socket/socket: Connection refused` on a Devuan/sysv-init machine, the guix-daemon isn't running — and the init script may be why it won't start. INSTALL.sh generated `/etc/init.d/guix-daemon` with `DAEMON_ARGS="... --substitute-urls='url1 url2 url3'"` launched as `daemonize ... $DAEMON_ARGS` (unquoted). The single quotes are literal inside the variable, and unquoted expansion word-splits the URL list into separate argv elements, so guix-daemon gets a malformed `--substitute-urls='url1` plus stray positional args and dies immediately on start. `/etc/init.d/guix-daemon start` prints "Starting…" and exits 0 — that is `daemonize` returning, NOT the daemon surviving — so it looks fine while guix is dead (this left a T480 with no working guix from a 2026-06-28 reboot until 2026-07-12). Fix: pass the URLs as ONE argv element — `daemonize -p "$PIDFILE" "$DAEMON" --build-users-group=guixbuild --substitute-urls="$SUBSTITUTE_URLS"` with the URLs in a double-quoted variable (fixed in INSTALL.sh). To isolate the cause, launch the daemon directly with minimal args (`sudo /usr/local/bin/guix-daemon --build-users-group=guixbuild`) and watch whether the socket mtime refreshes.

The trap within the trap: do NOT check guix-daemon liveness with `guix gc --list-roots` — it enumerates GC roots from the filesystem and succeeds with NO daemon running, a false positive that will tell you the daemon is up when it is dead (this cost real time and a wrong "daemon is running" claim, caught only when a subagent re-tested with a daemon-requiring op). Verify with something that actually connects: `guix processes`, `guix build -n <pkg>`, or the failing `guix package` itself. The socket *file* also persists across a dead daemon — a present socket proves nothing; its mtime only refreshes when a daemon actually starts, so check the mtime is recent (T480, 2026-07-12).

## guix-daemon starts by hand but is dead after every reboot on OpenRC: stray init-script backups poison provider resolution

This is the *next* era of the T480 guix-daemon saga, after the `--substitute-urls` quoting bug above was fixed and the script was rewritten to native `#!/sbin/openrc-run`. Symptom is identical to a dead daemon (`failed to connect to /var/guix/daemon-socket/socket: Connection refused`), but the script is correct and correctly registered — `/etc/init.d/guix-daemon` is `openrc-run`, symlinked into `/etc/runlevels/default/`, `rc-update show` lists it in `default`, and `sudo rc-service guix-daemon start` works every single time. Yet it never survives a reboot: someone starts it by hand, sees it run, and it is dead again next boot. The tell is that `rc-status default` does NOT list guix-daemon at all — not "stopped", not "crashed", simply *absent* from the runlevel OpenRC actually acts on at boot.

Root cause: OpenRC parses EVERY file in `/etc/init.d/`, and a timestamped backup left beside the real script — exactly what the Change Safety Protocol's `cp file file.backup-$(date)` reflex produces in place — is parsed as a rival service. The two backups here (`guix-daemon.backup-20260712-000004`, `guix-daemon.backup-20260714-021721`) were LSB scripts (`#!/bin/sh`) whose headers carried `# Provides: guix-daemon`, so OpenRC saw THREE services all providing the name `guix-daemon`, could not disambiguate which one the `default`-runlevel entry meant, and started none at boot. `rc-service guix-daemon start` works because it resolves the service by *filename*, bypassing provider resolution entirely — that is the false positive that made this look fixed after every manual start, for months.

Diagnose: `grep -l 'Provides:.*guix-daemon' /etc/init.d/*` and `ls /etc/init.d/guix*` (want exactly ONE file), and `sudo grep -c 'guix-daemon' /run/openrc/deptree` with `sudo grep providedby /run/openrc/deptree | grep guix` (a real service showing `providedby` a `.backup-*` name is the smoking gun). Fix: move the strays OUT of the scanned dir (reversible), regenerate the tree, verify — `sudo mkdir -p /var/backups/guix-initd-strays && sudo mv /etc/init.d/guix-daemon.backup-* /var/backups/guix-initd-strays/ && sudo rc-update -u`, then confirm `rc-status default` now shows `guix-daemon [ started ]` and `guix processes` answers (exit 0). Prevention is a hard rule: never leave timestamped backups inside an init-scanned directory (`/etc/init.d/` under OpenRC, `/etc/rc*.d/` under sysv) — route them to `/var/backups/` or use a non-timestamped in-place rename. The safety habit itself was the multi-month bug (T480, 2026-07-27).

## KDE global-shortcut collision checks can't trust `kglobalshortcutsrc` — compiled-in defaults are invisible there

Plasma writes only *overridden* global shortcuts into `~/.config/kglobalshortcutsrc`; a service's compiled-in default lives in its registration and never appears in the file until the user changes it. So grepping the file for a candidate key reports "free" when the key is actually taken — exactly how `Meta+E` scanned as unbound while mirroring the rofi launchers onto SonicDE, got bound to the emoji picker, and lost the live conflict to Dolphin's default `Meta+E`→file-manager. This is the same declared-vs-observed trap as environment variables: `kglobalshortcutsrc` is necessary but not sufficient evidence. The D-Bus route (`qdbus6 org.kde.kglobalaccel /kglobalaccel org.kde.KGlobalAccel.allComponents`) can also come back empty depending on version, so the only reliable confirmation is pressing the key on the live session — the user's fingers are the ground truth, not the file.

There are two default sources, both invisible in `kglobalshortcutsrc`, and you must check both. (1) App/service shortcuts declared in the launcher's own `.desktop` via `X-KDE-Shortcuts=` — e.g. `org.kde.plasma.emojier.desktop` owns `Meta+.` and `org.kde.spectacle.desktop`'s `RecordRegion` action owns `Meta+Shift+R,Meta+R` — findable by grepping `/usr/share/applications/*.desktop` for `X-KDE-Shortcuts` (do this FIRST, before binding anything). (2) plasmashell/KWin internal actions like file-manager `Meta+E`, Overview `Meta+W`, Peek-at-Desktop `Meta+D`, Lock `Meta+L`, Display-config `Meta+P`, Klipper `Meta+V`, task-manager `Meta+1..0` — these are in no `.desktop` and only a live keypress reveals them. So there is no punctuation key that is "safe" by category: `Meta+.` looks free but is the Emoji Selector, `Meta+R` looks free but is Spectacle's region-recorder. To claim a key already owned by a default, override the owning entry in the same apply pass — set its service action to keep only the accelerators you want and drop the one you're taking (spectacle `RecordRegion` → keep `Meta+Shift+R`, drop `Meta+R`; emojier `_launch` → move off `Meta+.`; internal actions like Overview → `none`), never merely add your binding alongside — the same displace-don't-add discipline as the xfwm4 `Super+4` bug in `x11.org`. This very gotcha first shipped asserting `Meta+.` was "never a KDE default" and was wrong within the hour: no key is free until BOTH the `.desktop` grep and a live keypress say so (T480, 2026-07-11).

There is a second observation point that bites identically: the *running* `kglobalacceld` daemon, not the file. Editing `~/.config/kglobalshortcutsrc` from outside the Plasma session — an SSH shell, cron, or an agent's tool subprocess (no `DBUS_SESSION_BUS_ADDRESS`/`DISPLAY`) — writes the file but cannot reload the daemon, so the shortcuts are declared-but-not-grabbed: the keys silently do nothing, or the old default still fires. `plasma-apply-preferences`'s `qdbus … || true` reload is a no-op in that context and once reported a false "applied" while a 2-day-old daemon held the stale grabs (its own guard now detects an unreachable bus and prints the reload steps instead). A config write is NOT a live grab. To actually load changes, run INSIDE the session: `kbuildsycoca6` (so new launcher `.desktop`s resolve) then bounce the daemon — `kquitapp6 kglobalacceld; setsid -f env -u LD_PRELOAD /usr/lib/x86_64-linux-gnu/libexec/kglobalacceld` — or simply log out and back in. An agent editing this file from its subprocess can never confirm its own work; only a keypress in the user's live session can (T480, 2026-07-11).

Third facet, the one that actually blocked a launcher suite for a whole session: a hand-written `[services][X.desktop] _launch=` entry does NOT register a global shortcut for a *custom* launcher. kglobalaccel only grabs shortcuts for services that declare `X-KDE-Shortcuts=` in their own `.desktop` (as the built-in Emojier and Spectacle do) or were assigned live via System Settings — a bare `_launch` line for a `.desktop` KDE doesn't already know as a shortcut owner is silently ignored. The fix for a custom launcher (rofi-launch, etc.) is to put the accelerator IN the `.desktop` (`X-KDE-Shortcuts=Meta+Space`) and rebuild sycoca, NOT to write kglobalshortcutsrc and hope. Confirmed 2026-07-11: with the `_launch` entries present and the daemon fresh, the keys fired nothing; adding `X-KDE-Shortcuts=` to each `.desktop` made them work on the next login. The kglobalshortcutsrc `_launch` entry is still useful — it sets the *active* value and lets you *displace* a conflicting default (e.g. move the Emojier off `Meta+.`) — but it cannot *create* a grab for an unregistered launcher (T480, 2026-07-11).

## Tailnet ACL reachability is tested with `tailscale ping`, never a port probe

`nc -z host 22` conflates "walled by ACL" with "no listener on that port" — a Windows box with no sshd times out identically to a blocked one, and an ACL was nearly misdiagnosed as broken this way (2026-07-11). `tailscale ping -c 5 <host>` tests the WireGuard path itself, independent of services; idle NAT'd peers may need several attempts (`-c 5`) to wake via DERP. Second trap the same day: ACL packet-filter drops happen after decryption, so the tunnel pings fine while a specific src→dst pair is dropped silently — invisible to tcpdump on either end. When one peer reaches a host and another cannot, read the target's inbound filter (`tailscale status --json` or the admin console), don't chase the network.

## A running binary can't be overwritten in place — curl to temp + `mv`

`curl -o ~/.local/bin/tool` onto a binary that is currently executing fails with `curl: (23) Failure writing output` ("text file busy" underneath), so self-hosted daemons silently never update through a naive download lane (herdr on X230 stayed at 0.7.1 this way, 2026-07-11). Download to `dest.tmp.$$`, `chmod +x`, then `mv -f` — rename is atomic and lands even while the old binary runs. The `app-apply` curl_bin lane does this correctly now; keep the pattern for any ad-hoc binary fetch.
