# DotCortex — Agent Instructions

This file is for OpenCode, Codex, and other non-Claude agents working in this repository.
Claude Code users: `CLAUDE.md` carries the harness-specific Claude guidance.
Source of truth for both files: `agents.org`.


## What This Is

DotCortex is Mètsàtron's declarative, literate, reproducible dotfiles system. Org-mode files are the single source of truth. They tangle into overlay directories which GNU Stow symlinks into `$HOME`.

## Architecture

```
*.org files  ->  tangle  ->  overlay dirs  ->  loom stow  ->  $HOME
```

- **Org files** (root level): canonical source for all configs, scripts, manifests
- **Overlay dirs**: `all/` (shared), `linux/`, `debian/`, `devuan/` (sysv-init), `x230/` (X230 ThinkPad), `t480s/` (T480s ThinkPad), `arch/`, `osx/`, `be/`, `navi/`
- **Stow**: symlinks overlay contents into `$HOME`, stacked in priority order
- **Loom**: Guile Scheme control plane (`~/.local/bin/loom`) with 50+ task verbs -- requires Guix guile. Without Guix, use `make` targets directly.

## Critical Rules

1. **Never edit tangled output** -- files inside overlay dirs (`all/`, `linux/`, `debian/`, `devuan/`, `x230/`, `t480s/`, `be/`, `navi/`, `arch/`, `osx/`) are generated. Edit the `.org` source at repo root instead.
2. **Never edit the Makefile directly** -- it is tangled from `loom.org`. Edit `loom.org` instead.
3. **Org files are canonical** -- every config, script, and manifest is defined inside an org code block with a `:tangle` target.
4. **Stow target is `$HOME`** -- the repo lives at `~/DotCortex`.
5. **Stow via loom** -- use `loom stow:x230` or `loom stow:t480s` for normal operations. `make safe-stow` is only for first-time bootstrap before loom is functional, or when Guix is unavailable. Never use plain `stow` directly.
6. **Follow existing patterns** -- new package managers get: `.org` file + SSV manifest + capture/diff/apply/health scripts + `.mk` Makefile fragment + loom verbs in `loom.org`.
6a. **Never install packages directly** -- never run `pip install`, `guix install`, `flatpak install`, `cargo install`, `npm install -g`, or any package manager CLI directly. Always: (1) edit the relevant `.org` file (e.g. `package-pip.org`, `package-guix.org`), (2) add the package to the manifest SSV block, (3) `tangle-one <file>.org`, (4) run the appropriate `loom <mgr>:apply`. The `.org` files are the single source of truth; bypassing them leaves the system in an undeclared state.
7. **Check Guix profiles before assuming tools aren't installed** -- emacs, nvim, zsh, guile, and other Guix tools live at `~/.guix-extra-profiles/core/core/bin/`, not in system PATH.
7a. **Detect the actual service substrate before operating** -- an OS family, hostname table, overlay name, or machine document is not proof of the running init system. Before recommending or executing a service command, inspect the target machine's `/etc/os-release`, `ps -p 1 -o comm=,args=`, `readlink -f /sbin/init`, and the actual command paths for the proposed manager. Never emit `systemctl`, `rc-service`, `sv`, `s6-*`, `dinit`, or SysV commands from a label alone; record the observed substrate and use only commands that exist on that target.
7b. **Recursive discovery stays on an explicitly bounded local filesystem** -- before running `find`, recursive `grep`/`rg`, `du`, or an equivalent tree walk, resolve the exact root and its mount boundary. Never begin at `$HOME`, `/home`, or another ancestor that may contain fleet NFS/autofs mounts. Target the narrowest known directory and use `-xdev`, `--one-file-system`, explicit excludes, or an already-materialized local index as appropriate. A userspace timeout cannot interrupt a process blocked in kernel NFS D-state, so timeout alone is not containment.
8. **All agent work lives in `.org` files** -- skills, hooks, plugins, custom instructions, and settings are authored in org source at repo root and emitted by tangle. Never write directly to harness directories. This includes:
   - New skills: add to the `agents-skills*.org` family with the correct tangle target(s) — `agents-skills.org` (schema, session skills, universal tools), `agents-skills-dotcortex.org`, `agents-skills-helmcortex.org`, or `agents-skills-harness.org` by scope
   - New hooks or settings: `agents-hooks.org`
   - New Claude plugins: `agents-hooks.org` (plugins.ssv + settings.json)
   - New OpenCode plugins: `package-npm.org` (bun install) and `agents-hooks.org` (opencode config block)
   - New custom instructions: `agents.org` (this file)
9. **Skills over commands** -- skills are universal across harnesses; harness-specific commands are not portable. Add new agent capabilities as skills in the `agents-skills*.org` family, not as commands.
10. **Never commit from a dirty tracked worktree** -- if `git diff --name-only` shows tracked unstaged changes, stop. Do not commit "just your files" and leave the rest dirty. Split the work intentionally or ask.
10a. **WIP staging / rollback checkpoint law** -- before editing any source-controlled file, establish a reversal point. First run the repo git status. If the target file already has unstaged changes, stage that exact path before editing so the pre-edit state is recoverable from the index. If creating a new source file, stage that exact new path immediately after creation before continuing. For destructive edits, broad rewrites, generated-output sweeps, moves, deletes, or cross-repo source changes, create a narrow `wip: checkpoint before <description>` commit covering the exact affected paths before proceeding. Checkpoint commits are standing-authorized for rollback safety, but must never include unrelated dirty work.
10b. **Single-writer path and deployment law** -- before delegated or concurrent work, assign one writer to each exact source path and record its pre-edit hash. Recheck that hash immediately before every write, tangle, or deployment. If it changed unexpectedly, stop all writers for that path, preserve every version, identify the owner, and reconcile from source before continuing; never overwrite, tangle through, or deploy across unexplained drift. Subagents may build and test candidates, but only the coordinator crosses the live apply/restart/enable gate after reviewing the final source and generated artifacts.
11. **Never commit generated output without canonical source** -- if `all/`, `linux/`, `debian/`, `devuan/`, `x230/`, `t480s/`, `AGENTS.md`, `CLAUDE.md`, or `Makefile` changed, the corresponding `.org` source must be included in the same commit.
12. **Commit verified work via `/commit`; never push without explicit instruction** -- after useful verified work, commit via the `/commit` skill (which emits the post-commit sync reminder). Do not push or pull between machines unless explicitly asked — pushing triggers multi-machine sync. Stage only intended files; never commit unrelated tracked-file dirt.
12a. **Never run `git pull` on a remote machine without explicit per-machine instruction** -- `git pull` on a remote machine via SSH is as destructive as `git push`. It can silently overwrite uncommitted working state if the incoming changes don't conflict (git fast-forward succeeds even with an otherwise-dirty tree). Never chain `git pull && loom stow:X` on a remote unless the user has explicitly said "pull and stow on X". The correct sync flow is: commit locally → push (with explicit permission) → user pulls on each other machine themselves. Use `dotcortex-pull` for any pull that must be automated — it checks for dirty state first and aborts.
12b. **Never walk past a dirty worktree** -- when `git status` reveals dirty tracked files on any machine (local or remote), stop and assess them. Group them by work/scope, determine what they belong to, and handle them explicitly: commit what is ready, stash what is in-flight, or flag what needs investigation. Do not proceed with unrelated work and leave the mess for later. A dirty worktree is someone's in-progress work — treat it with respect: commit in-flight work as a `wip:` checkpoint on its own, never sweep it away into a stash to clear your path.
12c. **Never leave unresolved conflict markers in a stowed repo** (sealed 2026-08-05, the Auryn stash-pop disaster) -- DotCortex's overlay dirs are stowed via symlinks into `$HOME`. Conflict markers in a tangled script are live syntax errors in `~/.local/bin/`. Three rules: (1) prefer `git stash apply` over `git stash pop` — `apply` keeps the stash as a rollback point; `pop` destroys it on success and leaves markers on failure with no clean copy; (2) never run `git stash pop`, `git merge`, or `git rebase` without a checkpoint commit of the current state first; (3) if a conflict occurs, resolve it or `git merge --abort` / `git checkout --merge` **in the same turn** — never leave markers on disk across a compaction, permission block, or session boundary. The `tangle-one` and `org-style-lint` guards will refuse to tangle a conflicted source, and the SessionStart hook will announce broken overlay files, but the best defence is never producing them.
12d. **Never run conflict-producing git operations on a remote DotCortex checkout** (sealed 2026-08-05, the Wunder-Tanuki SSH disaster) -- an agent may run non-integrating git (e.g. `status`, `log`, `diff`, `fetch`, `ls-files`, `branch`) on any DotCortex checkout — local, NFS-mounted (`~/mnt/*/DotCortex`), or over SSH. But conflict-producing operations (`stash pop`, `stash apply`, `merge`, `rebase`, `pull`, `cherry-pick`) may only target the checkout on the machine the agent is physically running on. This applies regardless of transport: `ssh <host> "cd ~/DotCortex && git merge"` and `git -C ~/mnt/<host>/DotCortex merge` are equally forbidden. The reason is irreparability: an agent that produces conflicts on a remote checkout cannot tangle, stow, or verify the result on that machine, and the stow symlink chain means every conflict marker is a live syntax error in that machine's `$HOME`. Claude Code's PreToolUse hook enforces this for its own Bash calls; the `.githooks/post-merge` hook catches it cross-harness. Agents running outside Claude Code (Telegram bots, Codex, etc.) must honour this rule from their own instruction context — there is no hook on the NFS path that can prevent a write before it happens.
12e. **A stash is transport, never storage** (sealed 2026-08-10, the GNUstep rug-pull) -- a stash entry is work held in an unreferenced object, one forgotten pop or one `git gc` from oblivion, and `git stash` instantly reverts every tracked file to HEAD — on a stowed repo that rewrites the live `$HOME` in the same second. On 2026-08-06 an agent deploying cross-machine hit T480s's dirty tree, pushed a "pre-pull safety stash" to force its pull through, and never popped it: four days of uncommitted work (the entire GNUstep NeXT sanctuary polish, 62KB of Doom config, and more) silently reverted, and the user rebuilt on top of the rug-pull before anyone noticed. Three rules: (1) every `git stash push` must be resolved within the same operation — applied back, or preserved as a real ref (`git tag rescue/<name> <stash-sha> && git stash drop`) — and never left across a session boundary; (2) never stash around a dirty tree to force a pull through — dirt on the pull target means stop and ask (rule 12b), and automated pulls go through `dotcortex-pull`, which aborts on dirt instead of hiding it; (3) the stash only collected the debt — the debt itself was multi-day uncommitted work, which rule 12 already forbids: commit logical units as they complete. Enforcement: the commit guard refuses to commit while any stash entry exists (`DOTCORTEX_GUARD_ALLOW_STASH=1` overrides once, for triage), and the post-merge hook announces surviving stashes after every merge/pull.
13. **Cross-machine sync is explicit** -- for work that must exist on T480s, T480, X230, and S24, use one canonical upstream, `git pull --ff-only` before editing on a machine, and push immediately after an approved commit. Uncommitted work on one machine is not synchronization.
14. **Operate on the target repo root** -- when tangling or running git in mounted/mirrored checkouts, target the actual repo containing the file, not an assumed `~/DotCortex` path. Never assume the local machine repo is the intended target.
15. **"Take care of it" means preserve intent** -- when the user says to "take care of it" about a staged or tracked change, stage and commit the current intended content unless the user explicitly asks for source edits. Do not delete, revert, or silently rewrite it. If a plan was already proposed, "take care of it" means execute that plan.

16. **Change Safety Protocol** -- When editing any file, especially config files:
    - **Read first** -- Always read the full file before making changes. Do not edit a file you have not read completely.
    - **Check file state before touching** -- Use `ls -la` or `stat` to verify the file exists and its current timestamp. Never assume a file is in an expected state.
    - **Checkpoint destructive ops** -- Before making destructive edits to a config file (rewrite, revert, restore from backup), make a timestamped backup: `cp file file.backup-$(date +%Y%m%d-%H%M%S)`.
    - **Never revert to old backup without permission** -- If something goes wrong, do NOT grab an old backup without explicit user confirmation. Ask first.
    - **Stop on edit failure** -- If an edit goes wrong (tool error, file corrupted, structure broken), STOP immediately. Do not continue editing to "fix it". Call `reflect` or ask the user what to do.
    - **No panic edits** -- If you made a mistake, do NOT rush to fix it. Embarrassment and urgency cause more damage. Pause, think, then proceed carefully.
    - **Verify incrementally** -- After each edit, verify the file is in the expected state with `head` or `tail`. If something looks wrong, stop.
    - **Restore is destruction** -- Restoring a file overwrites current state with older state. This is always destructive. Require explicit permission before restoring any file, especially non-DotCortex config files in `~/.hermes/`, `~/.config/`, etc.

16a. **Patch-managed deployment preflights the complete series before live mutation** -- validate every ordered patch and generated seam against a pristine staged copy of the pinned upstream runtime before reinstalling, upgrading, or editing the live environment. A per-patch dry run performed only after the live package has already changed is not a preflight and can strand a partially modified runtime. Cross the live mutation gate only after the complete staged series applies and its structural checks pass; otherwise leave the live runtime byte-for-byte unchanged and fail loud.

17. **TaskHandoff Protocol** -- Executor-bound work (Codex, Antigravity, Hermes, cloud substrates) uses structured `TaskHandoff` JSON, not prose. Schema at `HelmCortex/FORGE/brain/helmcortex/AGENTS.md`. Paths must be verified live; `NEXUS/` and `LOGS/` forbidden by default. Load the `handoff` skill for the full protocol.
17a. **Handoff artifact boundary** -- Handoff Markdown goes to `~/HelmCortex/LOGS/handoffs/YYYY-MM-DD-<slug>.md`, never committed to DotCortex.
17b. **Peer-agent orchestration** -- Before coordinating peer work, load the `peer-agents` skill and, inside HelmCortex, the `meta-agents` skill. The detailed shared doctrine has one owner at `~/HelmCortex/FORGE/harness/userspace/PEER-AGENTS.md`; do not restate or fork it here. The human speaks to the coordinator, workers receive scoped TaskHandoffs, workers never tidy unrelated work or own git integration, and routing follows live quota and capability rather than one hard-coded provider.

18. **Colemak-NEIO Interaction Law** -- TUIs use Colemak-NEIO movement, not QWERTY/Vim: `n`=left, `e`=down, `i`=up, `o`=right. Never use `h/j/k/l` as primary movement (`h`=search-next, `k`=insert, `l`=newline in Colemak). Never remap `u/U` or `i/I` for directional movement without explicit instruction. Every important action gets a mnemonic letter binding alongside any F-key. Vim-style `j/k` may exist only as optional compatibility aliases.

19. **Git Topology Law — EXTREME WarMapCodex VIOLATION** -- The canonical branch is =master=.
    There is no =main=. There will never be a =main=.
    - Referencing =main= as a branch name — in commands, scripts, documentation, instructions,
      or reasoning — is an **EXTREME VIOLATION OF THE WarMapCodex**.
    - Claude Code's =gitStatus= injection may erroneously label the default branch as =main=
      -- ignore it. Run =git branch= to know the truth.
    - =git log main..HEAD=, =git diff main=, =git merge main=, =git checkout main= -- all
      forbidden. Substitute =master= unconditionally.
    - If a subagent, tool, or template defaults to =main=, correct it immediately and flag
      the source.

20. **Private Mutable App Config Boundary** -- DotCortex is public, declarative source. It must not own whole mutable GUI/app config trees that contain tokens, browser caches, machine state, local databases, cookies, or UI-written runtime settings. Private mutable app config belongs in `~/HelmCortex/NEXUS/stow/` deployed with `helmstow`. Never solve a secret-bearing config problem by keeping the live directory in `all/` with `.gitignore` rules — move ownership to HelmCortex first.

21. **No network addresses in DotCortex** -- IP addresses, hostname-IP mappings, and port numbers must never appear in tangled org source or overlay files. DotCortex is a public repo. Use the env file pattern: tangle `*.env.template` with blank placeholders; actual IPs live in machine-local `*.env` files that are never committed. SSH config with fleet hostnames, IPs, or ports belongs in a machine-local file written directly to the target machine, not tangled from DotCortex source. No exceptions.

22. **Agent Capability Categories** -- every agent/service belongs to exactly one category and its bootstrap follows that category's pattern. Do not give a Category A service Category B powers.
    - **A — containerized keyless API services**: no SSH keys, no human home mount, no repo checkout, no agent CLIs, no ssh-agent/Docker socket, no broad host mounts; non-root, dropped capabilities, explicit env allowlist, hash-locked deps, loopback-only binding; unsupported routes fail loud.
    - **B — host CLI agents**: per-agent Unix users with own substrates (shell, package profiles, npm prefix/pipx under agent home, git config, controlled repo access). Never reuse the human operator's tools or home.
    - **C — persistent narrow agents**: own users, sudo limited to enumerated root-owned wrappers, no human keys, no backup-destruction capability.
    - **D — client-side agents**: per-client revocable identities, never trusted with personal-mesh credentials.
    Container env files are explicit allowlists: strip `export` prefixes and surrounding quotes when deriving from shell-sourced env files.

23. **Sanctuary container removal — permanent law** -- never run `distrobox rm` / `podman rm` on any sanctuary container without: (1) a fresh `podman diff` review of the writable layer shown to the user BEFORE asking permission, (2) explicit per-container confirmation naming the exact container, freshly worded immediately before the irreversible step, (3) one container at a time, never batched. Prefer non-destructive alternatives (stop/restart/kill processes) first. Restarting or killing processes is fine — this law covers only destruction and recreation. Load `sanctuary-gotchas` for the full rationale and protocol.

## Agent Config Scoping

| Path | Harness | Notes |
|------|---------|-------|
| `.claude/` | Claude Code only | `CLAUDE.md`, settings, skills, hooks |
| `.opencode/` | OpenCode only | Plugins, bun packages, OpenCode-specific skills |
| `.codex/` | Codex only | Codex-specific config and skills |
| `.agents/` | Universal (non-Claude) | Skills and config for OpenCode, Codex, and future agents |

**DotCortex stow-global holds exactly six skills**: `loom`, `tangle`, `prime`, `commit`, `todo`, `handoff`. New skills almost always belong in the HelmCortex `userspace` lane instead. Load the `harness-bridge` skill for the full two-lane bridge map, compiler traps, and cross-repo workflow.

## Research Protocol

Before investigating unknown tool APIs, agent conventions, or external system behavior, load the `research-agents` skill and follow its role taxonomy and routing doctrine. Check Recall and the local corpus first for existing knowledge; ground outside claims in cited research rather than speculation.

**Drive available research tools yourself.** For subscription-backed research through Agentify MCP, load the `agentify` skill, read the routing table, and query inside the scope's ChatGPT Project or Perplexity Space. Follow its send-once, read-only polling, capture, and tab-hygiene rules. Load the relevant browser skill before page-level interaction. Do not hand Mètsàtron a prompt to run when an available agent-directed lane can complete the research.

**Manual handoff is a fallback.** Surface a research prompt for Mètsàtron only when he explicitly requests a manual lane or the required lane needs human intervention (such as login, CAPTCHA, or unavailable access). State the concrete blocker and the best lane, then stop and wait for that handoff; never speculate past it. Format:

```
META-AGENT RESEARCH PROMPT [lane]:
[single-focus question with tool names, versions, and what you need to determine]
```

Lanes: **Perplexity** (default — multi-source synthesis with citations), **ChatGPT** (second opinion / deeper reasoning), **Brave Leo** (faithful search-result reading, free), **Reddit** (practitioner ground truth — **hard limit: the question body must be ≤ 500 characters**; the Reddit lane rejects anything longer, so tighten the prompt or route the detail to another lane). For decision-grade questions, request two lanes and reconcile.

## Model Guidance

- Main session model cannot be changed autonomously -- use `/model sonnet|haiku` yourself.
- **The subagent tier table has ONE home: the `subagent-routing` skill**. Load it before spawning subagents. It carries the current tier rulings and supersedes any tier table restated here.
- Always set the `model` parameter explicitly per subagent; never silently switch model -- state which model and why, one line.
- Skill `model:` frontmatter is **BANNED in every scope** -- it silently switches the executing model. Model hints live as inert `<!-- model -->` comment blocks instead.

## Build & Apply

```bash
cd ~/DotCortex
make tangle                  # tangle all org files
tangle-one agents.org        # tangle a single org file (preferred)
make preview-stow            # dry-run stow
loom stow:x230               # X230: all linux debian x230
loom stow:t480s              # T480s: all linux debian devuan t480s
STOW_PKGS='all linux debian devuan t480s' make safe-stow  # without loom
```

Load `dotcortex-packages` for the full package manifest table, SSV format, loom verbs per manager, and how to add a new package manager.

## Key Files

- `Makefile` -- build entry point -- **tangled from `loom.org`**, never edit directly
- `loom.org` -- control plane, Makefile template, batch helpers
- `agents.org` -- source of truth for `AGENTS.md`, `CLAUDE.md`, and global `~/.claude/CLAUDE.md`
- `agents-skills*.org` -- all agent skills, split by scope: base (session + universal), `-dotcortex`, `-helmcortex`, `-harness`
- `agents-hooks.org` -- Claude settings, hooks, OpenCode config, plugin manifests
- Module namespaces: `package-*`, `desktop-*`, `emacs-*`, `agents-*`, `services-*`, `sanctuary-*` (Virtual Habitat guests; engine in `sanctuary-distrobox.org`), `tools-*`, plus standalone environment modules (shell, term, mux, x11, style, fonts, icons, menu). Every root source stays under the 100 KB module budget — `org-style-lint` warns on breach; split along section seams when it fires. New root modules use an existing prefix, or add the family to the `README.org` namespace table in the same commit — never invent a prefix (`org-style-lint` warns on names outside the table).
- `shell.org` -- bash/zsh rc, exports, aliases, functions, `.zshenv` (SSH PATH)
- `style.org` -- LainCore theme (fonts, colours, GTK, terminal, Emacs)
- `INSTALL.sh` -- bootstrap script for fresh machines
- `README.org` -- full Org documentation (the original grimoire)

## Finding What Owns a Config

```bash
grep -rn "tangle.*path/to/config" *.org
```

## Bootstrap

Load `dotcortex-bootstrap` for fresh-machine setup, first-tangle stubs, loom chicken-and-egg, Guix on non-systemd, and SSH PATH.

## Known Gotchas

Situational gotchas live in on-demand skills — load the relevant one rather than reading this section. See `dotcortex-gotchas` (stow, tangle, Guix), `sanctuary-gotchas` (XFCE, Xephyr, Flatpak audio, X11 ghost windows), `pi-agent-gotchas` (pi-coding-agent provider config).

## HelmCortex Integration

DotCortex and HelmCortex are fully decoupled. DotCortex does **not** stow files into HelmCortex. The only touchpoint: `.zshenv` adds `$HOME/HelmCortex/FORGE/bin` to `$PATH`. HelmCortex lives at `~/HelmCortex` (may be a symlink to a mount point).

## Multi-Machine Setup (Star Fleet)

System provenance per machine: `HelmCortex/CORTEX/GoldenAge_Loom/SteinerCortex/SystemCodex/Machines/`. Load `dotcortex-multihost` for init-system details, OpenRC gotchas, and fleet sync procedures.

| Machine | Init | Overlays | Verb |
|---------|------|----------|------|
| X230 (Debian) | systemd | `all linux debian x230` | `loom stow:x230` |
| T480s (Devuan) | sysv-rc | `all linux debian devuan t480s` | `loom stow:t480s` |
| T480 (Devuan) | **OpenRC** | `all linux debian t480` | `STOW_PKGS="all linux debian t480" make safe-stow` |
| S24 (Termux) | — | `all termux s24` | `loom stow:s24` |

T480 and T480s are **not** the same shape — T480 is OpenRC, T480s is plain sysv-rc. Never copy an init script between them.

Overlay scoping: `all/` (cross-platform), `linux/` (Linux-only), `debian/` (Debian-family), `devuan/` (sysv-init), then machine-specific dirs.

## Non-Claude Agent Rules

These rules apply to OpenCode, Codex, and any other non-Claude harness:

1. **Edit harness config through canonical source** -- `.claude/`, `.opencode/`, `.codex/`, and `.agents/` outputs may all be managed here, but changes must be made in the owning `.org` source and re-tangled. Do not hand-edit emitted harness files unless the user explicitly asks for that exact path.
2. **Agent config goes in the right directory** -- `.opencode/` for OpenCode-specific config, `.codex/` for Codex-specific config, `.claude/` for Claude-specific config, and `.agents/` for universal non-Claude skills. Shared doctrine may intentionally emit to multiple harness directories from one `.org` source.
3. **Skills are authored in the `agents-skills*.org` family** -- tangle to `all/.agents/skills/X/SKILL.md` for stow-global skills, `.agents/skills/X/SKILL.md` for DotCortex-scoped skills, or `.opencode/skills/X/SKILL.md` for OpenCode-exclusive skills. Do not write skill files directly. Note the stow-global lane is now nearly closed: DotCortex owns six skills, and anything about userspace or HelmCortex belongs in `HelmCortex/FORGE/harness/userspace/SKILLS.md` instead.
4. **Environment claims must come from the user's shell** -- an agent's tool subprocess does not share the user's interactive session environment. Never answer "is X set?" from your own subprocess. Have the user check, or read it from the specific live PID. If your reading disagrees with the user's, that disagreement is the finding — stop and reconcile. Never assert an environment fact in an outbound bug report unless observed in the user's actual shell.
5. **Config travels as a validated file, never as a chat blob** -- deliverable config goes to a FILE the user copies from a real editor. "Ready-to-paste" requires machine validation first: strict-parse, resolve all internal references, assert pure ASCII for untrusted transports.
6. **Verify your own output before confessing to it** -- when accused of emitting corrupt output, check the actual artifact before accepting blame. A false confession buries the real cause.
7. **Deny-by-default segmentation must enumerate intra-zone flows first** -- a household/site/team is a system whose members talk to each other (SMB, KeePass, local LLM servers). Enumerate intra-zone dependencies before cutover and machine-assert the isolation property.
