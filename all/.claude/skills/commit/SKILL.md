---
name: commit
description: /commit — Structured Git Commit
---

# /commit — Structured Git Commit

You are creating a well-structured git commit. The user may provide a hint: $ARGUMENTS

## Steps

1. Run `git status` (never `-uall`) and `git diff --staged` + `git diff` to understand all changes.

2. **Classify the change type:**
   - `feat` — new feature or capability
   - `fix` — bug fix
   - `refactor` — restructuring without behavior change
   - `docs` — documentation only
   - `chore` — maintenance, config, dependencies
   - `tangle` — org source block changes that affect tangled output

3. **Determine scope from file paths:**
   - `emacs` — emacs.org, shared profile/build policy
   - `shell` — shell.org, bash/zsh config
   - `flatpak` — package-flatpak.org, Flatpak management
   - `loom` — loom.org, Makefile, control plane
   - `style` — style.org, LainCore theme
   - `tools` — tools.org, misc tooling
   - `stow` — overlay dirs, stow config
   - `pkg` — package manifests (pip, npm, cargo, guix, etc.)
   - Use the most specific scope that fits

4. **Build the commit message:**
   ```
   TYPE(SCOPE): one-line summary (imperative mood, <72 chars)

   - bullet point details of what changed
   - focus on WHY not just WHAT

   ```

5. **Refresh visibility before staging:**
   - If the work changes outstanding tasks, update the relevant `~/HelmCortex/LOGS/TODO/{workspace}.md` file.
   - If the work is machine-specific, update `~/HelmCortex/LOGS/TODO/Machines/{hostname}.md`.
   - If a durable lesson crystallized, run or recommend `/reflect` and persist the lesson to the narrowest real source of truth before committing.
   - If no TODO or reflection update is warranted, say so briefly in the commit report.

6. **Stage specific files** — NEVER use `git add .` or `git add -A`. Add files by name. If unsure which files belong, ask.

7. **Commit** using a HEREDOC for the message to preserve formatting.

8. Show `git log -1` to confirm.

9. **Post-commit sync reminder** — after every DotCortex commit, remind the user to sync other machines:
   - Push when ready: `git push`
   - On each other machine with a separate DotCortex checkout (X230, T480s, or any SSH-connected host):
     ```
     git pull --ff-only
     loom stow:x230      # or loom stow:t480s — match the target machine
     ```
   - If the repo is NFS-mounted (same working tree, no separate checkout), no pull is needed — but stow must still be re-run on each machine that needs the updated symlinks.
   - If a machine cannot fast-forward (diverged history), stop and investigate before merging.

## Rules

- If there are no changes, say so and stop.
- Refuse to commit from a dirty tracked worktree. If tracked unstaged changes exist outside the intended commit, stop and ask the user whether to split, stage, or stash them first. Exception — multi-writer repos with live concurrent sessions (HelmCortex, DotCortex on the fleet): pre-existing dirt from other lanes is expected; commit surgically instead of stopping, per the multi-writer rules below.
- Multi-writer repos: inspect the staged index before committing and use explicit, nonempty pathspecs to preserve other lanes' staged files. Never delete a live index lock; identify its holder and wait. Repair an accidental sweep with a new corrective commit; never reset, amend, or rewind shared `master`.
- Pathspec commits read the working-tree file, even with `GIT_INDEX_FILE`; selecting a path does not isolate your hunks. Review pre-existing edits within every selected file. When the intended commit differs from its live contents, use an isolated temporary worktree and index, verify the resulting commit diff, and preserve the original working file and staged delta.
- If changes span multiple unrelated scopes, suggest splitting into multiple commits.
- If the user's hint conflicts with what the diff shows, trust the diff.
- Never commit generated/tangled output without the canonical `.org` source in the same commit.
- Never use `git add .`, `git add -A`, or a broad pathspec that sweeps unrelated files into the commit.
- Cross-machine sync is always explicit: `git pull --ff-only` before editing on any machine, push immediately after an approved commit. Uncommitted work on one machine is not synchronisation.
- Never push directly to a remote working tree over SSH without confirming it is clean — a dirty remote will reject the push or fall out of sync with stow.
- Do not push unless explicitly asked.
- Remember: `.org` files are the source of truth, tangled output files are generated.
- Commit closeout is a visibility gate: TODO state and reflection-worthy lessons should not be left only in chat context.
