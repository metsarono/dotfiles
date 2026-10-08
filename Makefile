# -*- mode: makefile-gmake; indent-tabs-mode: t; tab-width: 8 -*-
.RECIPEPREFIX := |

EMACS ?= emacs
SCRIPT = all/.local/bin/dotfiles-batch.el
ROOT   = $(PWD)
GUIX ?= guix
GUIX_HOME := $(HOME)/.config/guix
EXTRA := $(HOME)/.guix-extra-profiles

# Stow packages you normally manage here
STOW_PKGS ?= all
# Stow target defaults to the current home; sanctuary helpers override it with
# the persistent guest home because the DotCortex checkout is a host-visible
# symlink from inside Distrobox.
STOW_TARGET ?= $(HOME)
# Stow conflict policy (layers.org "Adopting an existing account"): backup = legacy
# <file>.bak.<ts> and stow over it; adopt = dotcortex-stow-adopt (identical/skel only, else STOP).
STOW_CONFLICTS ?= backup
STOW_FLAGS = --target="$(STOW_TARGET)"

.PHONY: toc tangle all guix-pull guix-core guix-dev guix-gc guix-dirs \
        stow safe-stow x11-apply bridge-flatpak bridge-flatpak-reset preview-stow lint census odin\:deploy \
        layers-show layers-check auto-stow preview-auto-stow

lint:
| all/.local/bin/org-style-lint

# Make tangle depend on lint
tangle: lint

# Guix profile sets EMACSLOADPATH without trailing : which hides default lisp paths (cl-lib etc)
export EMACSLOADPATH := $(if $(EMACSLOADPATH),$(addsuffix :,$(EMACSLOADPATH)),)

EMACS_BATCH = $(EMACS) --batch -Q \
  --eval "(setq create-lockfiles nil make-backup-files nil auto-save-default nil backup-inhibited t vc-make-backup-files nil)"

toc:
| $(EMACS_BATCH) --eval '(load-file "$(SCRIPT)")' --eval '(dotfiles-batch-update "$(ROOT)")'

tangle:
| $(EMACS_BATCH) --eval '(load-file "$(SCRIPT)")' --eval '(dotfiles-batch-tangle "$(ROOT)")'

# census = does org-element parse every src block the raw text declares?
# Divergence means blocks are silently dropped from tangling. Fatal.
census:
| $(EMACS_BATCH) --eval '(load-file "$(SCRIPT)")' --eval '(dotfiles-batch-census "$(ROOT)")'

# all = toc → tangle → census → guix-dirs
all: toc tangle census guix-dirs

# Plain stow
stow:
| cd $(HOME)/DotCortex && stow $(STOW_FLAGS) $(STOW_PKGS)

# Safe stow with timestamped backups of real files
# LESSON: stow 2.4+ changed conflict message format from:
#   "existing target is neither a link nor a directory: FILE"
# to:
#   "cannot stow PKG/FILE over existing target FILE since neither a link nor a directory"
# We match both patterns plus:
#   "existing target is not owned by stow: FILE"
# If preview reports "existing target is stowed to a different package",
# abort before backing up/removing anything: that target is already repo-owned.
#
# LESSON (2026-07-27, the .codex migration): repair_mutable_agent_dir converts a
# whole-directory agent symlink (~/.codex -> NEXUS/stow/userspace/.codex) back
# into a real local directory and moves the runtime state home. Across a mount
# boundary `mv` is copy-then-unlink, so a LIVE process writing into the source
# makes the unlink fail AFTER the copy has already succeeded. Under `set -e`
# that aborted the entire safe-stow: the migration was actually complete, but
# stow never ran and the failure read as "nothing worked".
# A failed move is now non-fatal and distinguishes the two cases — destination
# already arrived (partial move, only the source needs clearing) versus nothing
# copied (fall back to cp -a). Leftovers are reported loudly and stow continues.
# Never re-tighten this into a bare `mv` under set -e.
#
# Host stow lanes (package-host-excludes.org, "Stow lanes"): a host's `stow`
# rows become --ignore arguments for every package and its `stow-hook` rows
# skip post-stow helpers. `stow -D` honours ignores too, so links made before a
# path was excluded are pruned first (links into this checkout only, never real
# files). A host without stow rows gets no arguments and no prune.
safe-stow:
| set -euo pipefail; \
| cd $(HOME)/DotCortex; \
| STOW_GUARD="$(HOME)/.local/bin/dotcortex-stow-target-guard"; \
| [ -x "$$STOW_GUARD" ] || STOW_GUARD="$(HOME)/DotCortex/all/.local/bin/dotcortex-stow-target-guard"; \
| [ -x "$$STOW_GUARD" ] || { echo "safe-stow: missing dotcortex-stow-target-guard — refusing to continue" >&2; exit 1; }; \
| "$$STOW_GUARD" --packages "$(STOW_PKGS)"; \
| if [ "$(STOW_CONFLICTS)" = adopt ]; then \
|   ADOPT="$(HOME)/.local/bin/dotcortex-stow-adopt"; \
|   [ -x "$$ADOPT" ] || ADOPT="$(HOME)/DotCortex/all/.local/bin/dotcortex-stow-adopt"; \
|   echo ">> adopt pre-existing files (STOW_CONFLICTS=adopt)"; \
|   "$$ADOPT" --apply --dir "$(HOME)/DotCortex" --target "$(STOW_TARGET)" --packages "$(STOW_PKGS)"; \
| fi; \
| repair_mutable_agent_dir() { \
|   local rel="$$1" target="$(HOME)/$$1" resolved entry name rel_entry ts backup; \
|   [ -L "$$target" ] || return 0; \
|   resolved=$$(readlink -f "$$target" 2>/dev/null || true); \
|   echo ">> repair mutable agent dir $$target"; \
|   rm -f "$$target"; \
|   mkdir -p "$$target"; \
|   [ -n "$$resolved" ] && [ -d "$$resolved" ] || return 0; \
|   for entry in "$$resolved"/* "$$resolved"/.[!.]* "$$resolved"/..?*; do \
|     [ -e "$$entry" ] || [ -L "$$entry" ] || continue; \
|     name=$$(basename "$$entry"); \
|     rel_entry=$${entry#$(HOME)/DotCortex/}; \
|     if git ls-files --error-unmatch "$$rel_entry" >/dev/null 2>&1 || git ls-files "$$rel_entry/" | grep -q .; then \
|       continue; \
|     fi; \
|     if [ -e "$$target/$$name" ] || [ -L "$$target/$$name" ]; then \
|       ts=$$(date +%Y%m%d-%H%M%S); \
|       backup="$$target/$$name.bak.$$ts"; \
|       echo "   backup existing $$target/$$name -> $$backup"; \
|       mv "$$target/$$name" "$$backup"; \
|     fi; \
|     echo "   move runtime $$entry -> $$target/$$name"; \
|     if mv "$$entry" "$$target/$$name" 2>/dev/null; then \
|       continue; \
|     fi; \
|     if [ -e "$$target/$$name" ] || [ -L "$$target/$$name" ]; then \
|       echo "   !! partial move: $$target/$$name arrived, source not released"; \
|     else \
|       cp -a "$$entry" "$$target/$$name" 2>/dev/null || { \
|         echo "   !! FAILED to migrate $$entry — left in place, stow continuing"; \
|         continue; \
|       }; \
|     fi; \
|     rm -rf "$$entry" 2>/dev/null || \
|       echo "   !! source still held: $$entry — stop the app writing it, then re-run"; \
|   done; \
| }; \
| repair_mutable_agent_dir .claude; \
| repair_mutable_agent_dir .agents; \
| repair_mutable_agent_dir .opencode; \
| repair_mutable_agent_dir .codex; \
| EXCL="$(HOME)/.local/bin/dotcortex-stow-excludes"; \
| [ -x "$$EXCL" ] || EXCL="$(HOME)/DotCortex/all/.local/bin/dotcortex-stow-excludes"; \
| HOST_STOW_IGNORES=""; \
| if [ -x "$$EXCL" ]; then \
|   HOST_STOW_IGNORES=$$("$$EXCL" ignore-args | tr '\n' ' '); \
|   if [ -n "$$HOST_STOW_IGNORES" ]; then \
|     echo ">> host stow excludes (package-host-excludes.org): $$("$$EXCL" paths | tr '\n' ' ')"; \
|     "$$EXCL" prune --apply --target "$(STOW_TARGET)" --repo "$(HOME)/DotCortex"; \
|   fi; \
| fi; \
| for pkg in $(STOW_PKGS); do \
|   preview_file=$$(mktemp); \
|   echo ">> preview $$pkg"; \
|   stow $(STOW_FLAGS) -n --ignore='\.bak\.' $$HOST_STOW_IGNORES $$pkg >"$$preview_file" 2>&1 || true; \
|   if grep -q 'existing target is stowed to a different package:' "$$preview_file"; then \
|     cat "$$preview_file"; \
|     rm -f "$$preview_file"; \
|     exit 1; \
|   fi; \
|   sed -n \
|       -e 's/.*existing target is neither a link nor a directory: \(.*\)$$/\1/p' \
|       -e 's/.*over existing target \(.*\) since neither.*/\1/p' \
|       -e 's/.*existing target is not owned by stow: \(.*\)$$/\1/p' \
|       "$$preview_file" \
|     | { grep -v '^HelmCortex$$' || true; } \
|     | while read -r t; do \
|         case "$$t" in "$(STOW_TARGET)"/*) abs="$$t" ;; /*) abs="$$t" ;; *) abs="$(STOW_TARGET)/$$t" ;; esac; \
|         if [ -e "$$abs" ] || [ -L "$$abs" ]; then \
|           if [ "$$t" = ".config/opencode/opencode.json" ]; then \
|             HELPER="$(STOW_TARGET)/.local/bin/dotcortex-opencode-config-merge-guard"; \
|             [ -x "$$HELPER" ] || HELPER="$(STOW_TARGET)/DotCortex/all/.local/bin/dotcortex-opencode-config-merge-guard"; \
|             if [ -x "$$HELPER" ]; then \
|               "$$HELPER" apply; \
|               continue; \
|             fi; \
|           fi; \
|           ts=$$(date +%Y%m%d-%H%M%S); \
|           echo "   backup $$abs -> $$abs.bak.$$ts"; \
|           cp -a "$$abs" "$$abs.bak.$$ts"; \
|           echo "   remove  $$abs"; \
|           rm -rf "$$abs"; \
|         fi; \
|       done; \
|   rm -f "$$preview_file"; \
|   echo ">> stow $$pkg"; \
|   if stow $(STOW_FLAGS) --ignore='\.bak\.' $$HOST_STOW_IGNORES $$pkg 2>&1; then \
|     true; \
|   else \
|     echo ">> stow $$pkg conflict — retrying with --ignore=HelmCortex"; \
|     stow $(STOW_FLAGS) --ignore='HelmCortex' --ignore='\.bak\.' $$HOST_STOW_IGNORES $$pkg; \
|   fi; \
| done; \
| case " $(STOW_PKGS) " in \
|   *" all "*|*" linux "*) \
|     HELPER="$(HOME)/.local/bin/icons-home-sync"; \
|     [ -x "$$HELPER" ] || HELPER="$(HOME)/DotCortex/all/.local/bin/icons-home-sync"; \
|     if [ -x "$$EXCL" ] && "$$EXCL" skip-hook icons-home-sync; then \
|       echo ">> icons-sync skipped (host stow-hook exclude)"; \
|     elif [ -x "$$HELPER" ]; then \
|       echo ">> icons-sync"; \
|       "$$HELPER"; \
|     fi; \
|     ;; \
| esac
| case " $(STOW_PKGS) " in \
|   *" t480s "*) \
|     HELPER="$(HOME)/.local/bin/t480s-plank-apply"; \
|     [ -x "$$HELPER" ] || HELPER="$(HOME)/DotCortex/linux/.local/bin/t480s-plank-apply"; \
|     [ -x "$$HELPER" ] || { echo "safe-stow: missing T480s Plank apply helper: $$HELPER" >&2; exit 1; }; \
|     echo ">> t480s-plank-apply"; \
|     "$$HELPER"; \
|     ;; \
| esac

preview-stow:
| cd $(HOME)/DotCortex && stow $(STOW_FLAGS) -n $(STOW_PKGS) || true

# Registry-resolved stack for this host + user (layers.org): the non-Guile
# equivalent of loom stow:auto / layers:show / layers:check.
LAYERS_HELPER ?= $(HOME)/DotCortex/all/.local/bin/dotcortex-layers

layers-show:
| "$(LAYERS_HELPER)" show

layers-check:
| "$(LAYERS_HELPER)" check

auto-stow:
| set -euo pipefail; \
| pkgs="$$("$(LAYERS_HELPER)" resolve --explain)"; \
| echo ">> auto-stow: $$pkgs"; \
| $(MAKE) --no-print-directory safe-stow STOW_PKGS="$$pkgs"

preview-auto-stow:
| set -euo pipefail; \
| pkgs="$$("$(LAYERS_HELPER)" resolve --explain)"; \
| ign="$$("$(HOME)/DotCortex/all/.local/bin/dotcortex-stow-excludes" ignore-args | tr '\n' ' ')"; \
| "$(HOME)/DotCortex/all/.local/bin/dotcortex-stow-excludes" prune --target "$(STOW_TARGET)" --repo "$(HOME)/DotCortex"; \
| cd $(HOME)/DotCortex && stow $(STOW_FLAGS) -n $$ign $$pkgs || true

# X11 apply for x230 overlay
x11-apply: tangle
| cd $(HOME)/DotCortex && stow $(STOW_FLAGS) x230
| @echo "✅ X11 applied."

# The escaped colon preserves the public odin:deploy command name for make.
odin\:deploy:
| bash odin-config/deploy.sh

include $(HOME)/DotCortex/all/.mk/flatpak.mk
include $(HOME)/DotCortex/all/.mk/icons.mk
include $(HOME)/DotCortex/all/.mk/guix.mk
include $(HOME)/DotCortex/all/.mk/guix-substitutes.mk
include $(HOME)/DotCortex/all/.mk/agent-guix.mk
include $(HOME)/DotCortex/all/.mk/snap.mk
include $(HOME)/DotCortex/all/.mk/appimage.mk
include $(HOME)/DotCortex/all/.mk/am.mk
include $(HOME)/DotCortex/all/.mk/cargo.mk
include $(HOME)/DotCortex/all/.mk/docs.mk
include $(HOME)/DotCortex/all/.mk/homebrew.mk
include $(HOME)/DotCortex/all/.mk/bun.mk
include $(HOME)/DotCortex/all/.mk/bunx.mk
include $(HOME)/DotCortex/all/.mk/npm.mk
include $(HOME)/DotCortex/all/.mk/pip.mk
include $(HOME)/DotCortex/all/.mk/pipx.mk
include $(HOME)/DotCortex/all/.mk/nala.mk
include $(HOME)/DotCortex/all/.mk/dnf.mk
include $(HOME)/DotCortex/all/.mk/bots.mk
include $(HOME)/DotCortex/all/.mk/sessions.mk
include $(HOME)/DotCortex/all/.mk/termux.mk
include $(HOME)/DotCortex/all/.mk/plasmoid.mk
include $(HOME)/DotCortex/all/.mk/xfce-desktopmenu.mk
