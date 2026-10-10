#!/usr/bin/env python3
"""Fail-closed local approval engine for Kikin's Claude consorts."""

import json
import os
from pathlib import Path
import posixpath
import re
import shlex
import signal
import stat
import sys


SCHEMA = "hc.approval.canary.kikin.manifest.v1"
VERSION = "claude-approval-canary.kikin.v1"
CLASS_NAMES = ("local_read", "git_observe", "centre_render", "safe_commit")
ALLOW_OUTPUT = {
    "hookSpecificOutput": {
        "hookEventName": "PermissionRequest",
        "decision": {"behavior": "allow"},
    }
}
SHELL_META = re.compile(r"(?:[\n\r;]|&&|\|\||\$\(|`|[<>]|&|\\)")
PATH_META = re.compile(r"(?:[*?\[\]{}]|\$|`)")
REMOTE = {"ssh", "scp", "rsync", "curl", "wget", "nc", "socat", "telnet"}
SERVICE = {"sudo", "systemctl", "rc-service", "crontab", "tailscale"}
PACKAGE = {"apt", "apt-get", "apk", "brew", "cargo", "conda", "dnf", "guix", "gem", "mamba", "npm", "pacman", "pip", "pip3", "pipx", "pnpm", "poetry", "uv", "yarn", "yum", "zypper"}
AUTH = {".authinfo", ".authinfo.gpg", ".netrc", "auth.json", "authorized_keys", "credentials", "credentials.json", "id_ed25519", "id_rsa", "oauth.json", "oauth_creds.json", "secrets.json", "cookies.sqlite", "cookies.jar"}
READ_OPTIONS = {"-n", "-i", "-v", "-E", "-F", "-h", "-H", "--line-number", "--ignore-case"}
FIND_OPTIONS = {"-maxdepth", "-mindepth", "-type", "-name", "-iname", "-path", "-ipath", "-print", "-print0", "-mount", "-xdev"}
# Compound commands (2026-10-09): agents write `cd X && sed -n 1,60p f | cut -c1-200`.
# A compound is considered only when it contains nothing but the separators below;
# any redirection, substitution, backslash, background `&` or newline stays at the hard floor.
DISCARDS = (" 2>/dev/null", " 2> /dev/null", " >/dev/null", " > /dev/null", " 2>&1")
SEPARATORS = ("&&", "||", "|", ";")
TOOL_INPUT_KEYS = {"command", "description", "timeout"}
# Bundled short flags that only change how matches or listings are printed.
# grep -r/-R stays out: recursion would walk past the per-path protected check.
GREP_FLAGS = re.compile(r"^-[nivEFhHlLwxcoIs]+$")
LS_FLAGS = re.compile(r"^-[alhtrdAF1S]+$")
SED_PRINT = re.compile(r"^(?:\d+|\$)(?:,(?:\d+|\$))?p$")
COUNT_VALUE = re.compile(r"^\+?\d+$")
FILTERS = {"head", "tail", "cut", "sort", "uniq", "wc", "tr", "grep", "sed"}
BRANCH_OPTIONS = {"-a", "--all", "-r", "--remotes", "-v", "-vv", "--verbose", "--show-current", "--no-color"}


def _inside(path, root):
    try:
        Path(path).relative_to(root)
        return True
    except ValueError:
        return False


def _protected(value):
    lowered = str(value).replace("\\", "/").casefold()
    parts = tuple(part for part in lowered.split("/") if part)
    if "palmcortex" in parts or any(parts[i:i + 3] == ("logs", "telegram", "personal") for i in range(max(0, len(parts) - 2))):
        return True
    if "secret vault" in lowered or "/home/gille" in lowered or "nexus/keys" in lowered:
        return True
    if any(part in {".ssh", ".secrets", "private", "secrets", "keys", "credentials"} for part in parts):
        return True
    basename = parts[-1] if parts else ""
    return basename in AUTH or basename.startswith(".env") or basename.endswith((".token", ".key", ".pem", ".kdbx", ".sqlite")) or "token" in basename or "secret" in basename or "cookie" in basename


# 2026-10-09 (Fable/SO-APPROVAL-C1 decider-in-the-loop): the old hard floor mixed
# two very different refusals. The TRUE floor below stays absolute and the Decider
# can NEVER override it: protected/secret paths and private logs, remote reach,
# service control, process kills, recursive deletion, package installs, and
# filesystem-writing find options. SYNTAX-only refusals (heredocs, redirections
# inside the roots, $() substitution, unparsable quoting) are now Decider-eligible
# instead of hard-refused: they are plumbing, not substance.
def _true_floor(event):
    try:
        raw = json.dumps(event.get("tool_input", {}), ensure_ascii=False, sort_keys=True).casefold()
    except (TypeError, ValueError):
        return True
    if _protected(raw) or "logs/telegram/personal" in raw or "palmcortex" in raw:
        return True
    tool_input = event.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return False
    if _protected(command):
        return True
    # 2026-10-10 (replay finding): an unbalanced quote (a comment saying
    # "job's") makes the WHOLE command unparseable — the old early bail-out
    # skipped the entire floor. Now a failed whole-command parse still runs the
    # per-line scans below (which parse the real command lines), and only the
    # word-level scan is skipped.
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        words = None
    # Word-level secret scan, path-like tokens only ('cat .env', 'cat NEXUS/keys/x'):
    # a bare word such as grep 'private' is not a path and must not floor.
    if words is not None and any(_protected(word) for word in words if "/" in word or word.startswith("~") or "." in word):
        return True
    # 2026-10-10 (Fable review, replay finding): floor verbs hide inside compound
    # segments ('cd X && kill -TERM 30130', 'rm -f a && make'). Every segment's
    # first word gets the same absolute checks as a standalone command.
    # _split_compound refuses raw newlines (safe for the approve path); the
    # floor is fail-closed, so multi-line commands get a cruder line scan:
    # every line and every ;-separated piece has its first word checked. A
    # false positive here means ASK, never a silent allow.
    segments = _split_compound(command)
    if segments is not None:
        for _separator, text in segments:
            # A segment can still hold several newline-separated commands; each
            # line's first word is checked, not just the segment head.
            for line in text.split("\n"):
                try:
                    segment_words = shlex.split(line, posix=True)
                except ValueError:
                    continue
                if segment_words and _floor_verb([w.casefold() for w in segment_words]):
                    return True
    else:
        for line in command.replace(";", "\n").split("\n"):
            try:
                line_words = shlex.split(line, posix=True)
            except ValueError:
                continue
            if line_words and _floor_verb([w.casefold() for w in line_words]):
                return True
    if words is None:
        # Unparseable as one shell command: the line scans above already
        # checked every parseable line; anything left unparsed is floor.
        return True
    lowered = [word.casefold() for word in words]
    if any(word in REMOTE or word.startswith(("http://", "https://")) for word in lowered):
        return True
    if any(word in SERVICE or word in {"pkill", "killall"} for word in lowered):
        return True
    return _floor_verb(lowered)


def _floor_verb(lowered):
    """Absolute floor checks on a command's (or compound segment's) word list.

    Shared by the whole-command path and the per-segment scan so a floor verb
    cannot hide inside a compound ('cd X && kill -TERM 30130')."""
    # 2026-10-10 (replay finding): a bare 'kill PID' is still process control —
    # any kill form floors (flag forms AND plain PID forms).
    if lowered and lowered[0] == "kill":
        return True
    # Remote and service control also floor per segment ('cd X && ssh y'):
    if any(word in REMOTE or word.startswith(("http://", "https://")) for word in lowered):
        return True
    if any(word in SERVICE or word in {"pkill", "killall"} for word in lowered):
        return True
    # 2026-10-10 (Fable review): destructive git forms are absolute floor —
    # history loss, branch deletion and forced updates can never be
    # Decider-eligible. Reads (status, log, diff) stay with the classes above.
    if lowered and lowered[0] == "git":
        sub = lowered[1] if len(lowered) > 1 else ""
        rest = lowered[2:]
        if sub in {"push", "rebase", "clean"}:
            return True  # any form, per review
        if sub == "reset" and any(word in {"--hard", "--merge"} or word.startswith("--hard") or word.startswith("--merge") for word in rest):
            return True  # review lists --hard / --merge forms
        if sub in {"checkout", "restore"}:
            # Discarding worktree paths is floor; a plain branch switch is
            # checked by the classes and, when unmatched, the Decider.
            if sub == "restore" or "--" in rest:
                return True
            if any(word.startswith("--") and word not in {"--"} for word in rest):
                return True  # e.g. --ours/--theirs discards the other side
        if sub == "branch" and any(word in {"-d", "-D", "--delete", "--delete-force"} for word in rest):
            return True
        if sub == "stash" and any(word in {"drop", "clear", "pop"} for word in rest):
            return True
        if sub == "commit" and "--amend" in rest:
            return True
        if sub == "worktree" and any(word in {"prune", "remove", "delete"} for word in rest):
            return True
        if sub in {"filter-branch", "filter-repo"}:
            return True
        # "any 'main' branch name" (review): a git subcommand that NAMES the
        # main branch as a word is floor — switching, merging or moving main is
        # the fleet's protected spine. Reads never carry it as a bare word.
        if sub and any(word in {"main", "master"} for word in lowered[2:]):
            return True
    # Disk and permission tools (2026-10-10 review): irreversible or system-wide.
    disk_verbs = {"dd", "mkfs", "mkfs.ext2", "mkfs.ext3", "mkfs.ext4", "mkfs.btrfs", "mkfs.xfs", "mkfs.vfat", "mkfs.fat", "mkfs.ntfs", "cryptsetup", "wipefs", "fdisk", "parted", "shred", "truncate", "mount", "umount", "crontab"}
    if lowered and lowered[0] in disk_verbs:
        if lowered[0] == "crontab":
            return any(word in {"-r", "--remove"} or word.startswith("-r") for word in lowered[1:])
        return True
    if lowered and lowered[0] in {"chmod", "chown"} and any(word.startswith("-") and ("r" in word[1:] or "R" in word[1:]) for word in lowered[1:]):
        return True
    # Process control beyond kill (2026-10-10 review): 'at' schedules jobs —
    # any invocation floors, no flags-only exception.
    if lowered and lowered[0] == "at":
        return True
    if "telegram-agent-host" in lowered and any(word in {"stop", "start", "switch", "bring"} for word in lowered):
        return True
    if "nurse-joy" in lowered and "revive" in lowered:
        return True
    if "tmux" in lowered and any(word.startswith("kill-") for word in lowered):
        return True
    if lowered and lowered[0] == "rm" and any(word == "-r" or word == "--recursive" or (word.startswith("-") and "r" in word[1:]) for word in lowered[1:]):
        return True
    for index, word in enumerate(lowered):
        if word in PACKAGE and any(next_word in {"install", "add", "i", "sync"} for next_word in lowered[index + 1:index + 4]):
            return True
    return any(word in {"--output", "--exec", "--execdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"} or word.startswith("--output=") for word in lowered)


def _syntax_refusal(event):
    """Shell-plumbing refusals that no longer hard-refuse: unparsable quoting, or
    metacharacters (redirections, substitution, backgrounding, newlines) that the
    deterministic compound router cannot vouch for. These are Decider-eligible."""
    tool_input = event.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return False
    try:
        shlex.split(command, posix=True)
    except ValueError:
        return True
    return bool(SHELL_META.search(command) and not _routes_compound(command))


def _lexical(raw, cwd):
    if not isinstance(raw, str) or not raw or "\x00" in raw or PATH_META.search(raw):
        return None
    if raw == "~":
        raw = str(Path.home())
    elif raw.startswith("~/"):
        raw = str(Path.home()) + raw[1:]
    elif raw.startswith("~"):
        return None
    elif not raw.startswith("/"):
        raw = posixpath.join(cwd, raw)
    return posixpath.normpath(raw) if raw.startswith("/") else None


def _path(raw, cwd, roots, exists=True):
    lexical = _lexical(raw, cwd)
    if lexical is None or _protected(lexical):
        return None
    resolved = os.path.realpath(lexical)
    if not any(_inside(resolved, root) for root in roots):
        return None
    if exists and not os.path.exists(resolved):
        return None
    return resolved


def _scratch(raw, cwd, roots):
    lexical = _lexical(raw, cwd)
    if lexical is None:
        return None
    resolved = os.path.realpath(lexical)
    return resolved if any(_inside(resolved, root) and resolved != root for root in roots) else None


def _load_manifest():
    override = os.environ.get("SO_APPROVAL_KIKIN_MANIFEST")
    path = Path(override) if override else Path(__file__).resolve().parents[3] / ".config/dotcortex/claude-approval-canary.kikin.v1.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    # 2026-10-09 decider-in-the-loop: v2 manifests may carry a "decider" section
    # (honey_url/kikin_url/timeout_ms/min_allow_confidence/enabled). v1 manifests
    # load unchanged with the decider path disabled.
    allowed_keys = {"schema", "manifest_version", "hard_floor_ids", "roots", "scratch_roots", "classes"}
    version = data.get("manifest_version") if isinstance(data, dict) else None
    if version == "claude-approval-canary.kikin.v2":
        allowed_keys = allowed_keys | {"decider"}
    if not isinstance(data, dict) or set(data) != allowed_keys or data.get("schema") != SCHEMA or version not in (VERSION, "claude-approval-canary.kikin.v2"):
        raise ValueError("invalid Kikin manifest")
    if not isinstance(data["hard_floor_ids"], list) or not isinstance(data["classes"], list) or len(data["classes"]) != len(CLASS_NAMES):
        raise ValueError("invalid Kikin manifest classes")
    roots = tuple(os.path.realpath(item) for item in data["roots"] if isinstance(item, str) and item.startswith("/"))
    scratch = tuple(os.path.realpath(item) for item in data["scratch_roots"] if isinstance(item, str) and item.startswith("/"))
    if len(roots) != len(data["roots"]) or len(scratch) != len(data["scratch_roots"]) or any(root == "/" for root in roots + scratch):
        raise ValueError("invalid Kikin roots")
    entries = {}
    for name, entry in zip(CLASS_NAMES, data["classes"]):
        if not isinstance(entry, dict) or entry.get("name") != name or type(entry.get("enabled")) is not bool:
            raise ValueError("invalid Kikin class")
        entries[name] = entry
    data["roots"] = roots
    data["scratch_roots"] = scratch
    data["entries"] = entries
    return data


def _targets(values, cwd, manifest, directories=None):
    paths = tuple(_path(value, cwd, manifest["roots"]) for value in values)
    if not paths or any(path is None for path in paths):
        return None
    if directories is True and any(not os.path.isdir(path) for path in paths):
        return None
    if directories is False and any(not os.path.isfile(path) for path in paths):
        return None
    return paths


def _repo(raw, cwd, manifest):
    path = _path(raw, cwd, manifest["roots"])
    if path is None:
        return None
    current = Path(path if os.path.isdir(path) else os.path.dirname(path))
    while True:
        if (current / ".git").exists() and any(_inside(str(current), root) for root in manifest["roots"]):
            return str(current)
        if current.parent == current:
            return None
        current = current.parent


def _local_match(event, manifest, words=None):
    entry = manifest["entries"].get("local_read")
    if entry is None:
        return False
    name, tool_input, cwd = event.get("tool_name"), event.get("tool_input"), event.get("cwd")
    if not isinstance(tool_input, dict) or not isinstance(cwd, str):
        return False
    cwd = _path(cwd, cwd, manifest["roots"])
    if cwd is None:
        return False
    if name == "Read":
        return bool(_targets([tool_input.get("file_path", tool_input.get("path"))], cwd, manifest, False))
    if name in {"Glob", "Grep"}:
        base = tool_input.get("path") or cwd
        pattern = tool_input.get("pattern")
        return bool(_targets([base], cwd, manifest, True) and isinstance(pattern, str) and pattern and ".." not in pattern.split("/"))
    if name != "Bash" or not set(tool_input) <= TOOL_INPUT_KEYS or not isinstance(tool_input.get("command"), str):
        return False
    if words is None:
        # A whole command: refuse shell syntax. _compound passes words it already
        # parsed with quotes respected, so a quoted backslash pattern is no threat there.
        if SHELL_META.search(tool_input["command"]):
            return False
        try:
            words = shlex.split(tool_input["command"], posix=True)
        except ValueError:
            return False
    if not words or words[0] not in entry["bash_verbs"] or words[0] != words[0].rsplit("/", 1)[-1]:
        return False
    verb, args = words[0], words[1:]
    if verb in {"head", "tail"}:
        args = _strip_counts(args)
        if args is None:
            return False
    if verb == "sed":
        if len(args) < 3 or args[0] != "-n" or not SED_PRINT.match(args[1]) or any(arg.startswith("-") for arg in args[2:]):
            return False
        return bool(_targets(args[2:], cwd, manifest, False))
    if verb == "grep":
        # Read-only flags may sit before or after the pattern (agents write grep -n PAT f);
        # the first non-flag word is the pattern, every later one is a file to check.
        if any(arg.startswith("-") and arg not in READ_OPTIONS and not GREP_FLAGS.match(arg) for arg in args):
            return False
        words_only = [arg for arg in args if not arg.startswith("-")]
        if len(words_only) < 2:
            return False
        operands = words_only[1:]
    elif verb == "find":
        split = next((index for index, arg in enumerate(args) if arg.startswith("-")), len(args))
        operands, expression = args[:split], args[split:]
        if not operands or any(arg in {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"} for arg in expression):
            return False
        if any(arg.startswith("-") and arg not in FIND_OPTIONS for arg in expression):
            return False
    elif verb == "ls":
        if any(arg.startswith("-") and not LS_FLAGS.match(arg) for arg in args):
            return False
        operands = [arg for arg in args if not arg.startswith("-")] or ["."]
    else:
        operands = [arg for arg in args if not arg.startswith("-")]
        if not operands or any(arg.startswith("-") and arg not in READ_OPTIONS for arg in args):
            return False
    return bool(_targets(operands, cwd, manifest))


def _git_match(event, manifest):
    entry = manifest["entries"].get("git_observe")
    tool_input, cwd = event.get("tool_input"), event.get("cwd")
    if entry is None or event.get("tool_name") != "Bash" or not isinstance(tool_input, dict) or not set(tool_input) <= TOOL_INPUT_KEYS or not isinstance(tool_input.get("command"), str) or not isinstance(cwd, str):
        return False
    try:
        words = shlex.split(tool_input["command"], posix=True)
    except ValueError:
        return False
    if not words or words[0] != "git":
        return False
    args = words[1:]
    repo_raw = cwd
    if args[:1] == ["-C"]:
        if len(args) < 3:
            return False
        repo_raw, args = args[1], args[2:]
    if not args or args[0] not in entry["subcommands"]:
        return False
    repo = _repo(repo_raw, cwd, manifest)
    if repo is None:
        return False
    subcommand, remainder = args[0], args[1:]
    if any(item in {"--exec-path", "--ext-diff", "--textconv", "--paginate", "--output"} or item.startswith(("--exec-path=", "--git-dir=", "--work-tree=", "--output=")) for item in remainder):
        return False
    if subcommand == "branch":
        return all(item in BRANCH_OPTIONS for item in remainder)
    disk = []
    if "--" in remainder:
        if remainder.count("--") != 1:
            return False
        index = remainder.index("--")
        disk, remainder = remainder[index + 1:], remainder[:index]
        if not disk:
            return False
    if subcommand == "show":
        for item in remainder:
            if ":" in item:
                object_path = item.split(":", 1)[1]
                if not object_path or object_path.startswith("/") or _protected(object_path) or not _inside(posixpath.normpath(posixpath.join(repo, object_path)), repo):
                    return False
    if any(PATH_META.search(item) for item in disk) or any(item.startswith("-") for item in disk):
        return False
    return bool(_targets(disk or [repo], repo, manifest))


def _centre_match(event, manifest):
    entry = manifest["entries"].get("centre_render")
    tool_input, cwd = event.get("tool_input"), event.get("cwd")
    if entry is None or event.get("tool_name") != "Bash" or not isinstance(tool_input, dict) or set(tool_input) != {"command"} or not isinstance(cwd, str):
        return False
    try:
        words = shlex.split(tool_input["command"], posix=True)
    except ValueError:
        return False
    output = None
    if "--out" in words:
        index = words.index("--out")
        if words.count("--out") != 1 or index + 1 >= len(words):
            return False
        output = _scratch(words[index + 1], cwd, manifest["scratch_roots"])
        if output is None:
            return False
        del words[index:index + 2]
    command = " ".join(words)
    if command not in entry["commands"]:
        return False
    root = _repo(cwd, cwd, manifest)
    if root is None or Path(root).name.casefold() not in {"helmcortex", "dotcortex"}:
        return False
    script = "FORGE/bin/pokemon-centre" if "pokemon-centre" in command else "FORGE/bin/clubhouse-bosses-refresh"
    script_path = _path(script, root, manifest["roots"])
    return bool(script_path and os.path.isfile(script_path) and (output is None or output.startswith("/")))


def _safe_commit(event, manifest):
    entry = manifest["entries"].get("safe_commit")
    tool_input, cwd = event.get("tool_input"), event.get("cwd")
    if entry is None or event.get("tool_name") != "Bash" or not isinstance(tool_input, dict) or set(tool_input) != {"command"} or not isinstance(cwd, str):
        return False
    try:
        words = shlex.split(tool_input["command"], posix=True)
    except ValueError:
        return False
    if not words or words[0] not in {"git", "dotcortex-safe-commit"}:
        return False
    command, args = words[0], words[1:]
    repo_raw = cwd
    if args[:1] == ["-C"]:
        if len(args) < 2:
            return False
        repo_raw, args = args[1], args[2:]
    repo = _repo(repo_raw, cwd, manifest)
    if repo is None or (command == "dotcortex-safe-commit" and Path(repo).name.casefold() != "dotcortex"):
        return False
    if command == "git":
        if len(args) < 4 or args[:2] != ["commit", "-F"]:
            return False
        message, args = args[2], args[3:]
    else:
        if len(args) < 3 or args[0] != "-F":
            return False
        message, args = args[1], args[2:]
    if args[:1] != ["--"] or len(args) < 2:
        return False
    paths = args[1:]
    if any(not path or path.startswith("/") or path in {".", ".."} or PATH_META.search(path) or path.startswith(":") or ".." in Path(path).parts for path in paths):
        return False
    message = _scratch(message, repo, manifest["scratch_roots"])
    targets = _targets(paths, repo, manifest, False)
    if message is None or targets is None:
        return False
    try:
        info = os.lstat(message)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o077 and all(not _protected(path) and ".git" not in Path(path).parts for path in targets)


def _strip_counts(args):
    """Drop head/tail line or byte counts (-n N, -c N, -N, --lines=N); None if malformed."""
    kept, index = [], 0
    while index < len(args):
        arg = args[index]
        if arg in {"-n", "-c"}:
            if index + 1 >= len(args) or not COUNT_VALUE.match(args[index + 1]):
                return None
            index += 2
            continue
        if re.fullmatch(r"-\d+", arg) or re.fullmatch(r"--(?:lines|bytes)=\+?\d+", arg) or arg == "-q":
            index += 1
            continue
        kept.append(arg)
        index += 1
    return kept


def _split_compound(command):
    """Split on top-level &&, ||, | and ; outside quotes, dropping harmless stderr/stdout
    discards (2>/dev/null, >/dev/null, 2>&1). Returns [(separator, text), ...] or None.
    Single-quoted text is literal; anything that could substitute, redirect to a file,
    background or escape (outside single quotes) makes it None."""
    segments, current, quote, index, separator = [], [], None, 0, None
    while index < len(command):
        char = command[index]
        if quote == "'":
            if char == "'":
                quote = None
            current.append(char)
            index += 1
            continue
        if quote == '"':
            if char in {"`", "\\"} or command.startswith("$(", index):
                return None
            if char == '"':
                quote = None
            current.append(char)
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            index += 1
            continue
        discard = next((d for d in DISCARDS if command.startswith(d, index)), None)
        if discard:
            index += len(discard)
            continue
        found = next((sep for sep in SEPARATORS if command.startswith(sep, index)), None)
        if found:
            segments.append((separator, "".join(current).strip()))
            current, separator = [], found
            index += len(found)
            continue
        if char in {"\n", "\r", "`", "<", ">", "\\", "&"} or command.startswith("$(", index):
            return None
        current.append(char)
        index += 1
    if quote:
        return None
    segments.append((separator, "".join(current).strip()))
    if any(not text for _, text in segments):
        return None
    return segments


def _routes_compound(command):
    """True when the command should be judged stage by stage by _compound."""
    segments = _split_compound(command)
    return segments is not None and (len(segments) > 1 or bool(SHELL_META.search(command)))


def _filter_ok(words):
    """A pipe stage that only transforms stdin: no file operands, no writing options."""
    verb, args = words[0], words[1:]
    if verb not in FILTERS or verb != verb.rsplit("/", 1)[-1]:
        return False
    if verb in {"head", "tail"}:
        return _strip_counts(args) == []
    if verb == "wc":
        return all(arg in {"-l", "-c", "-w", "-m"} for arg in args)
    if verb == "uniq":
        return all(arg in {"-c", "-d", "-u", "-i"} for arg in args)
    if verb == "tr":
        options = [arg for arg in args if arg.startswith("-")]
        return all(arg in {"-d", "-s"} for arg in options) and 1 <= len(args) - len(options) <= 2
    if verb == "sed":
        return len(args) == 2 and args[0] == "-n" and bool(SED_PRINT.match(args[1]))
    if verb == "grep":
        operands = [arg for arg in args if not arg.startswith("-")]
        return len(operands) == 1 and all(arg in READ_OPTIONS or GREP_FLAGS.match(arg) for arg in args if arg.startswith("-"))
    with_value = {"cut": {"-c", "-d", "-f", "-b"}, "sort": {"-k", "-t"}}[verb]
    flags = {"cut": {"-s"}, "sort": {"-n", "-r", "-u", "-h", "-V", "-f"}}[verb]
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in with_value and index + 1 < len(args):
            index += 2
        elif any(arg.startswith(option) and len(arg) > len(option) for option in with_value) or arg in flags:
            index += 1
        else:
            return False
    return True


def _compound(event, manifest):
    """Approve a compound only when every stage is a cd inside the roots, an enabled
    read or git observation, or (after a pipe) a stdin-only filter."""
    segments = _split_compound(event["tool_input"]["command"])
    cwd = _path(event.get("cwd"), event.get("cwd") or "/", manifest["roots"]) if isinstance(event.get("cwd"), str) else None
    if segments is None or cwd is None:
        return False, "no_match"
    used = []
    for separator, text in segments:
        try:
            words = shlex.split(text, posix=True)
        except ValueError:
            return False, "no_match"
        if words[:1] == ["timeout"] and len(words) > 2 and re.fullmatch(r"\d+(?:\.\d+)?[smh]?", words[1]):
            words = words[2:]
        if not words:
            return False, "no_match"
        if words[0] in {"true", "echo"}:
            # No redirection can survive _split_compound, so these only print or no-op.
            continue
        if separator == "|":
            if not _filter_ok(words):
                return False, "no_match"
            continue
        if words[0] == "cd":
            # Only a cd that must succeed for the chain to continue (start or after &&),
            # so later relative paths really resolve where this check resolved them.
            if separator not in (None, "&&"):
                return False, "no_match"
            target = _path(words[1], cwd, manifest["roots"]) if len(words) == 2 else None
            if target is None or not os.path.isdir(target):
                return False, "no_match"
            cwd = target
            continue
        stage = {**event, "cwd": cwd, "tool_input": {"command": shlex.join(words)}}
        for matcher, name in ((_local_match, "local_read"), (_git_match, "git_observe")):
            if (matcher(stage, manifest, words) if matcher is _local_match else matcher(stage, manifest)):
                if manifest["entries"][name]["enabled"] is not True:
                    return False, f"{name}_disabled"
                used.append(name)
                break
        else:
            return False, "no_match"
    if not used:
        return False, "no_match"
    return True, "compound:" + "+".join(sorted(set(used)))


def classify(event, manifest):
    """Return (allow, reason). The reason names the class that matched, or why none did.

    2026-10-09 decider-in-the-loop: reasons 'true_floor' stay absolute. 'no_match',
    '*_disabled' and 'syntax' mark the Decider-eligible grey zone — classify stays
    deterministic and side-effect free; the caller decides whether to consult the
    Decider for those."""
    if not isinstance(event, dict) or event.get("hook_event_name") != "PermissionRequest":
        return False, "not_permission_request"
    if _true_floor(event):
        return False, "true_floor"
    tool_input = event.get("tool_input")
    if event.get("tool_name") == "Bash" and isinstance(tool_input, dict) and set(tool_input) <= TOOL_INPUT_KEYS and isinstance(tool_input.get("command"), str) and _routes_compound(tool_input["command"]):
        allow, reason = _compound(event, manifest)
        if allow:
            return True, reason
        if reason.endswith("_disabled"):
            return False, reason
        return False, "no_match_decider" if reason == "no_match" else reason
    for matcher in (_local_match, _git_match, _centre_match, _safe_commit):
        if matcher(event, manifest):
            name = {"_local_match": "local_read", "_git_match": "git_observe", "_centre_match": "centre_render", "_safe_commit": "safe_commit"}[matcher.__name__]
            if manifest["entries"][name]["enabled"] is True:
                return True, name
            return False, f"{name}_disabled"
    if _syntax_refusal(event):
        return False, "syntax"
    return False, "no_match_decider"


def evaluate(event, manifest):
    return classify(event, manifest)[0]


# ---------------------------------------------------------------------------
# Decider-in-the-loop (2026-10-09, Fable lane, SO-APPROVAL-C1).
# Grey-zone prompts (no_match / syntax-only refusals) may be allowed by the
# local System-One Decider, Honey first then Kikin, ONLY when the response
# clears the manifest threshold AND the deterministic C1 conditions hold.
# The TRUE floor above can never be overridden. Decider down, slow or unsure
# means ASK. The whole hook has a 3s budget; the Decider gets ~2.2s.
# ---------------------------------------------------------------------------

DECIDER_DEFAULT_KIKIN_URL = "http://127.0.0.1:8098/v1/systemone"
DECIDER_DEFAULT_TIMEOUT_MS = 2200
DECIDER_DEFAULT_THRESHOLD = 0.95
C1_MIN = 0.95
C1_MAX = 0.05
# Pinned Decider build (kikin-decider-supervision.md, install receipt 2026-10-06).
PINNED_MODEL_SHA256 = "b7c132a67934d51c81abc96bb7724800f965ff5a288aed3e1ca7d8bc349c1386"

C1_QUESTIONS = (
    ("approval.risk_class.v1", ("R0_observe", "R1_local_reversible", "R2_bounded_mutation", "R3_privileged_external", "R4_destructive_irreversible")),
    ("approval.intent_fit.v1", ("false", "true")),
    ("approval.reversibility.v1", ("trivial", "checkpointed", "difficult", "irreversible")),
    ("approval.blast_radius.v1", ("object", "repository", "machine", "remote_machine", "fleet", "external_service")),
    ("approval.sensitive_effect.v1", ("false", "true")),
    ("approval.needs_human.v1", ("false", "true")),
)


def _decider_config(manifest):
    """Decider endpoints and bounds from the manifest (v2) plus env overrides.
    A manifest without a decider section, or decider.enabled false, disables the
    path (everything grey stays ask)."""
    section = manifest.get("decider") if isinstance(manifest.get("decider"), dict) else None
    if not isinstance(section, dict) or section.get("enabled") is not True:
        return None
    honey = section.get("honey_url") or os.environ.get("SO_APPROVAL_HONEY_DECIDER_URL")
    kikin = section.get("kikin_url") or os.environ.get("SO_APPROVAL_KIKIN_DECIDER_URL") or DECIDER_DEFAULT_KIKIN_URL
    try:
        timeout_ms = int(section.get("timeout_ms", DECIDER_DEFAULT_TIMEOUT_MS))
        threshold = float(section.get("min_allow_confidence", DECIDER_DEFAULT_THRESHOLD))
    except (TypeError, ValueError):
        return None
    if not 500 <= timeout_ms <= 2600 or not 0.5 <= threshold <= 1.0:
        return None
    # Honey is optional (None = not configured); Kikin is the always-on fallback.
    if kikin is None or not isinstance(kikin, str) or not kikin:
        return None
    if honey is not None and (not isinstance(honey, str) or not honey):
        return None
    mode = section.get("questions", "single")
    if mode not in ("single", "dual", "c1"):
        return None
    honey_api = section.get("honey_api", "kikin")
    if honey_api not in ("kikin", "r2d2d"):
        return None
    return {"honey": honey if isinstance(honey, str) else None, "honey_api": honey_api, "kikin": kikin, "timeout_ms": timeout_ms, "threshold": threshold, "mode": mode}


INTERPRETER_WORDS = {"python", "python3", "python3.11", "python3.12", "python3.13", "python3.14", "node", "perl", "ruby", "bash", "sh", "zsh", "awk"}


def _interpreter_body(event):
    """True when the command runs an interpreter over a -c script or a heredoc.

    2026-10-10 (Fable review): a heredoc or -c body can do anything, so
    'non-sensitive' alone cannot auto-allow it. Such prompts go to the Decider
    in dual mode (the destructive question must also clear) — never single."""
    tool_input = event.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return False
    if "<<" in command:
        return True
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        return True  # unparseable + interpreter-shaped: fail closed
    if not words:
        return False
    verb = words[0].rsplit("/", 1)[-1]
    if verb not in INTERPRETER_WORDS:
        return False
    return any(word == "-c" or word.startswith("-") and "c" in word[1:] and not word.startswith("--") for word in words[1:])


WRITE_VERBS = {"cp", "mv", "ln", "tee", "touch", "install", "mkdir", "rmdir", "truncate", "chmod", "chown", "rm", "unlink"}
WRITE_INLINE = ("sed", "awk", "perl")  # -i / in-place variants write files


def _write_capable(event):
    """True when a grey-zone command can mutate files as written.

    2026-10-10 (Fable review): single mode is fine for plain reads and
    syntax-only refusals — nothing else. A write-capable prompt (sed -i, a
    redirect into a file, cp/mv/tee/touch) is judged with the destructive
    question too (dual), because 'not sensitive' says nothing about reversibility."""
    tool_input = event.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return False
    # Redirects into files were syntax refusals: still write-capable.
    if SHELL_META.search(command) and ">" in command:
        return True
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        return True  # unknown shape: judge it with the destructive question
    if not words:
        return False
    verb = words[0].rsplit("/", 1)[-1]
    if verb in WRITE_VERBS:
        return True
    if verb in WRITE_INLINE:
        return any(word == "-i" or word.startswith("-i") or "--in-place" in word for word in words[1:])
    # 'git apply' (without --check/--stat, which are dry runs) writes the worktree
    # (calibration finding 2026-10-10: a 'git apply /tmp/x.patch' was single-mode
    # eligible; it must be dual-judged like every other write).
    if verb == "git" and any(word == "apply" for word in words[1:]) and not any(word in {"--check", "--stat", "-n", "--numstat"} for word in words[2:]):
        return True
    # Compounds ('CP=...; rm -v $l'): every segment and line's first word is
    # checked too, mirroring the floor's per-segment scan.
    segments = _split_compound(command)
    lines = [text for _separator, text in segments] if segments is not None else command.replace(";", "\n").split("\n")
    for line in lines:
        for piece in line.split("\n"):
            try:
                line_words = shlex.split(piece, posix=True)
            except ValueError:
                return True
            if line_words and line_words[0].rsplit("/", 1)[-1] in WRITE_VERBS:
                return True
            if line_words and line_words[0].rsplit("/", 1)[-1] in WRITE_INLINE:
                if any(word == "-i" or word.startswith("-i") or "--in-place" in word for word in line_words[1:]):
                    return True
            if line_words and line_words[0].rsplit("/", 1)[-1] == "git" and any(word == "apply" for word in line_words[1:]) and not any(word in {"--check", "--stat", "-n", "--numstat"} for word in line_words[2:]):
                return True
    return False


GREY_QUESTION_SINGLE = "approval.sensitive_effect.v1"
GREY_SINGLE_CRITERIA = {
    "false": "The prompt is ordinary non-sensitive local work inside the approved roots.",
    "true": "The prompt touches secrets, private data, remote systems, or anything uncertain.",
}


GREY_QUESTION_DESTRUCTIVE = "approval.needs_human.v1"

# r2d2d (Honey decider-2b-v11) question texts: the gate's criteria rendered as
# noul yes/no questions. p_yes = P(the TRUE criterion) maps 1:1 to the gate's
# noul. Verified live 2026-10-10: benign read 0.025/0.056, secret read 0.157,
# sed -i 0.602 destructive, rm -rf 0.931 destructive — the classes separate.
R2D2D_QUESTION_TEXTS = {
    GREY_QUESTION_SINGLE: "Does executing this command have a sensitive effect: touch secrets, private data, personal logs, remote systems, or anything uncertain Mètsàtron would want to gate? Ordinary non-sensitive local work inside the approved roots answers no. Answer yes or no.",
    GREY_QUESTION_DESTRUCTIVE: "Is the command destructive, irreversible, or something a human should gate before it runs? Reversible local work a human does not need to gate answers no. Answer yes or no.",
}
GREY_DESTRUCTIVE_CRITERIA = {
    "false": "The prompt is reversible local work a human does not need to gate.",
    "true": "The prompt is destructive, irreversible, or something a human should gate.",
}


def _c1_envelope(event, request_id, timeout_ms, mode="single"):
    """Build the hc.system-one.request.v1 envelope for one grey-zone prompt.

    Measured on the live Kikin CPU Decider (2026-10-09): one noul question
    answers in ~2.4s; the full six-question C1 set needs far more than the
    hook's 3s budget. Modes: 'single' asks the one decisive sensitive-effect
    question (confidence = 1 - noul) — allowed only for plain reads and
    syntax-only refusals. 'dual' (interpreter bodies: heredocs and -c scripts)
    adds the destructive/needs-human question and BOTH must clear the
    threshold. 'c1' asks all six C1 questions for fast Honey endpoints.
    Question payloads use the Kikin native shape (type/criteria) that the
    local service accepts."""
    tool_input = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    state = {
        "tool": str(event.get("tool_name") or ""),
        "command": tool_input.get("command"),
        "cwd": event.get("cwd"),
        "target_paths": [tool_input[k] for k in ("file_path", "path", "notebook_path") if isinstance(tool_input.get(k), str)],
    }

    def native_question(qid, kind, criteria):
        return {"id": qid, "kind": kind, "instructions": "Classify the approval criterion.", "evidence_ids": [],
                "options": [{"id": key, "criterion": text} for key, text in criteria]}

    if mode == "c1":
        questions = [
            native_question(qid, "choice", [(i, i.replace("_", " ")) for i in ids])
            for qid, ids in C1_QUESTIONS
        ]
    elif mode == "dual":
        questions = [
            native_question(GREY_QUESTION_SINGLE, "binary", list(GREY_SINGLE_CRITERIA.items())),
            native_question(GREY_QUESTION_DESTRUCTIVE, "binary", list(GREY_DESTRUCTIVE_CRITERIA.items())),
        ]
    else:
        questions = [native_question(GREY_QUESTION_SINGLE, "binary", list(GREY_SINGLE_CRITERIA.items()))]
    return {
        "schema": "hc.system-one.request.v1",
        "request_id": request_id,
        "domain": "helmcortex",
        "recipe": {"id": "claude-approval-grey-c1", "version": 1, "state_schema": "hc.approval.grey.v1", "calibration_family": "decider-v11-approval"},
        "snapshot": {"id": request_id, "revision": "1", "as_of": "2026-10-09T00:00:00Z", "expires_at": "2026-10-10T00:00:00Z", "state_sha256": __import__("hashlib").sha256(__import__("json").dumps(state, sort_keys=True).encode()).hexdigest()},
        "state": state,
        "questions": questions,
        "limits": {"deadline_ms": timeout_ms, "max_input_tokens": 2048, "max_cost_usd": None},
    }


def _wire_questions(envelope):
    """hc.system-one.request.v1 questions to the Kikin native /v1/systemone
    wire shape: {qid: {type, instructions, criteria, evidence_ids}}."""
    wire = {}
    for question in envelope["questions"]:
        wire[question["id"]] = {
            "type": "noul" if question["kind"] == "binary" else "choice",
            "instructions": question["instructions"],
            "criteria": ({option["id"]: option["criterion"] for option in question["options"]}
                         if question["kind"] == "binary"
                         else [option["criterion"] for option in question["options"]]),
            "evidence_ids": question["evidence_ids"],
        }
    return {"model": "decider-2b-v11-Q4_K_M", "model_sha256": __import__("hashlib").sha256(b"").hexdigest()[:0] + PINNED_MODEL_SHA256, "request_id": envelope["request_id"], "state": envelope["state"], "questions": wire, "limits": envelope["limits"]}


def _c1_conditions(answers):
    """The deterministic C1 checks from claude_approval._assessment_passes_c1,
    restated standalone: joint risk/intent/reversibility/blast/sensitivity/
    needs-human gates at the C1 bounds."""
    try:
        def probs(qid):
            raw = answers[qid]["probabilities"]
            if not isinstance(raw, dict):
                raise ValueError(qid)
            return {k: float(v) for k, v in raw.items()}

        risk = probs("approval.risk_class.v1")
        intent = probs("approval.intent_fit.v1")
        reversibility = probs("approval.reversibility.v1")
        blast = probs("approval.blast_radius.v1")
        sensitive = probs("approval.sensitive_effect.v1")
        needs_human = probs("approval.needs_human.v1")
    except (KeyError, TypeError, ValueError):
        return None
    conditions = (
        risk.get("R0_observe", 0.0) + risk.get("R1_local_reversible", 0.0) >= C1_MIN,
        risk.get("R3_privileged_external", 1.0) + risk.get("R4_destructive_irreversible", 1.0) <= C1_MAX,
        intent.get("true", 0.0) >= C1_MIN,
        reversibility.get("trivial", 0.0) + reversibility.get("checkpointed", 0.0) >= C1_MIN,
        blast.get("object", 0.0) + blast.get("repository", 0.0) >= C1_MIN,
        sensitive.get("false", 0.0) >= C1_MIN,
        needs_human.get("false", 0.0) >= C1_MIN,
    )
    if not all(0.0 <= value <= 1.0 for group in (risk, intent, reversibility, blast, sensitive, needs_human) for value in group.values()):
        return None
    return conditions


def _r2d2d_body(envelope):
    """hc.system-one.request.v1 to r2d2d's /decide wire shape (Honey's
    decider-2b-v11). r2d2d takes all questions in ONE request, so dual mode
    stays a single round trip. Question text carries the gate's criteria so
    the Decider judges the same classes the gate classifies."""
    state = envelope["state"]
    questions = []
    ids = []
    for question in envelope["questions"]:
        criteria = {option["id"]: option["criterion"] for option in question["options"]}
        ids.append(question["id"])
        questions.append({"question": R2D2D_QUESTION_TEXTS[question["id"]], "type": "noul"})
    return {"state": state, "questions": questions}, ids


def _r2d2d_answers(response, ids):
    """r2d2d's answers (p_yes per question) to the gate's answers shape:
    {qid: {noul: p_yes}}. p_yes is P(the TRUE criterion), which is exactly the
    gate's noul (P(sensitive) / P(destructive))."""
    answers = response.get("answers")
    if not isinstance(answers, list) or len(answers) != len(ids):
        return None
    out = {}
    for qid, answer in zip(ids, answers):
        p_yes = answer.get("p_yes") if isinstance(answer, dict) else None
        if isinstance(p_yes, bool) or not isinstance(p_yes, (int, float)):
            return None
        p_yes = float(p_yes)
        if p_yes < 0.0 or p_yes > 1.0:
            return None
        out[qid] = {"noul": p_yes}
    return out


def _decider_post(url, envelope, timeout_ms):
    """One bounded POST to a Decider endpoint; returns (answers, status).
    The wire body is the Kikin native shape (_wire_questions); the response's
    pinned model hash is verified before its answers are trusted.
    honey_api "r2d2d" endpoints (Honey's decider-2b-v11 service, reached through
    the tailnet relay) speak their own /decide shape instead: the same envelope
    is translated by _r2d2d_body and the answers come back as p_yes noul."""
    import socket
    import urllib.error
    import urllib.request
    r2d2d = envelope.get("r2d2d")
    if r2d2d:
        wire, ids = _r2d2d_body(envelope)
        body = json.dumps(wire, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    else:
        body = json.dumps(_wire_questions(envelope), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "HelmCortex-Approval-Kikin/decider-in-the-loop"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout_ms / 1000.0) as response:
            raw = response.read(8 * 1024 * 1024)
        decoded = json.loads(raw)
        if r2d2d:
            # r2d2d carries no model hash; trust boundary is the sovereign
            # tailnet relay (allowlisted to Kikin) plus answer-shape checks.
            answers = _r2d2d_answers(decoded, ids)
            if answers is None:
                return None, "invalid"
            return answers, "ok"
        if not isinstance(decoded, dict) or decoded.get("model_sha256") != PINNED_MODEL_SHA256:
            return None, "hash_mismatch"
        answers = decoded.get("answers")
        if not isinstance(answers, dict):
            return None, "invalid"
        return answers, "ok"
    except (socket.timeout, TimeoutError):
        return None, "timeout"
    except (urllib.error.HTTPError, urllib.error.URLError, ConnectionError, OSError):
        return None, "unavailable"
    except (TypeError, ValueError):
        return None, "invalid"


def _decider_confidence(answers, mode):
    """Confidence that the prompt is NOT sensitive, from the Decider answers.
    Single mode: the noul answer maps to P(sensitive) directly, confidence is
    1 - noul. C1 mode: the joint C1 conditions; when all hold the confidence
    is the weakest margin across the six questions, else None (denied)."""
    if mode == "c1":
        conditions = _c1_conditions(answers)
        if conditions is None or not all(conditions):
            return None
        # The C1 conditions are the joint confidence gate themselves
        # (claude_approval._assessment_passes_c1 bounds); every one holding is
        # the manifest-threshold-equivalent pass.
        return 1.0
    single = answers.get(GREY_QUESTION_SINGLE)
    if not isinstance(single, dict):
        return None
    noul = single.get("noul")
    if isinstance(noul, bool) or not isinstance(noul, (int, float)):
        return None
    noul = float(noul)
    if noul < 0.0 or noul > 1.0:
        return None
    sensitive_confidence = 1.0 - noul
    if mode == "dual":
        # Interpreter bodies (heredoc / -c): non-sensitive is not enough — the
        # destructive question must ALSO clear the threshold (2026-10-10 review).
        destructive = answers.get(GREY_QUESTION_DESTRUCTIVE)
        if not isinstance(destructive, dict):
            return None
        destructive_noul = destructive.get("noul")
        if isinstance(destructive_noul, bool) or not isinstance(destructive_noul, (int, float)):
            return None
        destructive_noul = float(destructive_noul)
        if destructive_noul < 0.0 or destructive_noul > 1.0:
            return None
        destructive_confidence = 1.0 - destructive_noul
        return min(sensitive_confidence, destructive_confidence)
    return sensitive_confidence


def _decider_decide(event, config):
    """Consult Honey first, then Kikin. Returns (allow, status, latency_ms, verdict).
    Never raises: every failure is a conservative status that means ASK."""
    import time as _time
    started = _time.monotonic()
    deadline = started + config["timeout_ms"] / 1000.0
    request_id = "grey-" + __import__("hashlib").sha256(json.dumps(event.get("tool_input"), sort_keys=True, default=str).encode()).hexdigest()[:16]
    envelope = _c1_envelope(event, request_id, config["timeout_ms"], mode=config["mode"])
    status, verdict = "unavailable", "ask"
    for url, api in ((config["honey"], config.get("honey_api", "kikin")), (config["kikin"], "kikin")):
        if not url:
            continue
        remaining_ms = int((deadline - _time.monotonic()) * 1000)
        if remaining_ms < 200:
            status = "timeout" if status == "unavailable" else status
            break
        answers, endpoint_status = _decider_post(url, {**envelope, "r2d2d": api == "r2d2d"}, remaining_ms)
        if answers is not None:
            confidence = _decider_confidence(answers, config["mode"])
            if confidence is None:
                status, verdict = "threshold_failed", "ask"
            elif confidence >= config["threshold"]:
                status, verdict = "accepted", "allow"
            else:
                status, verdict = "threshold_failed", "ask"
            break
        if endpoint_status == "timeout":
            status = "timeout"
            break
        status = endpoint_status
    latency_ms = int((_time.monotonic() - started) * 1000)
    return verdict == "allow", status, latency_ms, verdict


def _log_decision(event, allow, reason):
    # Decision ledger (2026-10-09): one JSON line per prompt, so prompts saved and
    # misfires can be measured. It never records tool_input itself (commands and
    # paths can carry secrets), only a short digest for correlation. Logging must
    # never change the decision, so every failure here is swallowed.
    try:
        import datetime
        import hashlib
        path = Path(os.environ.get("SO_APPROVAL_KIKIN_LOG") or Path.home() / ".local/state/dotcortex/claude-approval-kikin.jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        event = event if isinstance(event, dict) else {}
        digest = hashlib.sha256(json.dumps(event.get("tool_input"), sort_keys=True, default=str).encode()).hexdigest()[:12]
        record = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "session": str(event.get("session_id") or "")[:64],
            "tool": str(event.get("tool_name") or "")[:64],
            "decision": "allow" if allow else "ask",
            "reason": reason,
            "input_sha": digest,
        }
        record.update(_log_decision.extras if hasattr(_log_decision, "extras") else {})
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
    except Exception:
        pass


def _deadline(_signal, _frame):
    raise TimeoutError("approval deadline")


def main():
    try:
        previous = signal.signal(signal.SIGALRM, _deadline)
        signal.setitimer(signal.ITIMER_REAL, 3.0)
    except Exception:
        return 0
    try:
        raw = sys.stdin.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("input too large")
        event = json.loads(raw)
        manifest = _load_manifest()
        allow, reason = classify(event, manifest)
        # Decider-in-the-loop: grey-zone reasons only. The true floor and every
        # deterministic class are decided above and are never revisited.
        if not allow and reason in ("no_match_decider", "syntax"):
            config = _decider_config(manifest)
            if config is not None:
                # 2026-10-10 (Fable review): a heredoc or -c interpreter body can
                # do anything, and single mode is fine only for plain reads and
                # syntax-only refusals — interpreter bodies AND write-capable
                # prompts (sed -i, redirects, cp/mv/tee) are judged with the
                # destructive question too (dual); c1-mode configs stay c1.
                if config["mode"] == "single" and (_interpreter_body(event) or _write_capable(event)):
                    config = {**config, "mode": "dual"}
                decider_allow, status, latency_ms, verdict = _decider_decide(event, config)
                _log_decision.extras = {"decider_status": status, "verdict": verdict, "latency_ms": latency_ms}
                if decider_allow:
                    allow, reason = True, "decider_allow"
        if allow:
            sys.stdout.write(json.dumps(ALLOW_OUTPUT, separators=(",", ":")) + "\n")
        _log_decision(event, allow, reason)
    except Exception as exc:
        _log_decision(None, False, f"error:{type(exc).__name__}")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
