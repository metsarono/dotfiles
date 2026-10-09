#!/usr/bin/env python3
"""Fail-closed deterministic PermissionRequest rule engine for SO-APPROVAL P3."""

import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import signal
import stat
import subprocess
import sys


SCHEMA_VERSION = "so-approval-p3.v1"
HARD_TIMEOUT_SECONDS = 3.0
REMOTE_REALPATH_TIMEOUT_SECONDS = 2.5
CLASS_NAMES = (
    "ssh-kikin-readonly",
    "local-test-run",
    "centre-render",
    "dotcortex-safe-commit",
    "outbound-tool-call",
)
ALLOW_OUTPUT = {
    "hookSpecificOutput": {
        "hookEventName": "PermissionRequest",
        "decision": {"behavior": "allow"},
    }
}
SHELL_META_RE = re.compile(r"(?:[\n\r;]|&&|\|\||\$\(|`|[<>])")
SSH_RE = re.compile(
    r"^ssh -o BatchMode=yes ([A-Za-z0-9._-]+) '([^'\n\r]+)'$"
)
UNITTEST_RE = re.compile(
    r"^(?:python3|/usr/bin/python3) -m unittest "
    r"(FORGE\.tests\.[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)$"
)
PYTEST_RE = re.compile(
    r'^pytest ([A-Za-z0-9_./-]+) -q -m "not live"$'
)
CENTRE_COMMANDS = {
    "/usr/bin/python3 FORGE/bin/pokemon-centre render",
    "FORGE/bin/clubhouse-bosses-refresh",
}
READERS = {
    "cat",
    "head",
    "tail",
    "grep",
    "ls",
    "stat",
    "wc",
    "mailcortex",
    "pgrep",
    "date",
    "find",
}
GIT_READERS = {"log", "status", "diff", "show"}
FIND_WRITE_ACTIONS = {
    "-delete",
    "-exec",
    "-execdir",
    "-ok",
    "-okdir",
    "-fprint",
    "-fprint0",
    "-fprintf",
    "-fls",
}
GIT_UNSAFE_READ_OPTIONS = {
    "--ext-diff",
    "--textconv",
    "--exec-path",
    "--paginate",
}


class Rejected(ValueError):
    """Input is outside the exact allow shape."""


def _manifest_path():
    override = os.environ.get("SO_APPROVAL_P3_MANIFEST")
    if override:
        return Path(override)
    installed = Path.home() / ".config/dotcortex/claude-approval-p3.json"
    if installed.is_file():
        return installed
    source_tree = Path(__file__).resolve().parents[3]
    return source_tree / ".config/dotcortex/claude-approval-p3.json"


def _load_manifest():
    path = _manifest_path()
    data = json.loads(path.read_text(encoding="utf-8"))
    if set(data) != {
        "schema_version",
        "readonly_host",
        "remote_home",
        "remote_path_roots",
        "mailcortex_account",
        "local_test_roots",
        "centre_roots",
        "dotcortex_roots",
        "tmp_roots",
        "outbound_tools",
        "classes",
    }:
        raise Rejected("manifest keys")
    if data["schema_version"] != SCHEMA_VERSION:
        raise Rejected("manifest version")
    if not isinstance(data["readonly_host"], str) or not re.fullmatch(
        r"[A-Za-z0-9._-]+", data["readonly_host"]
    ):
        raise Rejected("readonly host")
    if not isinstance(data["remote_home"], str) or not data["remote_home"].startswith("/"):
        raise Rejected("remote home")
    if not isinstance(data["remote_path_roots"], list) or not data["remote_path_roots"]:
        raise Rejected("remote path roots")
    if any(
        not isinstance(root, str) or not root.startswith("/") or root == "/"
        for root in data["remote_path_roots"]
    ):
        raise Rejected("remote path root")
    if not isinstance(data["mailcortex_account"], str) or not data["mailcortex_account"]:
        raise Rejected("mailcortex account")
    for field in ("local_test_roots", "centre_roots", "dotcortex_roots"):
        if not isinstance(data[field], list) or not data[field]:
            raise Rejected(field)
        roots = []
        for raw in data[field]:
            if not isinstance(raw, str) or not raw.startswith("/"):
                raise Rejected(field)
            root = Path(raw).resolve(strict=False)
            if root == Path("/"):
                raise Rejected(field)
            roots.append(root)
        data[field] = roots
    if not isinstance(data["tmp_roots"], list) or not data["tmp_roots"]:
        raise Rejected("tmp roots")
    tmp_roots = []
    for raw in data["tmp_roots"]:
        if not isinstance(raw, str) or not raw.startswith("/"):
            raise Rejected("tmp root")
        root = Path(raw).resolve(strict=False)
        if root == Path("/"):
            raise Rejected("broad tmp root")
        tmp_roots.append(root)
    if not isinstance(data["outbound_tools"], list) or not all(
        isinstance(item, str) and item for item in data["outbound_tools"]
    ):
        raise Rejected("outbound tools")
    classes = data["classes"]
    if not isinstance(classes, list) or len(classes) != len(CLASS_NAMES):
        raise Rejected("classes")
    enabled = {}
    for expected, item in zip(CLASS_NAMES, classes):
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "enabled"}
            or item.get("name") != expected
            or type(item.get("enabled")) is not bool
        ):
            raise Rejected("class entry")
        enabled[expected] = item["enabled"]
    data["tmp_roots"] = tmp_roots
    data["enabled"] = enabled
    return data


def _protected_token(token):
    lowered = token.lower().replace("\\", "/")
    components = [part for part in lowered.split("/") if part]
    if "/home/gille" in lowered or "secret vault" in lowered:
        return True
    if ".git" in components or ".ssh" in components or ".env" in components:
        return True
    if "nexus/keys" in lowered:
        return True
    names = {
        ".netrc",
        ".authinfo",
        ".authinfo.gpg",
        "authorized_keys",
        "credentials",
        "credentials.json",
        "auth.json",
        "secrets.json",
        "id_rsa",
        "id_ed25519",
    }
    return any(part in names for part in components)


def _hard_never(command):
    if not isinstance(command, str) or not command or "\x00" in command:
        return True
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        return True
    lowered = [word.lower() for word in words]
    joined = " ".join(lowered)
    if any(_protected_token(word) for word in words):
        return True
    if re.search(r"(?:^|[;&|]\s*)git\s+(?:push|reset|revert)(?:\s|$)", joined):
        return True
    if re.search(r"(?:^|[;&|]\s*)git\s+worktree\s+prune(?:\s|$)", joined):
        return True
    if lowered and lowered[0] == "rm" and any(
        word == "--recursive" or (word.startswith("-") and "r" in word[1:])
        for word in lowered[1:]
    ):
        return True
    if any(word in {"sudo", "rc-service", "systemctl", "tailscale", "crontab"} for word in lowered):
        return True
    install_pairs = {
        "apt install",
        "apt-get install",
        "apk add",
        "dnf install",
        "yum install",
        "pacman -s",
        "zypper install",
        "brew install",
        "pip install",
        "pip3 install",
        "pipx install",
        "npm install",
        "npm i",
        "pnpm install",
        "yarn add",
        "cargo install",
        "guix install",
        "guix package",
    }
    if any(pair in joined for pair in install_pairs):
        return True
    if re.search(r"(?:python3|/usr/bin/python3)\s+-m\s+pip\s+install(?:\s|$)", joined):
        return True
    return False


def _inside(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _cwd_and_root(event, roots, exact=False):
    raw = event.get("cwd")
    if not isinstance(raw, str) or not raw.startswith("/"):
        raise Rejected("cwd")
    cwd = Path(raw).resolve(strict=False)
    for root in roots:
        if cwd == root or (not exact and _inside(cwd, root)):
            return cwd, root
    raise Rejected("cwd outside roots")


def _safe_relative_path(raw):
    if not raw or raw.startswith("/") or raw.startswith("~") or raw.startswith(":"):
        return False
    path = PurePosixPath(raw)
    if any(part in {"", ".", ".."} for part in path.parts):
        return False
    return not _protected_token(raw)


REMOTE_DYNAMIC_PATH = re.compile(r"[*?\[\]{}]")
REMOTE_EXCLUDED_COMPONENTS = {
    "private",
    "secrets",
    ".secrets",
    "keys",
    "credentials",
}


def _remote_path(raw, remote_home, base=None):
    if (
        not raw
        or "\x00" in raw
        or "$" in raw
        or "`" in raw
        or REMOTE_DYNAMIC_PATH.search(raw)
        or any(ord(character) < 32 or ord(character) == 127 for character in raw)
    ):
        return None
    if raw == "~":
        path = remote_home
    elif raw.startswith("~/"):
        path = remote_home.rstrip("/") + raw[1:]
    elif raw.startswith("~"):
        return None
    elif raw.startswith("/"):
        path = "/" + raw.lstrip("/")
    else:
        path = posixpath.join(base or remote_home, raw)
    normalized = posixpath.normpath(path)
    return normalized if normalized.startswith("/") else None


def _remote_path_excluded(path):
    components = tuple(part.lower() for part in path.split("/") if part)
    if (
        any(part in REMOTE_EXCLUDED_COMPONENTS for part in components)
        or "palmcortex" in components
        or any(
            components[index:index + 3] == ("logs", "telegram", "personal")
            for index in range(max(0, len(components) - 2))
        )
    ):
        return True
    basename = components[-1] if components else ""
    return (
        basename in {"env", ".env", "auth.json"}
        or basename.endswith((".env", ".token", ".key", ".pem", ".jar"))
        or basename.startswith("cookies")
        or "token" in basename
        or "secret" in basename
    )


def _remote_paths_allowed(raw_paths, manifest, base=None):
    roots = tuple(
        _remote_path(raw, manifest["remote_home"])
        for raw in manifest["remote_path_roots"]
    )
    if any(root is None for root in roots):
        return None
    resolved = []
    for raw in raw_paths:
        path = _remote_path(raw, manifest["remote_home"], base=base)
        if (
            path is None
            or not any(path == root or path.startswith(root.rstrip("/") + "/") for root in roots)
            or _remote_path_excluded(path)
        ):
            return None
        resolved.append(path)
    return resolved


def _remote_analysis(paths, realpath_paths=None):
    return {
        "paths": list(paths),
        "realpath_paths": list(paths if realpath_paths is None else realpath_paths),
    }


def _remote_git_paths(args, repo_raw, manifest):
    repo = _remote_path(repo_raw, manifest["remote_home"])
    roots = tuple(
        _remote_path(raw, manifest["remote_home"])
        for raw in manifest["remote_path_roots"]
    )
    if (
        repo is None
        or any(root is None for root in roots)
        or not any(repo == root or repo.startswith(root.rstrip("/") + "/") for root in roots)
        or _remote_path_excluded(repo)
    ):
        return None
    subcommand = args[0]
    remainder = list(args[1:])
    if any(REMOTE_DYNAMIC_PATH.search(token) for token in remainder):
        return None
    lexical_paths = [repo]
    realpath_paths = [repo]
    if subcommand == "show":
        if "--" in remainder:
            return None
        object_paths = []
        for token in remainder:
            if token.startswith("-"):
                continue
            if ":" not in token:
                continue
            revision, object_path = token.split(":", 1)
            if not revision or not object_path or object_path.startswith("/"):
                return None
            object_paths.append(object_path)
        resolved_objects = _remote_paths_allowed(object_paths, manifest, base=repo)
        if resolved_objects is None:
            return None
        lexical_paths.extend(resolved_objects)
        return _remote_analysis(lexical_paths, realpath_paths)

    disk_raw_paths = []
    if "--" in remainder:
        if remainder.count("--") != 1:
            return None
        separator = remainder.index("--")
        disk_raw_paths = remainder[separator + 1:]
        if not disk_raw_paths:
            return None
    elif subcommand == "status":
        disk_raw_paths = [token for token in remainder if not token.startswith("-")]
    resolved_disk = _remote_paths_allowed(disk_raw_paths, manifest, base=repo)
    if resolved_disk is None:
        return None
    lexical_paths.extend(resolved_disk)
    realpath_paths.extend(resolved_disk)
    return _remote_analysis(lexical_paths, realpath_paths)


def _reader_segment(segment, manifest):
    try:
        words = shlex.split(segment, posix=True)
    except ValueError:
        return None
    if not words:
        return None
    command = words[0]
    if command == "git":
        args = words[1:]
        repo_raw = "."
        if args[:1] == ["-C"]:
            if len(args) < 3:
                return None
            repo_raw = args[1]
            args = args[2:]
        if not args or args[0] not in GIT_READERS:
            return None
        if any(
            word in GIT_UNSAFE_READ_OPTIONS or word in {"-C"} or word.startswith(("--output=", "--git-dir=", "--work-tree="))
            for word in args[1:]
        ):
            return None
        return _remote_git_paths(args, repo_raw, manifest)
    if command not in READERS:
        return None
    args = words[1:]
    if command == "cat":
        paths = _remote_paths_allowed(args, manifest) if args and all(not item.startswith("-") for item in args) else None
        return None if paths is None else _remote_analysis(paths)
    if command == "mailcortex":
        if not args or args[0] not in {"inbox", "read"}:
            return None
        expected = 2 if args[0] == "inbox" else 3
        return _remote_analysis([]) if (
            len(args) == expected
            and args[1] == manifest["mailcortex_account"]
            and all(not item.startswith("-") for item in args[1:])
        ) else None
    if command == "find":
        if not args or any(
            word in FIND_WRITE_ACTIONS or any(word.startswith(item + "=") for item in FIND_WRITE_ACTIONS)
            for word in args
        ):
            return None
        cursor = 0
        while cursor < len(args) and not args[cursor].startswith("-") and args[cursor] not in {"!", ","}:
            cursor += 1
        starts = args[:cursor]
        expression = args[cursor:]
        if not starts or any(REMOTE_DYNAMIC_PATH.search(item) for item in expression):
            return None
        for index, item in enumerate(expression):
            if item in {"-name", "-iname"}:
                if index + 1 >= len(expression) or _remote_path_excluded("/" + expression[index + 1]):
                    return None
        paths = _remote_paths_allowed(starts, manifest)
        return None if paths is None else _remote_analysis(paths)
    if command in {"head", "tail"}:
        if not args or any(item in {"-f", "--follow", "--retry", "--pid"} or item.startswith(("--follow=", "--pid=")) for item in args):
            return None
        cursor = 0
        while cursor < len(args) and args[cursor].startswith("-"):
            option = args[cursor]
            if re.fullmatch(r"-\d+", option):
                cursor += 1
                continue
            if option in {"-n", "--lines", "-c", "--bytes"} and cursor + 1 < len(args):
                cursor += 2
                continue
            if option.startswith(("--lines=", "--bytes=")):
                cursor += 1
                continue
            return None
        if cursor >= len(args):
            return _remote_analysis([])
        paths = _remote_paths_allowed(args[cursor:], manifest)
        return None if paths is None else _remote_analysis(paths)
    if command == "grep":
        safe_flags = {"-E", "-F", "-G", "-H", "-h", "-i", "-l", "-n", "-s", "-v", "-w", "-x", "-c"}
        cursor = 0
        explicit_pattern = False
        while cursor < len(args) and args[cursor].startswith("-"):
            option = args[cursor]
            if option in safe_flags or option == "--color=never":
                cursor += 1
                continue
            if option in {"-e", "--regexp", "-m", "--max-count"} and cursor + 1 < len(args):
                explicit_pattern = explicit_pattern or option in {"-e", "--regexp"}
                cursor += 2
                continue
            if option.startswith(("--regexp=", "--max-count=")):
                explicit_pattern = explicit_pattern or option.startswith("--regexp=")
                cursor += 1
                continue
            return None
        operands = args[cursor:]
        if not explicit_pattern:
            if not operands:
                return None
            operands = operands[1:]
        if any(item.startswith("-") for item in operands):
            return None
        if not operands:
            return _remote_analysis([])
        paths = _remote_paths_allowed(operands, manifest)
        return None if paths is None else _remote_analysis(paths)
    if command == "pgrep":
        return _remote_analysis([]) if args and all(
            not item.startswith("-") or item in {"-c", "-l", "-x", "--count", "--exact", "--list-name"}
            for item in args
        ) and len([item for item in args if not item.startswith("-")]) == 1 else None
    if command == "date":
        return _remote_analysis([]) if all(
            item in {"-u", "--utc", "-R", "--rfc-email"}
            or item.startswith(("+", "--iso-8601", "--date="))
            for item in args
        ) else None
    if command == "wc" and any(item == "--files0-from" or item.startswith("--files0-from=") for item in args):
        return None
    if command in {"ls", "stat", "wc"}:
        operands = [item for item in args if not item.startswith("-")]
        if command in {"ls", "stat"} and not operands:
            return None
        if not operands:
            return _remote_analysis([])
        paths = _remote_paths_allowed(operands, manifest)
        return None if paths is None else _remote_analysis(paths)
    return None


def _ssh_readonly(command, manifest):
    match = SSH_RE.fullmatch(command)
    if not match or match.group(1) != manifest["readonly_host"]:
        return False
    remote = match.group(2)
    if SHELL_META_RE.search(remote.replace("|", "")):
        return False
    if "||" in remote or remote.startswith("|") or remote.endswith("|"):
        return False
    if _hard_never(remote):
        return False
    parts = [part.strip() for part in remote.split("|")]
    analyses = [_reader_segment(part, manifest) if part else None for part in parts]
    if not parts or any(analysis is None for analysis in analyses):
        return None
    return {
        "paths": [path for analysis in analyses for path in analysis["paths"]],
        "realpath_paths": [
            path for analysis in analyses for path in analysis["realpath_paths"]
        ],
    }


def _run_remote_realpath(argv, timeout_seconds):
    return subprocess.run(
        list(argv),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )


def _remote_realpath_proven(analysis, manifest, runner):
    paths = analysis.get("realpath_paths")
    if not isinstance(paths, list) or any(not isinstance(path, str) for path in paths):
        return False
    if not paths:
        return True
    argv = (
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=3",
        manifest["readonly_host"],
        "realpath",
        "-e",
        "--",
        *(shlex.quote(path) for path in paths),
    )
    completed = runner(argv, REMOTE_REALPATH_TIMEOUT_SECONDS)
    if getattr(completed, "returncode", None) != 0:
        return False
    stdout = getattr(completed, "stdout", None)
    if (
        not isinstance(stdout, str)
        or not stdout.endswith("\n")
        or "\r" in stdout
        or "\x00" in stdout
    ):
        return False
    resolved = stdout[:-1].split("\n")
    if len(resolved) != len(paths) or any(
        not path
        or not path.startswith("/")
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
        for path in resolved
    ):
        return False
    checked = _remote_paths_allowed(resolved, manifest)
    return checked == resolved


def _local_test(command, event, manifest):
    cwd, root = _cwd_and_root(event, manifest["local_test_roots"])
    if SHELL_META_RE.search(command):
        return False
    if UNITTEST_RE.fullmatch(command):
        return True
    match = PYTEST_RE.fullmatch(command)
    if not match or not _safe_relative_path(match.group(1)):
        return False
    target = (cwd / match.group(1)).resolve(strict=False)
    try:
        info = target.lstat()
    except OSError:
        return False
    return _inside(target, root) and stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)


def _centre(command, event, manifest):
    cwd, _root = _cwd_and_root(event, manifest["centre_roots"], exact=True)
    if command not in CENTRE_COMMANDS:
        return False
    script = "FORGE/bin/pokemon-centre" if command.startswith("/usr/bin/python3 ") else command
    target = (cwd / script).resolve(strict=False)
    try:
        info = target.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)


def _safe_commit(command, event, manifest):
    cwd, root = _cwd_and_root(event, manifest["dotcortex_roots"], exact=True)
    if cwd != root or SHELL_META_RE.search(command) or _hard_never(command):
        return False
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        return False
    if len(words) < 6 or words[:2] != ["git", "commit"] or words[2] != "-F":
        return False
    try:
        separator = words.index("--", 4)
    except ValueError:
        return False
    if separator != 4 or not words[5:]:
        return False
    message = Path(words[3])
    if not message.is_absolute():
        message = cwd / message
    try:
        info = message.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        return False
    if info.st_uid != os.getuid() or not any(
        _inside(message.resolve(strict=False), root) and message.resolve(strict=False) != root
        for root in manifest["tmp_roots"]
    ):
        return False
    for raw in words[5:]:
        if not _safe_relative_path(raw):
            return False
        target = (cwd / raw).resolve(strict=False)
        try:
            target_info = target.lstat()
        except OSError:
            return False
        if (
            not _inside(target, root)
            or not stat.S_ISREG(target_info.st_mode)
            or stat.S_ISLNK(target_info.st_mode)
        ):
            return False
    return True


def _protected_tool_input(tool_input):
    try:
        raw = json.dumps(tool_input, ensure_ascii=False, sort_keys=True).lower().replace("\\\\", "/")
    except (TypeError, ValueError):
        return True
    return any(
        marker in raw
        for marker in (
            "/home/gille",
            "secret vault",
            "nexus/keys",
            "/.ssh/",
            "~/.ssh/",
            "/.env",
            "auth.json",
            "credentials.json",
            "oauth.json",
        )
    )


def _candidate(event, manifest):
    tool_name = event.get("tool_name")
    tool_input = event.get("tool_input")
    if not isinstance(tool_name, str) or not isinstance(tool_input, dict):
        raise Rejected("tool event")
    if tool_name != "Bash":
        if tool_name in manifest["outbound_tools"] and not _protected_tool_input(tool_input):
            return "outbound-tool-call", True
        raise Rejected("unknown tool")
    if set(tool_input) != {"command"} or not isinstance(tool_input.get("command"), str):
        raise Rejected("bash input")
    command = tool_input["command"]
    if _hard_never(command):
        raise Rejected("hard never")
    parsers = (
        ("ssh-kikin-readonly", lambda: _ssh_readonly(command, manifest)),
        ("local-test-run", lambda: _local_test(command, event, manifest)),
        ("centre-render", lambda: _centre(command, event, manifest)),
        ("dotcortex-safe-commit", lambda: _safe_commit(command, event, manifest)),
    )
    matches = []
    for name, parser in parsers:
        try:
            parsed = parser()
            if parsed:
                matches.append((name, parsed if name == "ssh-kikin-readonly" else None))
        except (OSError, Rejected, ValueError):
            continue
    if len(matches) != 1:
        raise Rejected("no unique rule")
    return matches[0]


def evaluate(event, manifest, remote_path_runner=_run_remote_realpath):
    if not isinstance(event, dict) or event.get("hook_event_name") != "PermissionRequest":
        raise Rejected("event")
    rule, analysis = _candidate(event, manifest)
    if manifest["enabled"].get(rule) is not True:
        return False
    if rule == "ssh-kikin-readonly":
        try:
            return _remote_realpath_proven(analysis, manifest, remote_path_runner)
        except Exception:
            return False
    return True


def _deadline(_signum, _frame):
    raise TimeoutError("approval deadline")


def main():
    try:
        previous_handler = signal.signal(signal.SIGALRM, _deadline)
        signal.setitimer(signal.ITIMER_REAL, HARD_TIMEOUT_SECONDS)
    except Exception:
        return 0
    try:
        raw = sys.stdin.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise Rejected("input too large")
        event = json.loads(raw)
        manifest = _load_manifest()
        if evaluate(event, manifest):
            sys.stdout.write(json.dumps(ALLOW_OUTPUT, separators=(",", ":")))
            sys.stdout.write("\n")
    except Exception:
        pass
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
