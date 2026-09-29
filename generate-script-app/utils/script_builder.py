"""Safe construction of audit shell scripts from LLM-generated checks.

The commands here come from an LLM reading a benchmark PDF, so they are
UNTRUSTED input to the shell. This module is the single choke point that turns
a (rule, command) pair into a shell block, and it is deliberately strict:

  - The command is validated against an allowlist of read-only audit tools and
    rejected if it contains shell metacharacters that could chain, redirect,
    or substitute additional commands.
  - Rule text is only ever used as literal data inside a single-quoted echo,
    never executed.
  - The result row keeps your existing contract: benchmark|rule|command|result

Rejecting a command here means the LLM produced something we won't put in a
script - the caller logs it and moves on, rather than shipping unsafe shell.
"""
import re
import shlex

# Read-only tools an audit check is allowed to invoke as its FIRST word.
# Everything an audit legitimately needs is a read/inspect command; nothing
# here mutates state. Extend deliberately, not casually.
ALLOWED_COMMANDS = {
    "cat", "grep", "egrep", "fgrep", "awk", "gawk", "sed", "cut", "head", "tail",
    "stat", "ls", "find", "test", "[", "readlink", "realpath",
    "sysctl", "systemctl", "service",
    "getent", "id", "getcap", "getfacl", "lsattr", "mount", "findmnt",
    "sestatus", "getenforce", "aa-status", "ss", "ip", "iptables", "ip6tables",
    "sshd", "modprobe", "lsmod", "rpm", "dpkg", "dpkg-query", "auditctl",
    "grubby", "uname", "hostname", "wc", "echo", "printf", "date", "true",
    "false", "chage", "passwd", "crontab", "who", "last", "lastlog", "df",
    "sort", "uniq", "tr", "nft",
    # Read-only SELinux query tools (all inspect state, none mutate it):
    "semanage", "getsebool", "seinfo", "sesearch", "matchpathcon", "ausearch",
    "aureport",
    # Other read-only service/config query tools seen in real benchmarks:
    "postconf",      # Postfix config query (postconf -n is read-only)
    "sshd",          # sshd -T dumps effective config (already present above too)
    "apparmor_status", "journalctl", "lsof", "netstat", "ps", "namei",
    "sysctl", "ausyscall", "systemd-analyze",
    "ufw",           # `ufw status` is read-only (dual-use: guarded below)
    "gsettings",     # `gsettings get` is read-only (dual-use: guarded below)
}

# Dual-use tools: allowlisted as a binary, but only for read subcommands. Map
# each to the subcommands (its FIRST argument) we permit. Anything else - stop,
# start, disable, flush, delete, add, set, load - is a mutation and rejected.
SUBCOMMAND_ALLOW = {
    "systemctl": {"is-enabled", "is-active", "is-failed", "status", "show",
                  "list-units", "list-unit-files", "get-default", "cat"},
    "service": {"status"},
    "auditctl": {"-l", "-s"},
    "ip": {"addr", "a", "link", "route", "r", "rule", "-6"},
    "iptables": {"-L", "-S", "-n", "-t", "--list", "--list-rules"},
    "ip6tables": {"-L", "-S", "-n", "-t", "--list", "--list-rules"},
    "nft": {"list"},
    "crontab": {"-l"},
    "passwd": {"-S"},
    "ufw": {"status"},          # `ufw status` reads; enable/disable/allow mutate
    "gsettings": {"get", "list-recursively", "list-keys", "list-schemas",
                  "get-default"},  # get reads; `set`/`reset` mutate
    "modprobe": {"-n", "--showconfig", "-c", "--show-depends", "-D"},
    "mount": set(),          # bare `mount` lists; any arg is suspicious here
    "sysctl": None,          # read-only in practice; None = no subcmd restriction
    # semanage is dual-use: `semanage <object> -l` lists (read), while -a/-d/-m
    # add/delete/modify. Its object comes first (login/port/fcontext/...), so we
    # can't allow by subcommand; instead block its mutation FLAGS explicitly.
    "semanage": None,        # flag-level check below handles it
}

# Tools whose mutation is expressed as a FLAG rather than a subcommand/verb.
# Map tool -> set of flags that indicate a write. Presence of any = reject.
MUTATION_FLAGS = {
    "semanage": {"-a", "--add", "-d", "--delete", "-m", "--modify", "-D",
                 "--deleteall", "-C"},
    "setsebool": {"-P"},  # setsebool always mutates; not in allowlist anyway
    "journalctl": {"--flush", "--rotate", "--sync", "--relinquish-var",
                   "--vacuum-size", "--vacuum-time", "--vacuum-files"},
}

# Metacharacters that let a command chain, substitute, redirect, or background.
# We check for these ONLY in the parts of the command that are OUTSIDE quotes,
# so an awk/sed program in single quotes with $3 or () is fine, but a bare
# $(...) or ; is not.
_DANGEROUS_CHARS = set(";&`$><\n\r")


class UnsafeCommand(Exception):
    """Raised when an LLM-generated command is rejected as unsafe/unparseable."""


# A small allowlist of SPECIFIC safe shell idioms that appear constantly in real
# audit commands. Each is neutralized (blanked out) before the metacharacter
# scan, so the scan still catches every OTHER use of $(), >, &, etc. This is
# deliberately a fixed set of exact patterns, not a general relaxation:
#
#   $(uname -r)  $(uname -m)  $(uname -s)  $(hostname)  $(id -u)
#       - read-only command substitutions used to build paths like
#         /boot/config-$(uname -r). The inner command is itself read-only.
#   2>/dev/null  2>&1  1>/dev/null  &>/dev/null
#       - stderr/stdout redirection to discard noise (e.g. find's permission
#         errors). Redirection only to /dev/null or a merge, never to a file.
#
# Anything not matching these exact patterns still trips the normal checks.
_SAFE_IDIOMS = [
    r"\$\(uname -[rmsniop]\)",
    r"\$\(hostname\)",
    r"\$\(id -u\)",
    r"\$\(id -g\)",
    r"2>\s*/dev/null",
    r"2>&1",
    r"1>\s*/dev/null",
    r"&>\s*/dev/null",
    r">\s*/dev/null",
]
_SAFE_IDIOM_RE = re.compile("|".join(_SAFE_IDIOMS))


def _neutralize_safe_idioms(command):
    """Replace each allowlisted safe idiom with harmless placeholder spaces, so
    the metacharacter scanner doesn't see their $, (, >, & characters. Length is
    preserved (not that it matters) and only exact-pattern matches are blanked."""
    return _SAFE_IDIOM_RE.sub(lambda m: " " * len(m.group(0)), command)


def _strip_quoted(s):
    """Return s with the CONTENTS of single/double-quoted spans removed, so we
    can scan only the unquoted shell text for metacharacters. Quotes themselves
    are kept as empty pairs. A dangling quote raises (unbalanced = suspicious)."""
    out = []
    i, n = 0, len(s)
    quote = None
    while i < n:
        c = s[i]
        if quote:
            if c == quote:
                quote = None
        elif c in ("'", '"'):
            quote = c
        else:
            out.append(c)
        i += 1
    if quote:
        raise UnsafeCommand("unbalanced quotes")
    return "".join(out)


def _check_metachars(command):
    # Blank out the specific safe idioms FIRST, then scan whatever remains.
    scanned = _neutralize_safe_idioms(command)
    unquoted = _strip_quoted(scanned)
    for ch in unquoted:
        if ch in _DANGEROUS_CHARS:
            raise UnsafeCommand(f"metacharacter {ch!r} outside quotes")
    if "$(" in unquoted or "||" in unquoted or "&&" in unquoted:
        raise UnsafeCommand("command substitution or logical chain")


def _tokens(segment):
    try:
        tokens = shlex.split(segment.strip())
    except ValueError as e:
        raise UnsafeCommand(f"unparseable: {e}")
    if not tokens:
        raise UnsafeCommand("empty command segment")
    return tokens


# Mutation verbs that must never appear as a bare token in a read-only check.
# This backstops object-verb tools like `ip link delete` / `ip addr add` where
# the action isn't the first argument. Compared case-insensitively.
MUTATION_VERBS = {
    "add", "del", "delete", "set", "change", "replace", "flush", "start",
    "stop", "restart", "reload", "enable", "disable", "mask", "unmask",
    "remove", "install", "create", "destroy", "up", "down", "load", "insert",
    "append", "modify", "edit", "write", "truncate",
}


def _check_one_command(segment):
    """Validate a single (pipe-free) command segment: allowed binary +, for
    dual-use tools, an allowed read subcommand, and no mutation verb anywhere."""
    _check_metachars(segment)
    # For token analysis (binary, subcommand, mutation verbs), remove the safe
    # idioms entirely - they're redirections/substitutions, not the command's
    # verb or arguments, and leaving them in would confuse tokenization.
    cleaned = _SAFE_IDIOM_RE.sub(" ", segment)
    tokens = _tokens(cleaned)
    binary = tokens[0]
    if binary not in ALLOWED_COMMANDS:
        raise UnsafeCommand(f"command not in allowlist: {binary!r}")

    # Backstop: no mutation verb as a standalone token (skip the binary itself,
    # and skip anything that's clearly a value, e.g. a path or flag).
    for tok in tokens[1:]:
        if tok.lower() in MUTATION_VERBS:
            raise UnsafeCommand(f"mutation verb in command: {tok!r}")

    # find can execute or delete via flags - block its action flags explicitly.
    if binary == "find":
        for tok in tokens[1:]:
            if tok in ("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint",
                       "-fprintf", "-fls"):
                raise UnsafeCommand(f"find action flag not allowed: {tok!r}")

    # Tools whose write action is a flag (e.g. semanage -a) rather than a verb.
    if binary in MUTATION_FLAGS:
        bad = MUTATION_FLAGS[binary]
        for tok in tokens[1:]:
            # Match exact flags and --flag=value forms (split on '=' first).
            tok_base = tok.split("=", 1)[0]
            if tok in bad or tok_base in bad:
                raise UnsafeCommand(f"{binary} mutation flag not allowed: {tok!r}")

    if binary in SUBCOMMAND_ALLOW:
        allowed = SUBCOMMAND_ALLOW[binary]
        if allowed is None:
            return  # no subcommand restriction for this tool
        # first argument after the binary is the subcommand
        sub = tokens[1] if len(tokens) > 1 else None
        if sub is None and allowed:
            # e.g. bare `systemctl` with no read subcommand - reject
            raise UnsafeCommand(f"{binary} requires a read subcommand")
        if sub is not None and sub not in allowed:
            raise UnsafeCommand(f"{binary} subcommand not allowed: {sub!r}")


def validate_command(command):
    """Return the command if it is a safe, read-only audit check; else raise.

    Structure allowed:
      - An optional '&&' chain where EVERY segment is itself a safe read-only
        command (e.g. `dpkg-query -s x &>/dev/null && echo 'x'`). '&&' is
        dual-use, so it is permitted ONLY because each side is independently
        validated - `grep x && rm -rf /` still dies on the `rm` segment.
      - Within each '&&' segment, up to TWO pipes between allowlisted read-only
        commands (e.g. `awk ... | sort | uniq -d`).
      - Quoted awk/sed programs are preserved; dual-use tools are restricted to
        their read subcommands; mutation verbs/flags are rejected."""
    command = command.strip()
    if not command:
        raise UnsafeCommand("empty command")
    if len(command) > 500:
        raise UnsafeCommand("command too long")

    # Split on '&&' that sits outside quotes. Each resulting segment must be a
    # safe read-only command (or pipeline) in its own right.
    and_segments = _split_on_unquoted(command, "&&")
    for seg in and_segments:
        seg = seg.strip()
        if not seg:
            raise UnsafeCommand("empty '&&' segment")
        _validate_pipeline(seg)
    return command


def _validate_pipeline(segment):
    """Validate one '&&'-free segment: up to two pipes between read-only cmds."""
    # Neutralize safe idioms so their inner characters don't affect pipe counting.
    unquoted = _strip_quoted(_neutralize_safe_idioms(segment))
    outside_pipes = unquoted.count("|")

    if outside_pipes > 2:
        raise UnsafeCommand("too many pipes (max two)")

    if outside_pipes == 0:
        _check_one_command(segment)
        return

    parts = _split_on_unquoted(segment, "|")
    if len(parts) != outside_pipes + 1:
        raise UnsafeCommand("malformed pipe")
    for part in parts:
        _check_one_command(part)


def _split_on_unquoted(s, sep):
    """Split s on occurrences of `sep` that sit outside any quotes.

    Handles single- and double-quoted spans so a separator inside a quoted
    awk/sed program (or an echo string) does not cause a split."""
    parts = []
    buf = []
    quote = None
    i, n = 0, len(s)
    slen = len(sep)
    while i < n:
        c = s[i]
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            i += 1
        elif c in ("'", '"'):
            quote = c
            buf.append(c)
            i += 1
        elif s[i:i + slen] == sep:
            parts.append("".join(buf))
            buf = []
            i += slen
        else:
            buf.append(c)
            i += 1
    parts.append("".join(buf))
    return parts


def _sq(s):
    """Wrap a string as a safe single-quoted shell literal.

    Single quotes disable ALL shell interpretation; the only tricky character
    is ' itself, handled with the standard '\\'' idiom."""
    return "'" + s.replace("'", "'\\''") + "'"


def build_block(benchmark_name, rule, command):
    """Build one shell block for a validated check.

    Raises UnsafeCommand if the command doesn't pass validation - the caller
    decides whether to skip and log.
    """
    validated = validate_command(command)

    # rule and benchmark are DATA, emitted via single-quoted literals so they
    # can never be interpreted as shell. The command is run as-is (already
    # validated as read-only + metacharacter-free). Its text in the result row
    # is passed through a single-quoted literal too.
    #
    # CRITICAL: the result row must stay on ONE line. Commands like `mount` or
    # `getent passwd` emit many lines; if those newlines reached the output they
    # would break the 'benchmark|rule|command|result' parser (each extra line
    # becomes an unparseable row). So we collapse all whitespace/newlines in the
    # captured output to single spaces with `tr`, and cap the length so a huge
    # dump doesn't produce an enormous cell. The raw command still runs in full;
    # only its captured text is normalised for the single-line result format.
    return (
        f"# Rule: {rule}\n"
        f"__res=$({validated} 2>&1 | tr '\\n\\r\\t' '   ' | tr -s ' ' | cut -c1-1000)\n"
        f"printf '%s|%s|%s|%s\\n' {_sq(benchmark_name)} {_sq(rule)} "
        f"{_sq(command)} \"$__res\"\n"
    )


def build_script(benchmark_name, checks):
    """Assemble a full script from an iterable of (rule, command) pairs.

    Returns (script_text, accepted, rejected) where accepted/rejected are lists
    of (rule, command[, reason]) so the caller can report what was dropped.
    """
    lines = ["#!/bin/bash", "# Generated audit script - read-only checks only", ""]
    accepted, rejected = [], []
    for rule, command in checks:
        try:
            lines.append(build_block(benchmark_name, rule, command))
            accepted.append((rule, command))
        except UnsafeCommand as e:
            rejected.append((rule, command, str(e)))
    return "\n".join(lines) + "\n", accepted, rejected
