#!/usr/bin/env python3
"""Pre-install gate for third-party Claude Code skills, plugins and MCP servers.

WHY THIS EXISTS
Anything installed into ~/.claude/ runs in EVERY session on the machine, with whatever
tools that session has.  Skills, plugin hooks and MCP servers are all just code somebody
else wrote, and installing one is running it.  Once you install other people's packages
routinely, "read it first" has to stop being a good intention.

WHAT IT IS NOT
It does NOT decide whether something is safe, and it never prints a verdict.  A checker
that outputs SAFE would be trusted exactly as much as a real audit and cost nothing to be
wrong.

What it does instead is mechanical and honest: fetch the package WITHOUT installing it,
then list every place it (1) executes code, (2) reaches the network, (3) touches
credentials, (4) writes outside its own folder, or (5) hides what it is doing.  Then a
human reads those specific lines.  The point is to turn "read 4,000 lines" into "read
these 12", which is a thing that actually gets done.

WHY A SCRIPT AND NOT A HOOK
A hook would be better - it cannot be forgotten.  It loses here on capability: plugin
installs happen through the /plugin slash command, not through the Bash tool, so a
PreToolUse hook never sees the event.  A guard that cannot observe the thing it guards is
worse than none, because it looks like cover.  So this one you have to remember to run.

USAGE
    inspect-third-party.py fetch  <git-url-or-local-path> [--name NAME]
    inspect-third-party.py report <NAME>
    inspect-third-party.py install <NAME> [--kind skill|plugin]
    inspect-third-party.py undo   <NAME>
    inspect-third-party.py list

Quarantine lives at ~/.claude-quarantine/ -- deliberately OUTSIDE ~/.claude, so fetching
something can never make it live.  Override with CLAUDE_QUARANTINE; the install target
follows CLAUDE_CONFIG_DIR, as Claude Code itself does.

EXIT CODES for `report`:  0 = nothing flagged, 1 = findings to read, 2 = could not inspect.
A guard that cannot run must say so, never shrug.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

HOME = os.path.expanduser("~")
QUARANTINE = os.environ.get("CLAUDE_QUARANTINE") or os.path.join(HOME, ".claude-quarantine")
CLAUDE_DIR = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(HOME, ".claude")
MANIFEST_DIR = os.path.join(QUARANTINE, "_manifests")

# Files worth reading at all.  Binaries and media are reported by name only -- we do not
# pretend to inspect what we cannot read.
TEXT_EXT = {
    ".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl",
    ".ps1", ".psm1", ".cmd", ".bat", ".md", ".json", ".yaml", ".yml", ".toml", ".txt", ".cfg", ".ini",
}
EXECUTABLE_EXT = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl",
                  ".ps1", ".psm1", ".cmd", ".bat"}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}

# Legal boilerplate matches half the pattern list and means nothing.  Left in the file list
# so it is visible, but not scanned -- the first test run produced four findings from an
# Apache licence, and a report that is mostly false positives does not get read.
LICENCE_FILES = {"license", "licence", "license.md", "licence.md", "license.txt",
                 "copying", "notice", "notice.txt", "authors", "contributors"}

# PowerShell is case-insensitive, so its cmdlets are matched case-insensitively. Everything
# else is a plain, case-sensitive substring on purpose: easy to audit, no regex surprises,
# and far fewer false positives than lower-casing `_TOKEN` into every variable name.
PS = lambda *words: re.compile(r"(?i)(?<![\w-])(%s)(?![\w-])" % "|".join(map(re.escape, words)))

# Each rule: (category, human explanation, list of literal needles or compiled regexes)
RULES = [
    ("NETWORK", "reaches the network -- where does the data go, and what comes back?", [
        "curl ", "wget ", "fetch(", "requests.get", "requests.post", "urllib",
        "http://", "https://", "axios", "XMLHttpRequest", "urlopen", "httpx",
        "socket.", "nc -", "ssh ", "scp ",
        PS("Invoke-WebRequest", "iwr", "Invoke-RestMethod", "irm", "Start-BitsTransfer", "Net.WebClient"),
    ]),
    ("CREDENTIALS", "reads secrets or identity files -- nothing legitimate needs most of these", [
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AWS_SECRET", "AWS_ACCESS_KEY",
        "GITHUB_TOKEN", "GH_TOKEN", "_TOKEN", "_SECRET", "_PASSWORD", "API_KEY",
        ".env", ".aws", ".ssh", "id_rsa", "id_ed25519", ".netrc", "credentials",
        ".claude.json", "keychain", "gnome-keyring", "Credential",
    ]),
    ("WRITES_OUTSIDE", "writes outside its own folder -- into your config, your home, or system paths", [
        "~/.claude", ".claude/settings", "settings.json", "CLAUDE.md",
        "os.path.expanduser", "$HOME", "%USERPROFILE%", "/etc/", "/usr/local/",
        "crontab", "systemctl", "launchctl", ">> ~/", "> ~/",
        PS("Set-ItemProperty", "New-ItemProperty", "HKLM", "HKCU", "Register-ScheduledTask"),
    ]),
    ("EXECUTES", "runs other programs or evaluates strings at runtime", [
        "subprocess", "os.system", "os.popen", "child_process", "execSync", "spawnSync",
        "eval(", "exec(", "Function(", "source ", ". /",
        PS("Invoke-Expression", "iex", "Start-Process", "Invoke-Command"),
    ]),
    ("OBFUSCATION", "hides what it is doing -- treat any hit here as disqualifying until explained", [
        "base64 -d", "base64 --decode", "b64decode", "atob(", "fromCharCode",
        "\\x68\\x74\\x74\\x70", "rot13", "codecs.decode", "gzip.decompress", "zlib.decompress",
        "chr(", "unescape(", PS("FromBase64String", "-EncodedCommand", "-enc"),
    ]),
    ("DESTRUCTIVE", "deletes or overwrites -- confirm the target is inside its own folder", [
        "rm -rf", "rm -r ", "shutil.rmtree", "unlink(", "rmdir /s",
        "git push --force", "git reset --hard", "truncate", "DROP TABLE",
        PS("Remove-Item"),
    ]),
]

# Files that make a package ACT rather than just describe -- these get read first.
ACTIVE_FILENAMES = {"hooks.json", "plugin.json", ".mcp.json", "mcp.json", "package.json",
                    "install.sh", "setup.py", "postinstall.js", "makefile"}

# Terminal control characters. The report prints lines copied out of somebody else's files,
# and an ESC sequence in one of them could move the cursor and overwrite the findings above
# it on screen. Everything below 0x20 except tab, plus DEL and the C1 range, becomes '?'.
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean(s):
    return CONTROL.sub("?", s)


def die(msg, code=2):
    sys.stderr.write("ERROR: %s\n" % msg)
    sys.exit(code)


def safe_name(name):
    """A package name becomes a folder name in two places. Never let it climb out."""
    n = re.sub(r"[^A-Za-z0-9._-]", "-", name or "")
    if not n or n.startswith(".") or n == "_manifests":
        die("%r is not a usable package name. Use --name with letters, digits, - or _." % name)
    return n


def ensure_dirs():
    for d in (QUARANTINE, MANIFEST_DIR):
        if not os.path.isdir(d):
            os.makedirs(d)


def walk(root):
    """Yield (path, is_symlink). Symlinked directories are reported, never descended into."""
    for dirpath, dirnames, filenames in os.walk(root):
        keep = []
        for d in sorted(dirnames):
            if d in SKIP_DIRS:
                continue
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                yield full, True
            else:
                keep.append(d)
        dirnames[:] = keep
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            yield full, os.path.islink(full)


def find_symlinks(root):
    return [os.path.relpath(p, root).replace("\\", "/") for p, link in walk(root) if link]


def read_text(path):
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except Exception:
        return None
    if b"\x00" in raw[:4096]:
        return None  # binary
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return None


def matches(needle, line):
    return needle.search(line) is not None if hasattr(needle, "search") else needle in line


# ---------------------------------------------------------------- fetch

def cmd_fetch(args):
    ensure_dirs()
    src = args.source
    base = src.rstrip("/\\").replace("\\", "/").split("/")[-1]
    name = safe_name(args.name or re.sub(r"\.git$", "", base))
    dest = os.path.join(QUARANTINE, name)

    if os.path.exists(dest):
        die("%s already in quarantine. Inspect it, or remove %s first." % (name, dest))

    if os.path.isdir(src):
        # symlinks=True copies a link AS a link. The default would follow it and copy
        # whatever it points at - a link to ~/.ssh/id_rsa would bring your key along.
        shutil.copytree(src, dest, symlinks=True, ignore=shutil.ignore_patterns(*SKIP_DIRS))
        origin = os.path.abspath(src)
    else:
        # --depth 1 keeps it small; no submodules, which would fetch code we did not name.
        # `--` so a source that starts with "-" is a URL, never an option.
        rc = subprocess.call(["git", "clone", "--depth", "1", "--no-recurse-submodules", "--", src, dest])
        if rc != 0:
            die("git clone failed for %s" % src)
        origin = src

    with open(os.path.join(MANIFEST_DIR, name + ".origin"), "w", encoding="utf-8") as fh:
        fh.write(origin + "\n")

    print("Quarantined at: %s" % dest)
    print("NOT installed. Nothing from this package can run yet.")
    print("")
    print("Next:  inspect-third-party.py report %s" % name)
    return 0


# ---------------------------------------------------------------- report

def markdown_scan_mask(lines):
    """Line numbers inside YAML frontmatter or fenced code - the parts of a .md that act."""
    mask = set()
    fence = None
    in_fm = False
    for i, line in enumerate(lines, 1):
        st = line.strip()
        if i == 1 and st == "---":
            in_fm = True
            mask.add(i)
            continue
        if in_fm:
            mask.add(i)
            if st == "---":
                in_fm = False
            continue
        marker = st[:3]
        if marker in ("```", "~~~"):
            if fence is None:
                fence = marker
            elif marker == fence:
                fence = None
            mask.add(i)
            continue
        if fence:
            mask.add(i)
    return mask


def cmd_report(args):
    name = safe_name(args.name)
    root = os.path.join(QUARANTINE, name)
    if not os.path.isdir(root):
        die("%s is not in quarantine. Run `fetch` first." % name)

    findings = {}      # category -> list of (relpath, lineno, line)
    active = []
    unreadable = []
    licences = []
    prose = []
    symlinks = []
    total_files = 0
    total_lines = 0

    for path, is_link in walk(root):
        rel = os.path.relpath(path, root).replace("\\", "/")
        if is_link:
            try:
                target = os.readlink(path)
            except OSError:
                target = "?"
            symlinks.append((rel, target))
            continue

        total_files += 1
        ext = os.path.splitext(path)[1].lower()
        base = os.path.basename(path)

        text = None
        if not ext or ext in TEXT_EXT or base.lower() in ACTIVE_FILENAMES:
            text = read_text(path)

        # A file with no extension that starts with #! is a script, whatever it is called.
        shebang = text is not None and text.startswith("#!")
        if base.lower() in ACTIVE_FILENAMES or ext in EXECUTABLE_EXT or shebang:
            active.append(rel)

        if base.lower() in LICENCE_FILES:
            licences.append(rel)
            continue

        if text is None:
            unreadable.append(rel)
            continue

        lines = text.splitlines()
        total_lines += len(lines)

        # A .md file in a skill or plugin is INSTRUCTIONS -- it is read by the model, not run
        # by a shell.  Pattern-matching its prose produces noise (a README that merely says
        # the words "CLAUDE.md" is not writing to it).  So inside Markdown, the rules apply
        # only to fenced code and YAML frontmatter, which are the parts that become actions.
        #
        # This is a deliberate blind spot and it is the dangerous one: a hostile skill's
        # payload IS prose -- instructions telling a session to exfiltrate something.  No
        # pattern can judge that, so the prose is counted and surfaced for a human to READ
        # rather than silently dropped.
        scan_mask = None
        if ext == ".md":
            scan_mask = markdown_scan_mask(lines)
            prose_lines = len(lines) - len(scan_mask)
            if prose_lines > 0:
                prose.append((rel, prose_lines))

        for i, line in enumerate(lines, 1):
            if scan_mask is not None and i not in scan_mask:
                continue
            if len(line) > 400:
                findings.setdefault("OBFUSCATION", []).append(
                    (rel, i, "<line is %d chars -- long enough to hide a payload>" % len(line)))
                continue
            for category, _why, needles in RULES:
                if any(matches(n, line) for n in needles):
                    findings.setdefault(category, []).append((rel, i, line.strip()[:200]))

    # ---- output. Every string that came from the package goes through clean().
    print("=" * 78)
    print("PRE-INSTALL REPORT: %s" % name)
    print("=" * 78)
    origin_file = os.path.join(MANIFEST_DIR, name + ".origin")
    if os.path.isfile(origin_file):
        print("Source : %s" % clean(open(origin_file, encoding="utf-8").read().strip()))
    print("Scanned: %d files, %d lines of readable text" % (total_files, total_lines))
    print("")
    print("This report does NOT say whether the package is safe. It says where to look.")
    print("")

    if symlinks:
        print("-- SYMBOLIC LINKS (%d) -- not followed, and `install` will refuse them --" % len(symlinks))
        print("   A link can point anywhere on your disk. Check where each one goes.")
        for rel, target in symlinks[:25]:
            print("   %s -> %s" % (clean(rel), clean(target)))
        print("")

    if active:
        print("-- CODE THAT WILL ACTUALLY RUN (%d files) --" % len(active))
        for rel in active[:40]:
            print("   %s" % clean(rel))
        if len(active) > 40:
            print("   ... and %d more" % (len(active) - 40))
        print("")

    if prose:
        total_prose = sum(n for _r, n in prose)
        print("-- INSTRUCTIONS TO THE MODEL (%d files, %d lines of prose) --" % (len(prose), total_prose))
        print("   Patterns were NOT applied to this text, because prose is not code and")
        print("   matching it produces noise. But this is the payload that a hostile skill")
        print("   would use, and no scanner can judge it. Read these yourself.")
        for rel, n in sorted(prose, key=lambda x: -x[1])[:15]:
            print("   %-55s %5d lines" % (clean(rel), n))
        if len(prose) > 15:
            print("   ... and %d more" % (len(prose) - 15))
        print("")

    if licences:
        print("-- LICENCE TEXT, NOT SCANNED (%d) --  %s" % (len(licences), clean(", ".join(licences[:5]))))
        print("")

    if unreadable:
        print("-- NOT INSPECTED (%d binary/unknown files) --" % len(unreadable))
        print("   These were not read at all. If any is executable, this report is blind to it.")
        for rel in unreadable[:15]:
            print("   %s" % clean(rel))
        if len(unreadable) > 15:
            print("   ... and %d more" % (len(unreadable) - 15))
        print("")

    for category, why, _n in RULES:
        hits = findings.get(category)
        if not hits:
            continue
        print("-- %s (%d) --" % (category, len(hits)))
        print("   %s" % why)
        for rel, lineno, line in hits[:25]:
            print("   %s:%d" % (clean(rel), lineno))
            print("       %s" % clean(line))
        if len(hits) > 25:
            print("   ... and %d more hits in this category" % (len(hits) - 25))
        print("")

    if not findings and not symlinks:
        print("Nothing matched the pattern list.")
        print("That is NOT a clean bill of health -- it means this tool found nothing it")
        print("knows how to look for. Read the files above yourself before installing.")
        print("")

    print("=" * 78)
    print("To install : inspect-third-party.py install %s --kind skill" % name)
    print("To undo    : inspect-third-party.py undo %s" % name)
    print("=" * 78)
    return 1 if (findings or symlinks) else 0


# ---------------------------------------------------------------- install / undo

def cmd_install(args):
    name = safe_name(args.name)
    src = os.path.join(QUARANTINE, name)
    if not os.path.isdir(src):
        die("%s is not in quarantine." % name)

    links = find_symlinks(src)
    if links:
        die("%s contains %d symbolic link(s), e.g. %s. A link installed into ~/.claude can\n"
            "       point at anything on your disk. Replace them with real files first." % (name, len(links), links[0]))

    kind = args.kind
    target_parent = os.path.join(CLAUDE_DIR, "skills" if kind == "skill" else "plugins")
    dest = os.path.join(target_parent, name)
    if os.path.exists(dest):
        die("%s already exists. Run `undo %s` first." % (dest, name))

    if not os.path.isdir(target_parent):
        os.makedirs(target_parent)

    # The manifest is what makes the undo REAL: it records exactly what landed, and undo
    # refuses to remove anything not on this list.
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns(*SKIP_DIRS))
    copied = sorted(os.path.relpath(p, CLAUDE_DIR).replace("\\", "/") for p, _l in walk(dest))

    manifest = {"name": name, "kind": kind, "installed_to": dest, "files": copied}
    with open(os.path.join(MANIFEST_DIR, name + ".manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

    print("Installed %d files to %s" % (len(copied), dest))
    print("")
    print("This affects EVERY session on this machine, starting with the next one.")
    print("Undo with: inspect-third-party.py undo %s" % name)
    print("")
    print("NOTE: this copied files only. It did NOT edit ~/.claude/settings.json.")
    print("If the package's README tells you to add a hook or an mcpServers entry, that")
    print("edit is yours to make and yours to reverse -- the undo cannot see it.")
    return 0


def cmd_undo(args):
    name = safe_name(args.name)
    mpath = os.path.join(MANIFEST_DIR, name + ".manifest.json")
    if not os.path.isfile(mpath):
        die("No manifest for %s. It was not installed by this tool, so this tool will not\n"
            "       remove it -- deleting files it did not place is how you lose something else." % name)

    with open(mpath, encoding="utf-8") as fh:
        manifest = json.load(fh)
    dest = manifest["installed_to"]
    root = os.path.realpath(CLAUDE_DIR)

    removed = 0
    for rel in manifest["files"]:
        path = os.path.realpath(os.path.join(CLAUDE_DIR, rel))
        if not path.startswith(root + os.sep):
            continue                       # never outside ~/.claude, whatever the manifest says
        if os.path.isfile(path):
            os.remove(path)
            removed += 1

    # Remove folders only once they are empty. Anything left was not placed by install -
    # your own edits, or files the skill wrote while running - and is not ours to delete.
    for dirpath, _dirs, _files in sorted(os.walk(dest), key=lambda t: -len(t[0])):
        try:
            os.rmdir(dirpath)
        except OSError:
            pass
    leftovers = [os.path.relpath(p, dest) for p, _l in walk(dest)] if os.path.isdir(dest) else []

    os.remove(mpath)
    print("Removed %d files placed by install." % removed)
    if leftovers:
        print("")
        print("KEPT %d file(s) this tool did not place, in %s:" % (len(leftovers), dest))
        for rel in leftovers[:15]:
            print("   %s" % clean(rel))
        print("Delete them yourself if you are sure they are not yours.")
    print("")
    print("Quarantine copy kept at %s -- delete it by hand if you are done with it."
          % os.path.join(QUARANTINE, name))
    print("If you also edited ~/.claude/settings.json for this package, reverse that yourself.")
    return 0


def cmd_list(args):
    ensure_dirs()
    quarantined = sorted(d for d in os.listdir(QUARANTINE)
                         if os.path.isdir(os.path.join(QUARANTINE, d)) and d != "_manifests")
    installed = sorted(f[:-len(".manifest.json")] for f in os.listdir(MANIFEST_DIR)
                       if f.endswith(".manifest.json"))
    print("Quarantined (fetched, not live): %s" % (", ".join(quarantined) or "none"))
    print("Installed by this tool          : %s" % (", ".join(installed) or "none"))
    print("")
    print("Anything in ~/.claude/skills or ~/.claude/plugins NOT listed above was installed")
    print("some other way, and this tool cannot undo it.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Pre-install gate for third-party Claude Code packages.")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("fetch", help="download to quarantine without installing")
    p.add_argument("source")
    p.add_argument("--name")
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("report", help="list where the package executes, connects, and reads secrets")
    p.add_argument("name")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("install", help="promote from quarantine into ~/.claude, recording a manifest")
    p.add_argument("name")
    p.add_argument("--kind", choices=["skill", "plugin"], default="skill")
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("undo", help="remove exactly what install placed")
    p.add_argument("name")
    p.set_defaults(func=cmd_undo)

    p = sub.add_parser("list", help="what is quarantined and what is installed")
    p.set_defaults(func=cmd_list)

    args = ap.parse_args()
    if not getattr(args, "func", None):
        ap.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    # Windows consoles default to cp1252, and this tool prints lines copied verbatim out of
    # somebody else's source.  One checkmark in a third-party shell script once crashed the
    # whole report mid-category -- which means a package could suppress its own findings
    # just by containing a non-ASCII byte.  errors="replace" so an undisplayable character
    # degrades to '?' instead of taking the report with it.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
    sys.exit(main())
