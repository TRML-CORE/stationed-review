"""Deterministic context: diff, changed lines, rules from the base branch."""
import re
import subprocess

RULE_FILES = ["REVIEW.md", "AGENTS.md", "CLAUDE.md", ".stationed/review.yml"]
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def git(repo, *args, check=True):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(f"git {' '.join(args[:2])} failed: {r.stderr.strip()[:300]}")
    return r.stdout


def merge_base(repo, base, head):
    return git(repo, "merge-base", base, head).strip()


def diff(repo, base, head, unified=5):
    return git(repo, "diff", "-M", "-C", f"--unified={unified}", "--no-color", f"{base}...{head}")


def changed_files(repo, base, head):
    out = git(repo, "diff", "--name-status", "-M", f"{base}...{head}")
    files = []
    for line in out.splitlines():
        parts = line.split("\t")
        if parts and parts[0][:1] != "D":
            files.append(parts[-1])
    return files


def hunks(diff_text):
    """{path: [(start, end), ...]} of new-side line ranges GitHub accepts comments on."""
    out, path = {}, None
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            path = None if line[4:] == "/dev/null" else line[4:].removeprefix("b/")
            continue
        m = HUNK.match(line)
        if m and path:
            start, count = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
            if count:
                out.setdefault(path, []).append((start, start + count - 1))
    return out


def rules(repo, base_ref):
    """Rule files read from the base branch, so a PR can't rewrite its own review rules."""
    found = {}
    for path in RULE_FILES:
        r = subprocess.run(["git", "-C", repo, "show", f"{base_ref}:{path}"], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            found[path] = r.stdout[:20000]
    return found


def show(repo, ref, path):
    r = subprocess.run(["git", "-C", repo, "show", f"{ref}:{path}"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def is_ancestor(repo, a, b):
    return subprocess.run(["git", "-C", repo, "merge-base", "--is-ancestor", a, b]).returncode == 0
