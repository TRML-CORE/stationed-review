"""Post-processing: filter, place in the diff, fingerprint, dedupe, rank, track rounds."""
import fnmatch
import hashlib
import re

SEV_RANK = {"critical": 0, "severe": 1, "warning": 2, "non_severe": 3, "investigate": 4, "informational": 5}
BLOCKING = {"severe", "critical"}


def norm(text, digits=False):
    text = re.sub(r"\s+", " ", str(text or "").strip().lower())
    return re.sub(r"\d+", "", text) if digits else text


def fingerprint(f):
    key = "|".join([f["category"], f["file"], norm(f.get("anchor")), norm(f["title"], digits=True)])
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def ignored(path, patterns):
    return any(fnmatch.fnmatch(path, p) for p in patterns)


def place(f, file_hunks, slack=8):
    """Move a finding's range into one diff hunk; None if it isn't near any changed lines."""
    best = None
    for lo, hi in file_hunks or []:
        if f["start_line"] <= hi and f["end_line"] >= lo:
            dist = 0
        else:
            dist = min(abs(f["start_line"] - hi), abs(f["end_line"] - lo))
        if dist <= slack and (best is None or dist < best[0]):
            best = (dist, lo, hi)
    if not best:
        return None
    _, lo, hi = best
    start = min(max(f["start_line"], lo), hi)
    end = min(max(f["end_line"], start), hi)
    return start, end


def overlaps(a, b, slack=3):
    return (a["file"] == b["file"] and a["start_line"] - slack <= b.get("end_line", b["start_line"])
            and b["start_line"] - slack <= a["end_line"])


def select(findings, hunks_by_file, cfg):
    """Deterministic filter + rank. Returns (posted, dropped_reasons)."""
    kept, dropped, seen = [], [], set()
    for f in findings:
        if f["confidence"] < cfg["min_confidence"]:
            dropped.append((f, "low confidence"))
            continue
        if ignored(f["file"], cfg["paths_ignore"]):
            dropped.append((f, "ignored path"))
            continue
        placed = place(f, hunks_by_file.get(f["file"]))
        # Security and blocking findings outside the new-side diff (e.g. a deleted module's callers)
        # stay in the summary instead of being dropped.
        if placed is None and f["category"] != "security" and f["severity"] not in BLOCKING:
            dropped.append((f, "outside the diff"))
            continue
        f = dict(f, inline=placed is not None, orig_lines=(f["start_line"], f["end_line"]))
        if placed:
            f["start_line"], f["end_line"] = placed
        f["fp"] = fingerprint(f)
        if f["fp"] in seen or any(overlaps(f, k) and f["category"] == k["category"] and
                                  norm(f["title"]) == norm(k["title"]) for k in kept):
            dropped.append((f, "duplicate"))
            continue
        seen.add(f["fp"])
        kept.append(f)
    kept.sort(key=lambda f: (not f.get("introduced_by_pr", True), SEV_RANK[f["severity"]], -f["confidence"]))
    for f in kept[cfg["max_findings"]:]:
        dropped.append((f, "over max_findings"))
    return kept[:cfg["max_findings"]], dropped


def reconcile(prior_open, model_prior, new, anchor_present):
    """Split prior open findings into fixed / still open, and drop new findings that repeat them.

    prior_open: list of state findings; model_prior: {fp: status}; anchor_present(f) -> bool.
    A finding is fixed when the model says fixed/obsolete and its anchor is gone or moved,
    or when the model says obsolete. Model 'fixed' with the anchor untouched stays open, except for
    summary-only findings: their anchor is unchanged code outside the diff by definition.
    """
    def repeats(f, p):
        return f["fp"] == p["fp"] or (overlaps(f, p) and f["category"] == p["category"])

    fixed, still = [], []
    for p in prior_open:
        status = model_prior.get(p["fp"], "still_open")
        closed = status == "obsolete" or (status == "fixed" and (p.get("inline") is False or not anchor_present(p)))
        # A finding found again this round is not fixed, whatever the model said about it.
        if closed and not any(repeats(f, p) for f in new):
            fixed.append(p)
        else:
            still.append(p)
    fresh = [f for f in new if not any(repeats(f, p) for p in still)]
    return fixed, still, fresh


def conclusion(policy, open_findings, open_threads=0):
    if policy == "no_open_severe" and any(f["severity"] in BLOCKING for f in open_findings
                                          if f.get("introduced_by_pr", True)):
        return "failure"
    return "success" if not open_findings else "neutral"
