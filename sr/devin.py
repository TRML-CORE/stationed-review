"""Devin Review on the same PR: wait for it, then read what it posted so we only add what it missed."""
import time

BOT = "devin-ai-integration"


def is_devin_check(run):
    app = (run.get("app") or {}).get("slug", "")
    return "devin" in app.lower() and run.get("name", "").lower().startswith("devin review")


def wait(gh, sha, appear_s=120, total_s=600, poll_s=20, sleep=time.sleep, clock=time.monotonic):
    """Wait for Devin Review's check on `sha` to complete. Returns its state, or None if it never ran."""
    start = clock()
    while True:
        runs = [r for r in gh.check_runs(sha) if is_devin_check(r)]
        if runs and all(r.get("status") == "completed" for r in runs):
            return "completed"
        elapsed = clock() - start
        if (not runs and elapsed >= appear_s) or elapsed >= total_s:
            return "running" if runs else None
        sleep(poll_s)


def findings(gh, number):
    """Top-level review comments Devin posted on the PR, normalised for overlap checks."""
    out = []
    for c in gh.pr_review_comments(number):
        if not (c.get("user") or {}).get("login", "").startswith(BOT) or c.get("in_reply_to_id"):
            continue
        end = c.get("line") or c.get("original_line")
        if not c.get("path") or not end:
            continue
        start = c.get("start_line") or c.get("original_start_line") or end
        title = next((ln.strip("*# 🔴🟡🟢") for ln in (c.get("body") or "").splitlines() if ln.strip()), "")
        out.append({"file": c["path"], "start_line": int(start), "end_line": int(end), "title": title[:200]})
    return out
