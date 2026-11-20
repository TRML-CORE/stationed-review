"""One review job: fetch, build context, review, publish. Used by the Modal app and the CLI."""
import os
import re
import subprocess
import tempfile
import time
import traceback
import uuid

from . import VERSION, claude, config, devin, engine, gitctx, post, process, state
from .github import GitHub
from .redact import redact

# The bridge's installation token lasts 1 hour; finish reviewing early enough to still post with it.
JOB_BUDGET_S = 3000
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA = re.compile(r"^[0-9a-f]{40}$")
REF = re.compile(r"^[A-Za-z0-9._/-]+$")


def validate(job):
    errors = []
    if not REPO.match(str(job.get("repo", ""))):
        errors.append("repo")
    if not SHA.match(str(job.get("head_sha", ""))):
        errors.append("head_sha")
    if not REF.match(str(job.get("base_ref", ""))) or ".." in str(job.get("base_ref", "")):
        errors.append("base_ref")
    for key in ("number", "check_run_id"):
        if not isinstance(job.get(key), int) or job[key] < 1:
            errors.append(key)
    if not isinstance(job.get("token"), str) or len(job["token"]) < 20:
        errors.append("token")
    return errors


def fetch(job, workdir):
    """Clone base + PR head; the token goes through env-only git config, never argv or disk."""
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_CONFIG_COUNT="1",
               GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
               GIT_CONFIG_VALUE_0="AUTHORIZATION: basic " + _basic(job["token"]))
    url = f"https://github.com/{job['repo']}.git"
    subprocess.run(["git", "init", "-q", workdir], check=True)
    r = subprocess.run(["git", "-C", workdir, "fetch", "-q", "--no-tags", url,
                        f"+refs/heads/{job['base_ref']}:refs/remotes/origin/{job['base_ref']}",
                        f"+refs/pull/{job['number']}/head:refs/sr/head"], env=env, capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError("git fetch failed: " + redact(r.stderr)[-300:])
    got = gitctx.git(workdir, "rev-parse", "refs/sr/head").strip()
    if got != job["head_sha"]:
        raise RuntimeError(f"PR head moved to {got[:7]}; a newer job will review it")
    gitctx.git(workdir, "checkout", "-q", "--detach", job["head_sha"])


def _basic(token):
    import base64
    return base64.b64encode(f"x-access-token:{token}".encode()).decode()


def load_state(gh, number):
    for c in gh.issue_comments(number):
        if state.STICKY in (c.get("body") or "") and (c.get("user") or {}).get("type") == "Bot":
            return state.parse(c["body"]), c["id"]
    return state.empty(), None


def build_context(repo_dir, base_ref, head_sha, pr, prior):
    base_tip = f"refs/remotes/origin/{base_ref}"
    base_sha = gitctx.merge_base(repo_dir, base_tip, head_sha)
    since = prior.get("last_sha")
    if since and (since == head_sha or not gitctx.is_ancestor(repo_dir, since, head_sha)):
        since = None if since != head_sha else since
    return {"base_sha": base_sha, "head_sha": head_sha, "base_tip": base_tip,
            "diff": gitctx.diff(repo_dir, base_sha, head_sha),
            # GitHub only accepts comments inside its own 3-line-context hunks.
            "hunk_diff": gitctx.diff(repo_dir, base_sha, head_sha, unified=3),
            "files": gitctx.changed_files(repo_dir, base_sha, head_sha),
            "rules": gitctx.rules(repo_dir, base_tip), "title": pr.get("title") or "",
            "body": pr.get("body") or "", "prior_open": prior.get("findings", []), "since_sha": since}


def run_job(job, log=print, gh=None):
    started = time.time()
    gh = gh or GitHub(job["token"], job["repo"])
    check_id = job["check_run_id"]
    os.environ["SR_RUN_ID"] = run_id = uuid.uuid4().hex[:12]
    try:
        gh.check(check_id, status="in_progress", output={"title": "Reviewing", "summary": "Finding and verifying issues."})
        pr = gh.pr(job["number"])
        if pr.get("head", {}).get("sha") != job["head_sha"]:
            gh.check(check_id, status="completed", conclusion="skipped",
                     output={"title": "Superseded", "summary": "A newer commit will be reviewed."})
            return "superseded"
        with tempfile.TemporaryDirectory(prefix="sr-") as workdir:
            fetch(job, workdir)
            cfg = config.load(gitctx.show(workdir, f"refs/remotes/origin/{job['base_ref']}", ".stationed/review.yml"))
            prior, sticky_id = load_state(gh, job["number"])
            if cfg["mode"] == "off":
                gh.check(check_id, status="completed", conclusion="skipped",
                         output={"title": "Off for this repo", "summary": "`.stationed/review.yml` sets `mode: off`."})
                return "off"
            ctx = build_context(workdir, job["base_ref"], job["head_sha"], pr, prior)
            if not any(not process.ignored(f, cfg["paths_ignore"]) for f in ctx["files"]):
                gh.check(check_id, status="completed", conclusion="success",
                         output={"title": "Nothing to review", "summary": "Only ignored paths changed."})
                return "ignored"
            if ctx["since_sha"] == job["head_sha"]:
                gh.check(check_id, status="completed",
                         conclusion=process.conclusion(cfg["check_policy"], prior.get("findings", [])),
                         output={"title": "Already reviewed", "summary": f"`{job['head_sha'][:7]}` was reviewed."})
                return "duplicate"
            if cfg["skip_devin_duplicates"]:
                log(f"devin review: {devin.wait(gh, job['head_sha'])}")
                ctx["external"] = devin.findings(gh, job["number"])
            ctx["deadline"] = started + JOB_BUDGET_S
            result = engine.review(ctx, cfg, workdir, log)
            meta = {"run_id": run_id, "engine": "stationed-review", "model": cfg["model"], "effort": cfg["effort"],
                    "head_sha": job["head_sha"], "duration_s": int(time.time() - started),
                    "cost_usd": sum(m.get("cost_usd") or 0 for m in result["metas"]) or None}
            if gh.pr(job["number"]).get("head", {}).get("sha") != job["head_sha"]:
                gh.check(check_id, status="completed", conclusion="skipped",
                         output={"title": "Superseded", "summary": "A newer commit will be reviewed."})
                return "superseded"
            post.publish(gh, job["number"], job["head_sha"], check_id, result, prior, sticky_id, cfg, meta)
            log(f"posted: {len(result['new'])} new, {len(result['fixed'])} fixed, {len(result['refuted'])} refuted")
            return "posted"
    except Exception as e:  # noqa: BLE001 - always close the check
        log("failed: " + redact("".join(traceback.format_exception_only(type(e), e))).strip())
        try:
            gh.check(check_id, status="completed", conclusion="neutral",
                     output={"title": "Review failed", "summary": redact(str(e))[:500] +
                             "\n\nRe-run with `/bridge review` once fixed. This check never blocks merging."})
        except Exception:  # noqa: BLE001
            pass
        return "failed"
