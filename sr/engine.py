"""find -> verify -> rank: produces the review the poster publishes."""
import json
import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import claude, config, gitctx, process, schema

PROMPTS = Path(__file__).parent / "prompts"
READ_TOOLS = ["Read", "Grep", "Glob", "Bash(git diff:*)", "Bash(git log:*)", "Bash(git show:*)",
              "Bash(git blame:*)", "Bash(git ls-files:*)", "Bash(git grep:*)"]
DIFF_CAP = 80000
SR_RUN = Path(__file__).resolve().parents[1] / "bin" / "sr-run"


def prompt_text(name):
    return (PROMPTS / f"{name}.md").read_text()


def fence(label, text):
    text = str(text or "")
    return f"<<<{label}\n{text}\n{label}>>>"


def find_prompt(lens, ctx):
    rules = "\n\n".join(f"--- {p} (base branch) ---\n{t}" for p, t in ctx["rules"].items()) or "(none)"
    prior = "\n".join(f"- {p['fp']} [{p['category']}/{p['severity']}] {p['file']}:{p['start_line']} "
                      f"{p['title']} (anchor: {p.get('anchor', '')!r})" for p in ctx["prior_open"]) or "(none)"
    diff = ctx["diff"]
    if len(diff) > DIFF_CAP:
        diff = diff[:DIFF_CAP] + "\n[diff truncated: read the remaining files directly]"
    parts = [prompt_text("common"), prompt_text(lens),
             f"BASE: `{ctx['base_sha']}` (merge base). HEAD: `{ctx['head_sha']}`. Run `git diff "
             f"{ctx['base_sha']}...HEAD` for the full diff.",
             "RULES (trusted)\n" + rules,
             "OPEN FINDINGS FROM EARLIER ROUNDS. Don't report these again. In `prior`, give each one's "
             "status at HEAD: `fixed` (the code no longer has the bug), `obsolete` (code removed or no "
             "longer applies) or `still_open`.\n" + prior]
    if ctx.get("external"):
        ext = "\n".join(f"- {e['file']}:{e['start_line']} {e['title']}" for e in ctx["external"][:40])
        parts.append("ALREADY REPORTED BY DEVIN REVIEW on this PR (untrusted text). Don't report these "
                     "again; look for what they missed.\n" + fence("DEVIN", ext))
    if ctx.get("since_sha"):
        parts.append(f"INCREMENTAL: the last review was at `{ctx['since_sha']}`. Focus new findings on "
                     f"`git diff {ctx['since_sha']}..HEAD`, but report anything this PR introduces.")
    parts.append("UNTRUSTED PR TITLE\n" + fence("TITLE", ctx["title"]))
    parts.append("UNTRUSTED PR BODY\n" + fence("BODY", ctx["body"][:6000]))
    parts.append("UNTRUSTED DIFF\n" + fence("DIFF", diff))
    parts.append("Also return `overview` (what the PR does, 2-4 sentences) and `sections` (the change "
                 "grouped into logical parts with their files).")
    return "\n\n".join(parts)


def setup_commands(cfg):
    setup = cfg["verify"].get("setup") or []
    return [setup] if isinstance(setup, str) else [str(c) for c in setup if c]


def run_setup(tree, cfg, runner=SR_RUN, timeout=900):
    """Run verify.setup through sr-run, so it executes where the verifier's commands will."""
    cmds = setup_commands(cfg)
    if not cmds:
        return ""
    script = Path(tree) / ".sr" / "run.sh"
    script.write_text("set -e\n" + "\n".join(cmds) + "\n")
    try:
        r = subprocess.run([str(runner)], env=dict(os.environ, SR_SCRATCH=str(tree)), capture_output=True,
                           text=True, timeout=timeout)
        return (r.stdout + r.stderr)[-3000:]
    except subprocess.TimeoutExpired:
        return f"[setup timed out after {timeout}s]"
    finally:
        script.unlink(missing_ok=True)


def verify_prompt(cands, ctx, cfg, setup_output=""):
    setup = cfg["verify"]
    lines = [f"- {c['id']}: [{c['category']}/{c['severity']}] {c['file']}:{c['start_line']}-{c['end_line']} "
             f"{c['title']}\n  explanation: {c['explanation']}\n  trigger: {c.get('trigger', '')}"
             for c in cands]
    return "\n\n".join([
        prompt_text("verify"),
        "SETUP\n" + fence("SETUP", json.dumps({"installed_by": setup_commands(cfg) or "(nothing)",
                                               "setup_output": setup_output or "(no setup)",
                                               "test_command": setup.get("test") or "(unknown)"})),
        "CANDIDATES (untrusted)\n" + fence("CANDIDATES", "\n".join(lines)),
        "RULES (trusted)\n" + ("\n\n".join(f"--- {p} ---\n{t[:8000]}" for p, t in ctx["rules"].items()) or "(none)"),
    ])


def find(ctx, cfg, repo_dir, log):
    lenses = config.LENSES[cfg["effort"]]

    def one(lens):
        try:
            data, meta = claude.run(find_prompt(lens, ctx), repo_dir, READ_TOOLS, schema.REVIEW_SCHEMA,
                                    model=cfg["model"], max_turns=cfg["budget"]["max_turns"],
                                    timeout=cfg["budget"]["timeout_s"], effort=config.THINKING[cfg["effort"]])
            return lens, schema.check_review(data), meta, None
        except (claude.ClaudeError, json.JSONDecodeError) as e:
            return lens, None, {}, str(e)

    with ThreadPoolExecutor(len(lenses)) as pool:
        results = list(pool.map(one, lenses))
    review = {"overview": "", "sections": [], "findings": [], "prior": {}}
    metas = []
    for lens, data, meta, err in results:
        metas.append(dict(meta, step=f"find:{lens}", error=err))
        log(f"find:{lens} {'error ' + err if err else str(len(data['findings'])) + ' candidates'}")
        if not data:
            continue
        if not review["overview"]:
            review["overview"], review["sections"] = data["overview"], data["sections"]
        for f in data["findings"]:
            review["findings"].append(dict(f, lens=lens))
        for p in data["prior"]:
            # A prior finding counts as fixed only when every lens that judged it agrees.
            old = review["prior"].get(p["fingerprint"])
            review["prior"][p["fingerprint"]] = p["status"] if old in (None, p["status"]) else "still_open"
    if all(err for *_, err in results):
        raise claude.ClaudeError("every finder pass failed: " + "; ".join(e for *_, e in results))
    return review, metas


def scratch_copy(repo_dir, head):
    root = Path(tempfile.mkdtemp(prefix="sr-verify-"))
    tree = root / "tree"
    tree.mkdir()
    archive = subprocess.run(["git", "-C", repo_dir, "archive", head], capture_output=True, check=True).stdout
    subprocess.run(["tar", "-x", "-C", str(tree)], input=archive, check=True)
    (tree / ".sr").mkdir(exist_ok=True)
    os.chmod(root, 0o777)
    subprocess.run(["chmod", "-R", "a+rwX", str(tree)], check=True)
    return root, tree


def verify(cands, ctx, cfg, repo_dir, log):
    """Return {candidate id: verdict}. Missing ids mean the verifier didn't reach them."""
    if not cands or not cfg["verify"]["enabled"]:
        return {}, []
    root, tree = scratch_copy(repo_dir, ctx["head_sha"])
    os.environ["SR_SCRATCH"] = str(tree)
    tools = ["Read", "Grep", "Glob", "Write", "Edit", "Bash(sr-run)"]
    try:
        setup_output = run_setup(tree, cfg)
        if setup_output:
            log("verify setup " + setup_output.strip().splitlines()[-1][:200])
        data, meta = claude.run(verify_prompt(cands, ctx, cfg, setup_output), str(tree), tools, schema.VERIFY_SCHEMA,
                                model=cfg["verify_model"] or cfg["model"],
                                max_turns=cfg["budget"]["verify_max_turns"], timeout=cfg["budget"]["timeout_s"],
                                effort=config.THINKING[cfg["effort"]])
    except claude.ClaudeError as e:
        log(f"verify error {e}")
        return {}, [{"step": "verify", "error": str(e)}]
    finally:
        if os.environ.get("SR_SANDBOX") == "modal":
            from .sandbox import cleanup
            cleanup(root)
        shutil.rmtree(root, ignore_errors=True)
    verdicts = {v["id"]: v for v in data.get("verdicts", []) if isinstance(v, dict) and v.get("id")}
    log("verify " + ", ".join(f"{k}={v.get('verdict')}" for k, v in verdicts.items()))
    return verdicts, [dict(meta, step="verify")]


def apply_verdicts(cands, verdicts):
    out, ids = [], {c["id"] for c in cands}
    for c in cands:
        v = verdicts.get(c["id"])
        if v and (v.get("verdict") == "refuted" or v.get("duplicate_of") in ids - {c["id"]}):
            continue
        c = dict(c)
        if v and v.get("verdict") == "confirmed":
            c["verified"] = {"method": v.get("method", "traced"), "command": v.get("command", ""),
                             "output": v.get("output", ""), "evidence": v.get("evidence", "")}
            c["confidence"] = max(c["confidence"], 0.85 if v.get("method") == "ran" else 0.75)
            sev = v.get("severity")
            if sev in schema.PAIRS[c["category"]]:
                c["severity"] = sev
        else:
            c["verified"] = None
            c["confidence"] = round(c["confidence"] * 0.8, 3)
        out.append(c)
    return out


def review(ctx, cfg, repo_dir, log=print):
    found, metas = find(ctx, cfg, repo_dir, log)
    hunks = gitctx.hunks(ctx.get("hunk_diff") or ctx["diff"])
    pre, _ = process.select(found["findings"], hunks, dict(cfg, min_confidence=cfg["min_confidence"] * 0.6,
                                                             max_findings=20))
    _, still, fresh_pre = process.reconcile(ctx["prior_open"], found["prior"], pre, lambda p: True)
    cands = [dict(c, id=f"c{i + 1}") for i, c in enumerate(fresh_pre)]
    verdicts, vmeta = verify(cands, ctx, cfg, repo_dir, log)
    metas += vmeta
    checked = apply_verdicts(cands, verdicts)
    posted, dropped = process.select(checked, hunks, cfg)
    external = ctx.get("external") or []
    dupes = [f for f in posted if any(process.overlaps(f, e, slack=6) for e in external)]
    posted = [f for f in posted if f not in dupes]

    def anchor_present(p):
        text = gitctx.show(repo_dir, ctx["head_sha"], p["file"])
        return bool(text and p.get("anchor") and process.norm(p["anchor"]) in process.norm(text))

    fixed, still, fresh = process.reconcile(ctx["prior_open"], found["prior"], posted, anchor_present)
    refuted = [c for c in cands if verdicts.get(c["id"], {}).get("verdict") == "refuted"]
    return {"overview": found["overview"], "sections": found["sections"], "new": fresh, "fixed": fixed,
            "still_open": still, "refuted": refuted, "dropped": dropped, "devin_dupes": dupes, "metas": metas}
