"""Render and publish one review run: inline review (mode on), sticky summary, check run."""
import json

from . import VERSION, process, state
from .redact import clean

CHECK = "Stationed Review"
ICON = {"severe": "🔴", "non_severe": "🟡", "investigate": "🔍", "informational": "📝",
        "critical": "🟥", "warning": "🟨"}
LABEL = {"bug": "Bug", "flag": "Flag", "security": "Security"}
LEVEL = {"severe": "failure", "critical": "failure", "non_severe": "warning", "warning": "warning",
         "investigate": "warning", "informational": "notice"}


def header(f):
    sev = f["severity"].replace("_", "-")
    extra = f", {f['cwe']}" if f.get("cwe") else ""
    pre = " · Pre-existing" if not f.get("introduced_by_pr", True) else ""
    return f"{ICON[f['severity']]} **{LABEL[f['category']]} ({sev}{extra}){pre}: {clean(f['title'], 140)}**"


def verified_line(f):
    v = f.get("verified")
    if not v:
        return "_Not reproduced: the verifier couldn't confirm or refute this._"
    if v["method"] == "ran":
        out = f"\n```\n{clean(v.get('output', ''), 800)}\n```" if v.get("output") else ""
        return f"✅ Reproduced by running `{clean(v.get('command', ''), 200)}`{out}"
    return f"✅ Confirmed by tracing: {clean(v.get('evidence', ''), 600)}"


def finding_body(f, run_id):
    parts = [header(f), clean(f["explanation"])]
    if f.get("trigger"):
        parts.append(f"**Trigger:** {clean(f['trigger'], 600)}")
    parts.append(verified_line(f))
    if f.get("suggested_fix"):
        parts.append(f"**Fix:** {clean(f['suggested_fix'], 1200)}")
    marker = {"v": 1, "fp": f["fp"], "cat": f["category"], "sev": f["severity"],
              "conf": round(f["confidence"], 2), "run": run_id}
    parts.append(f"<!-- stationed-review {json.dumps(marker)} -->")
    return "\n\n".join(parts)


def counts(findings):
    out = {}
    for f in findings:
        key = "pre_existing" if not f.get("introduced_by_pr", True) else f["severity"]
        out[key] = out.get(key, 0) + 1
    return out


def summary_body(result, st, meta):
    open_f = st["findings"]
    lines = [state.STICKY, "## Stationed Review", clean(result["overview"], 1200) or "_No overview._"]
    if result["sections"]:
        lines.append("<details><summary>Changes by area</summary>\n")
        for s in result["sections"]:
            files = ", ".join(f"`{clean(x, 200)}`" for x in s.get("files", [])[:12])
            lines.append(f"- **{clean(s['title'], 140)}**: {clean(s.get('summary', ''), 400)} {files}")
        lines.append("\n</details>")
    lines.append(f"### Open findings ({len(open_f)})")
    if open_f:
        for f in open_f:
            where = f"`{f['file']}:{f['start_line']}`"
            tag = " ✅ reproduced" if (f.get("verified") or {}).get("method") == "ran" else ""
            lines.append(f"- {ICON[f['severity']]} {clean(f['title'], 140)} ({where}){tag}")
    else:
        lines.append("None.")
    if result["fixed"]:
        lines.append("### Fixed this round")
        lines += [f"- ✅ {clean(f['title'], 140)} (`{f['file']}`)" for f in result["fixed"]]
    if st["mode"] == "shadow" and result["new"]:
        lines.append("### New this round (details)")
        for f in result["new"]:
            lines.append(f"<details><summary>{header(f)} — <code>{clean(f['file'], 200)}:{f['start_line']}</code>"
                         f"</summary>\n\n{finding_body(f, meta['run_id'])}\n\n</details>")
    cost = meta.get("cost_usd")
    lines.append(f"<sub>{meta['engine']} · {meta['model']} · effort {meta['effort']} · "
                 f"{meta['duration_s']}s{f' · ${cost:.2f}' if cost else ''} · "
                 f"{len(result['refuted'])} candidate(s) refuted by the verifier · "
                 f"commit `{meta['head_sha'][:7]}`</sub>")
    body = "\n\n".join(lines)
    return body + "\n" + state.dump(st, limit=65000 - len(body) - 10)


def annotations(findings):
    out = []
    for f in findings[:50]:
        out.append({"path": f["file"], "start_line": f["start_line"], "end_line": f["end_line"],
                    "annotation_level": LEVEL[f["severity"]], "title": clean(f["title"], 255),
                    "message": clean(f"{f['explanation']}\n\nTrigger: {f.get('trigger', '')}", 3500)})
    return out


def publish(gh, pr_number, head_sha, check_id, result, prev_state, sticky_id, cfg, meta):
    """Post the run. Returns the new state."""
    run_id = meta["run_id"]
    mode = cfg["mode"]
    st = {"v": 1, "mode": mode, "last_sha": head_sha, "findings": [], "runs": prev_state.get("runs", [])}
    keep = {p["fp"]: p for p in result["still_open"]}

    if mode == "on":
        for p in result["fixed"]:
            if p.get("comment_id"):
                try:
                    gh.reply(pr_number, p["comment_id"], f"✅ Fixed in `{head_sha[:7]}`.")
                    t = gh.thread_for_comment(pr_number, p["comment_id"])
                    if t and not t["isResolved"]:
                        gh.resolve_thread(t["id"])
                except Exception as e:  # noqa: BLE001 - a failed resolve must not lose the review
                    meta.setdefault("warnings", []).append(f"resolve {p['fp']}: {e}")
        inline = [f for f in result["new"] if f.get("inline")]
        if inline or result["new"]:
            comments = [{"path": f["file"], "line": f["end_line"], "side": "RIGHT",
                         **({"start_line": f["start_line"], "start_side": "RIGHT"}
                            if f["end_line"] > f["start_line"] else {}),
                         "body": finding_body(f, run_id)} for f in inline]
            n = len(result["new"])
            body = f"Stationed Review found {n} new potential issue{'s' if n != 1 else ''}."
            outside = [f for f in result["new"] if not f.get("inline")]
            if outside:
                body += "\n\n" + "\n\n".join(finding_body(f, run_id) for f in outside)
            rv = gh.review(pr_number, head_sha, body, comments)
            by_fp = {}
            for c in gh.review_comments(pr_number, rv["id"]):
                for f in inline:
                    if f'"fp": "{f["fp"]}"' in (c.get("body") or ""):
                        by_fp[f["fp"]] = c["id"]
            for f in result["new"]:
                f["comment_id"] = by_fp.get(f["fp"])

    for f in list(keep.values()) + result["new"]:
        st["findings"].append({k: f.get(k) for k in ("fp", "category", "severity", "file", "start_line",
                                                     "end_line", "title", "anchor", "comment_id",
                                                     "introduced_by_pr", "verified")})
    st["runs"].append({"run": run_id, "sha": head_sha, "new": len(result["new"]), "fixed": len(result["fixed"]),
                       "open": len(st["findings"]), "refuted": len(result["refuted"]),
                       "cost_usd": meta.get("cost_usd"), "duration_s": meta["duration_s"]})
    body = summary_body(result, st, meta)
    gh.upsert_comment(pr_number, state.STICKY, body, sticky_id)

    c = counts(st["findings"])
    concl = process.conclusion(cfg["check_policy"], st["findings"])
    n = len(result["new"])
    title = (f"{n} new potential issue{'s' if n != 1 else ''}" if n else "No new issues") + \
        f" · {len(st['findings'])} open · {len(result['fixed'])} fixed"
    summary = (f"{title}\n\n<!-- stationed-review-severity {json.dumps(c)} -->\n\n"
               f"Engine {meta['engine']} v{VERSION}, mode `{mode}`, policy `{cfg['check_policy']}`.")
    gh.check(check_id, status="completed", conclusion=concl,
             output={"title": title, "summary": summary, "annotations": annotations(result["new"])})
    return st
