"""Output schemas and a dependency-free validator for the fields the poster relies on."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REVIEW_SCHEMA = json.loads((ROOT / "schemas" / "review.schema.json").read_text())
VERIFY_SCHEMA = json.loads((ROOT / "schemas" / "verify.schema.json").read_text())

PAIRS = {
    "bug": {"severe", "non_severe"},
    "flag": {"investigate", "informational"},
    "security": {"critical", "warning"},
}
LIMITS = {"title": 140, "explanation": 2000, "suggested_fix": 2000, "evidence": 1000, "anchor": 500}


def check_finding(f):
    """Return the finding normalised, or None when it can't be posted safely."""
    if not isinstance(f, dict):
        return None
    cat, sev = f.get("category"), f.get("severity")
    if cat not in PAIRS or sev not in PAIRS[cat]:
        return None
    if cat == "security" and not str(f.get("cwe", "")).startswith("CWE-"):
        return None
    if not isinstance(f.get("file"), str) or not f["file"] or f["file"].startswith(("/", "..")):
        return None
    try:
        start = int(f.get("start_line"))
        end = int(f.get("end_line", start))
        conf = float(f.get("confidence"))
    except (TypeError, ValueError):
        return None
    if start < 1 or not 0 <= conf <= 1 or not f.get("title") or not f.get("explanation"):
        return None
    out = dict(f, start_line=start, end_line=max(start, end), confidence=conf)
    for key, cap in LIMITS.items():
        if isinstance(out.get(key), str):
            out[key] = out[key][:cap]
    out.setdefault("introduced_by_pr", True)
    return out


def check_review(obj):
    if not isinstance(obj, dict):
        return {"overview": "", "sections": [], "findings": [], "prior": []}
    findings = [g for g in (check_finding(f) for f in obj.get("findings") or []) if g]
    prior = [p for p in obj.get("prior") or []
             if isinstance(p, dict) and p.get("status") in ("fixed", "still_open", "obsolete")
             and isinstance(p.get("fingerprint"), str)]
    sections = [s for s in obj.get("sections") or [] if isinstance(s, dict) and s.get("title")][:20]
    return {"overview": str(obj.get("overview", ""))[:1200], "sections": sections,
            "findings": findings[:40], "prior": prior}
