"""Incremental state lives in a hidden block in the sticky summary comment."""
import base64
import json
import re

MARK = "stationed-review-state"
BLOCK = re.compile(r"<!-- " + MARK + r" ([A-Za-z0-9+/=]+) -->")
STICKY = "<!-- stationed-review-summary -->"
MAX_RUNS = 20


def empty():
    return {"v": 1, "last_sha": None, "findings": [], "runs": []}


def parse(body):
    m = BLOCK.search(body or "")
    if not m:
        return empty()
    try:
        data = json.loads(base64.b64decode(m.group(1)))
        return data if isinstance(data, dict) and data.get("v") == 1 else empty()
    except (ValueError, json.JSONDecodeError):
        return empty()


def _block(state):
    raw = base64.b64encode(json.dumps(state, separators=(",", ":")).encode()).decode()
    return f"<!-- {MARK} {raw} -->"


def _compact(f):
    v = f.get("verified")
    return dict(f, title=str(f.get("title") or "")[:140], anchor=str(f.get("anchor") or "")[:200],
                verified={"method": v.get("method")} if isinstance(v, dict) else v)


def dump(state, limit=60000):
    """Fit the block in `limit` chars: drop old runs, then verifier output, then the last findings."""
    state = dict(state, runs=state.get("runs", [])[-MAX_RUNS:])
    while len(_block(state)) > limit and state["runs"]:
        state["runs"] = state["runs"][1:]
    if len(_block(state)) > limit:
        state["findings"] = [_compact(f) for f in state.get("findings", [])]
    while len(_block(state)) > limit and state.get("findings"):
        state["findings"] = state["findings"][:-1]
    return _block(state)
