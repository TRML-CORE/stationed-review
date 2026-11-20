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


def dump(state, limit=60000):
    state = dict(state, runs=state.get("runs", [])[-MAX_RUNS:])
    while True:
        raw = base64.b64encode(json.dumps(state, separators=(",", ":")).encode()).decode()
        block = f"<!-- {MARK} {raw} -->"
        if len(block) <= limit or not state["runs"]:
            return block
        state["runs"] = state["runs"][1:]
