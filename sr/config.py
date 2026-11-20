"""`.stationed/review.yml`, read from the base branch."""
import copy

DEFAULTS = {
    "mode": "shadow",            # on: inline threads; shadow: summary + check annotations only; off
    "check_policy": "completed",  # completed | no_open_severe | all_resolved
    "effort": "standard",        # quick | standard | deep
    "min_confidence": 0.6,
    "max_findings": 15,
    "paths_ignore": ["**/*.lock", "docs/changes/**", "**/package-lock.json"],
    "model": "opus",
    "verify_model": "",
    "budget": {"max_turns": 40, "verify_max_turns": 60, "timeout_s": 1500},
    "verify": {"enabled": True, "setup": [], "test": ""},
}
THINKING = {"quick": "medium", "standard": "high", "deep": "max"}
LENSES = {"quick": ["correctness"], "standard": ["correctness", "integration"],
          "deep": ["correctness", "integration", "security"]}


def merge(base, extra):
    out = copy.deepcopy(base)
    for k, v in (extra or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge(out[k], v)
        elif k in out:
            out[k] = v
    return out


def load(text):
    if not text:
        return copy.deepcopy(DEFAULTS)
    import yaml
    data = yaml.safe_load(text) or {}
    cfg = merge(DEFAULTS, data if isinstance(data, dict) else {})
    if cfg["mode"] not in ("on", "shadow", "off"):
        cfg["mode"] = "shadow"
    if cfg["effort"] not in LENSES:
        cfg["effort"] = "standard"
    if cfg["check_policy"] not in ("completed", "no_open_severe", "all_resolved"):
        cfg["check_policy"] = "completed"
    return cfg
