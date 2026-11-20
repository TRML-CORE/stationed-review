"""Run Claude Code headless and return its structured output."""
import json
import os
import re
import subprocess
import time

PASS_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY",
            "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_CUSTOM_HEADERS", "SR_SANDBOX",
            "SR_SANDBOX_USER", "SR_SCRATCH", "SR_SANDBOX_IMAGE", "SR_RUN_ID", "SR_HOME", "MODAL_TOKEN_ID",
            "MODAL_TOKEN_SECRET", "MODAL_ENVIRONMENT")
DENY = ["WebFetch", "WebSearch", "Task", "NotebookEdit", "TodoWrite"]
FENCE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)


class ClaudeError(RuntimeError):
    pass


def child_env(environ=None):
    """The agent's environment. On Modal, sr-run needs the container's MODAL_* settings to start a Sandbox."""
    environ = os.environ if environ is None else environ
    env = {k: environ[k] for k in PASS_ENV if k in environ}
    if environ.get("SR_SANDBOX") == "modal":
        env.update({k: v for k, v in environ.items() if k.startswith("MODAL_")})
    return env


def run(prompt, cwd, tools, schema, model="opus", max_turns=40, timeout=1500, effort=None, binary="claude"):
    env = child_env()
    cmd = [binary, "-p", "--setting-sources", "user", "--output-format", "json", "--model", model, "--max-turns", str(max_turns),
           "--json-schema", json.dumps(schema), "--allowedTools", ",".join(tools),
           "--disallowedTools", ",".join(DENY + ([] if any(t.startswith("Bash") for t in tools) else ["Bash"]))]
    if not any(t in tools for t in ("Write", "Edit")):
        cmd[-1] += ",Write,Edit"
    if effort:
        cmd += ["--effort", effort]
    started = time.time()
    try:
        r = subprocess.run(cmd, input=prompt, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise ClaudeError(f"timed out after {timeout}s") from e
    meta = {"duration_ms": int((time.time() - started) * 1000)}
    try:
        out = json.loads(r.stdout)
    except json.JSONDecodeError:
        raise ClaudeError(f"exit {r.returncode}: {(r.stderr or r.stdout).strip()[-400:]}")
    meta.update(cost_usd=out.get("total_cost_usd"), turns=out.get("num_turns"), model=model)
    if out.get("is_error"):
        raise ClaudeError(str(out.get("result") or out.get("subtype"))[:400])
    data = out.get("structured_output")
    if data is None:
        m = FENCE.search(str(out.get("result", "")))
        data = json.loads(m.group(1)) if m else None
    if not isinstance(data, dict):
        raise ClaudeError("no structured output")
    return data, meta
