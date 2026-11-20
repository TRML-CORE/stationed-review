"""Stationed Review on Modal.

  POST /job  (X-SR-Signature: sha256=HMAC(SR_JOB_SECRET, body)) -> 202, review runs in its own container.

Deploy: `modal deploy modal_app.py`. Secret `stationed-review` holds SR_JOB_SECRET and either
CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY (optionally ANTHROPIC_BASE_URL/ANTHROPIC_AUTH_TOKEN for Manifest).
"""
import hashlib
import hmac
import json
import os
import subprocess

import modal

try:
    from fastapi import Request
except ImportError:  # deploying from a machine without fastapi
    Request = object

from sr.modal_images import reviewer_image

app = modal.App("stationed-review", image=reviewer_image())
secret = modal.Secret.from_name("stationed-review")


@app.function(secrets=[secret], timeout=1800, cpu=2.0, memory=4096, single_use_containers=True, max_containers=10)
def review(job: dict):
    """Runs as root only to hand the job to the unprivileged `sr` user."""
    path = "/tmp/job.json"
    with open(path, "w") as f:
        json.dump(job, f)
    os.chmod(path, 0o600)
    subprocess.run(["chown", "sr", path], check=True)
    env = dict(os.environ, HOME="/home/sr", SR_SANDBOX="modal", PYTHONPATH="/opt/stationed-review")
    env.pop("SR_JOB_SECRET", None)
    subprocess.run(["runuser", "-u", "sr", "--preserve-environment", "--", "python3", "-m", "sr", "job", path],
                   cwd="/opt/stationed-review", env=env, check=False)


@app.function(secrets=[secret], min_containers=0)
@modal.fastapi_endpoint(method="POST", label="stationed-review-job")
async def job(request: Request):
    from fastapi.responses import JSONResponse
    from sr.run import validate
    body = await request.body()
    want = "sha256=" + hmac.new(os.environ["SR_JOB_SECRET"].encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, request.headers.get("x-sr-signature", "")):
        return JSONResponse({"error": "bad signature"}, status_code=401)
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return JSONResponse({"error": "bad json"}, status_code=400)
    bad = validate(data)
    if bad:
        return JSONResponse({"error": "invalid fields", "fields": bad}, status_code=400)
    call = review.spawn(data)
    return JSONResponse({"queued": call.object_id}, status_code=202)
