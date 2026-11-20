"""CLI.

  python -m sr job job.json          run one bridge job (posts to GitHub)
  python -m sr replay REPO_DIR --base REF --head SHA [--out out.json] [--effort deep]
                                     review a local checkout without posting (benchmarks)
"""
import argparse
import json
import sys

from . import config, engine, gitctx
from .run import build_context, run_job, validate


def main(argv=None):
    p = argparse.ArgumentParser(prog="sr")
    sub = p.add_subparsers(dest="cmd", required=True)
    j = sub.add_parser("job")
    j.add_argument("file")
    r = sub.add_parser("replay")
    r.add_argument("repo_dir")
    r.add_argument("--base", required=True, help="base branch ref, e.g. refs/remotes/origin/main")
    r.add_argument("--head", required=True)
    r.add_argument("--title", default="")
    r.add_argument("--body-file")
    r.add_argument("--prior", help="JSON file: earlier findings in state format")
    r.add_argument("--effort")
    r.add_argument("--model")
    r.add_argument("--no-verify", action="store_true")
    r.add_argument("--out")
    a = p.parse_args(argv)
    if a.cmd == "job":
        job = json.load(open(a.file))
        bad = validate(job)
        if bad:
            sys.exit(f"invalid job fields: {', '.join(bad)}")
        print(run_job(job))
        return
    cfg = config.load(gitctx.show(a.repo_dir, a.base, ".stationed/review.yml"))
    if a.effort:
        cfg["effort"] = a.effort
        cfg["budget"]["max_turns"], cfg["budget"]["verify_max_turns"] = config.TURNS[a.effort]
    if a.model:
        cfg["model"] = a.model
    if a.no_verify:
        cfg["verify"]["enabled"] = False
    prior = {"findings": json.load(open(a.prior))} if a.prior else {}
    body = open(a.body_file).read() if a.body_file else ""
    base_name = a.base.removeprefix("refs/remotes/origin/")
    ctx = build_context(a.repo_dir, base_name, a.head, {"title": a.title, "body": body}, prior)
    result = engine.review(ctx, cfg, a.repo_dir, log=lambda m: print(m, file=sys.stderr))
    text = json.dumps(result, indent=2, default=str)
    if a.out:
        open(a.out, "w").write(text)
    else:
        print(text)


if __name__ == "__main__":
    main()
