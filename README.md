# stationed-review

Org-wide PR reviewer for TRML-CORE: **find → verify → rank → post**.

- **Trigger:** the hosted TRML Bridge App sends a signed job (`X-SR-Signature`, HMAC-SHA256) with a
  one-hour token scoped to one repo to the Modal endpoint in `modal_app.py`.
- **Find:** 1–3 read-only Claude Code passes (correctness, integration, security) over the merge-base
  diff, with `REVIEW.md` / `AGENTS.md` / `CLAUDE.md` / `.stationed/review.yml` read from the **base** branch.
- **Verify:** a second pass writes repros under `.sr/` and runs them with `sr-run` in a Modal Sandbox
  that holds no secrets. Refuted candidates are dropped.
- **Rank and post:** deterministic filtering, placement on changed lines, fingerprints, round
  tracking in a hidden state block, a sticky summary and a `Stationed Review` check. Findings Devin
  Review already posted on the PR are skipped.

## Repo config (`.stationed/review.yml`, optional)

```yaml
mode: shadow            # shadow (summary + check) | on (inline threads) | off
effort: standard        # quick | standard | deep
check_policy: completed # completed (never blocks) | no_open_severe
skip_devin_duplicates: true
verify: { setup: ["pip install -r requirements.txt"], test: "./scripts/test.sh" }
```

## Run

```sh
python3 -m unittest discover -s tests                     # unit tests
python3 -m sr replay REPO --base refs/remotes/origin/main --head SHA --out out.json   # offline review
modal deploy modal_app.py                                 # Modal secret `stationed-review`:
                                                          #   SR_JOB_SECRET + CLAUDE_CODE_OAUTH_TOKEN or CLAUDE_OAUTH_TOKEN_1..n
```
