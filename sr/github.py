"""Minimal GitHub REST/GraphQL client (stdlib only)."""
import json
import urllib.error
import urllib.request

API = "https://api.github.com"


class GitHubError(RuntimeError):
    pass


class GitHub:
    def __init__(self, token, repo, api=API):
        self.token, self.repo, self.api = token, repo, api

    def call(self, method, path, body=None):
        url = path if path.startswith("http") else f"{self.api}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "stationed-review"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raise GitHubError(f"{method} {path.split('?')[0]} -> {e.code}: {e.read()[:300]!r}") from None

    def repo_path(self, rest):
        return f"/repos/{self.repo}{rest}"

    def graphql(self, query, **variables):
        out = self.call("POST", "/graphql", {"query": query, "variables": variables})
        if out.get("errors"):
            raise GitHubError(str(out["errors"])[:300])
        return out["data"]

    def pr(self, number):
        return self.call("GET", self.repo_path(f"/pulls/{number}"))

    def issue_comments(self, number):
        out, page = [], 1
        while True:
            batch = self.call("GET", self.repo_path(f"/issues/{number}/comments?per_page=100&page={page}"))
            out += batch
            if len(batch) < 100:
                return out
            page += 1

    def upsert_comment(self, number, marker, body, comment_id=None):
        if comment_id:
            return self.call("PATCH", self.repo_path(f"/issues/comments/{comment_id}"), {"body": body})
        return self.call("POST", self.repo_path(f"/issues/{number}/comments"), {"body": body})

    def check(self, check_id, **fields):
        return self.call("PATCH", self.repo_path(f"/check-runs/{check_id}"), fields)

    def create_check(self, name, head_sha, **fields):
        return self.call("POST", self.repo_path("/check-runs"), dict(name=name, head_sha=head_sha, **fields))

    def review(self, number, sha, body, comments):
        return self.call("POST", self.repo_path(f"/pulls/{number}/reviews"),
                         {"commit_id": sha, "event": "COMMENT", "body": body, "comments": comments})

    def review_comments(self, number, review_id):
        return self.call("GET", self.repo_path(f"/pulls/{number}/reviews/{review_id}/comments?per_page=100"))

    def reply(self, number, comment_id, body):
        return self.call("POST", self.repo_path(f"/pulls/{number}/comments/{comment_id}/replies"), {"body": body})

    def thread_for_comment(self, number, comment_id):
        owner, name = self.repo.split("/")
        data = self.graphql("""query($o:String!,$n:String!,$pr:Int!){repository(owner:$o,name:$n){
          pullRequest(number:$pr){reviewThreads(first:100){nodes{id isResolved comments(first:1){nodes{databaseId}}}}}}}""",
                            o=owner, n=name, pr=number)
        for t in data["repository"]["pullRequest"]["reviewThreads"]["nodes"]:
            ids = [c["databaseId"] for c in t["comments"]["nodes"]]
            if comment_id in ids:
                return t
        return None

    def resolve_thread(self, thread_id):
        self.graphql("mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{id}}}", id=thread_id)
