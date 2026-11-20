"""`sr-run` backend for Modal: run .sr/run.sh in a per-review Modal Sandbox with no secrets."""
import hashlib
import io
import json
import os
import sys
import tarfile
from pathlib import Path

SKIP = {".git", "node_modules", ".venv", "__pycache__"}


def manifest(tree):
    """{path: digest} for every file and symlink in the scratch tree."""
    out = {}
    for path in Path(tree).rglob("*"):
        rel = path.relative_to(tree)
        if SKIP & set(rel.parts) or rel.parts[0] == ".sr":
            continue
        if path.is_symlink():
            out[str(rel)] = "link:" + os.readlink(path)
        elif path.is_file():
            out[str(rel)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def tar_tree(tree, base=None):
    """Tar .sr plus every file that differs from `base` (all files if None), listing deletions in .sr/.deleted."""
    tree, now = Path(tree), manifest(tree)
    changed = [p for p, h in now.items() if base is None or base.get(p) != h]
    deleted = sorted(set(base or ()) - set(now))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel in changed:
            tar.add(tree / rel, arcname=rel, recursive=False)
        for path in (tree / ".sr").rglob("*"):
            if path.is_file() and path.name != ".deleted":
                tar.add(path, arcname=str(path.relative_to(tree)))
        data = "\0".join(deleted).encode()
        info = tarfile.TarInfo(".sr/.deleted")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# The first run unpacks the whole checkout; /base then holds the tree as the setup run (SR_SETUP=1)
# left it, or as uploaded when there is no setup. Every later run starts from a fresh copy of /base,
# so files a repro wrote or changed don't reach the next one, and only the verifier's own edits
# (files that differ locally from the uploaded checkout) are laid on top.
APPLY = "tar -xz -C /w && cd /w && xargs -0 -r rm -rf -- < .sr/.deleted"
FIRST = "rm -rf /w && mkdir -p /w && " + APPLY
RESTORE = "rm -rf /w && cp -a /base /w && " + APPLY
SNAPSHOT = "rm -rf /base && cp -a /w /base"


def main(tree):
    import modal
    tree = Path(tree)
    id_file = tree.parent / "sandbox_id"
    if id_file.exists():
        sb = modal.Sandbox.from_id(id_file.read_text().strip())
    else:
        app = modal.App.lookup("stationed-review", create_if_missing=False)
        from .modal_images import sandbox_image
        sb = modal.Sandbox.create("sleep", "3600", app=app, image=sandbox_image(), timeout=3600,
                                  cpu=2.0, memory=4096, workdir="/w")
        id_file.write_text(sb.object_id)
    base_file = tree.parent / "sandbox_base.json"
    base = json.loads(base_file.read_text()) if base_file.exists() else None
    if base is None:
        base_file.write_text(json.dumps(manifest(tree)))
    setup = os.environ.get("SR_SETUP") == "1"
    up = sb.exec("bash", "-c", FIRST if base is None else RESTORE, timeout=300)
    up.stdin.write(tar_tree(tree, base))
    up.stdin.write_eof()
    up.stdin.drain()
    up.wait()
    if base is None:  # snapshot now too, so a setup run that is cut short still leaves a /base
        sb.exec("bash", "-c", SNAPSHOT, timeout=300).wait()
    p = sb.exec("bash", "-c", "cd /w && timeout 600 bash .sr/run.sh 2>&1 | tail -c 8000; "
                "echo \"[exit ${PIPESTATUS[0]}]\"", timeout=700)
    sys.stdout.write(p.stdout.read())
    p.wait()
    if setup:
        sb.exec("bash", "-c", SNAPSHOT, timeout=300).wait()


def cleanup(root):
    id_file = Path(root) / "sandbox_id"
    if id_file.exists():
        import modal
        try:
            modal.Sandbox.from_id(id_file.read_text().strip()).terminate()
        except Exception:  # noqa: BLE001 - the sandbox times out on its own
            pass


if __name__ == "__main__":
    main(sys.argv[1])
