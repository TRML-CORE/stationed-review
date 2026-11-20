"""`sr-run` backend for Modal: run .sr/run.sh in a per-review Modal Sandbox with no secrets."""
import io
import sys
import tarfile
import time
from pathlib import Path

SKIP = {".git", "node_modules", ".venv", "__pycache__"}


def tar_tree(tree, since=None):
    """Tar the scratch tree; with `since`, only files changed after it, so the sandbox keeps setup edits."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in Path(tree).rglob("*"):
            rel = path.relative_to(tree)
            if SKIP & set(rel.parts) or not path.is_file():
                continue
            if since is None or rel.parts[0] == ".sr" or path.lstat().st_mtime >= since:
                tar.add(path, arcname=str(rel))
    return buf.getvalue()


def main(tree):
    import modal
    tree = Path(tree)
    id_file = tree.parent / "sandbox_id"
    stamp = tree.parent / "uploaded_at"
    since = float(stamp.read_text()) if stamp.exists() else None
    if id_file.exists():
        sb = modal.Sandbox.from_id(id_file.read_text().strip())
    else:
        app = modal.App.lookup("stationed-review", create_if_missing=False)
        from .modal_images import sandbox_image
        sb = modal.Sandbox.create("sleep", "3600", app=app, image=sandbox_image(), timeout=3600,
                                  cpu=2.0, memory=4096, workdir="/w")
        id_file.write_text(sb.object_id)
    started = time.time()
    up = sb.exec("bash", "-c", "mkdir -p /w && tar -xz -C /w", timeout=120)
    up.stdin.write(tar_tree(tree, since))
    up.stdin.write_eof()
    up.stdin.drain()
    up.wait()
    stamp.write_text(str(started))
    p = sb.exec("bash", "-c", "cd /w && timeout 600 bash .sr/run.sh 2>&1 | tail -c 8000; "
                "echo \"[exit ${PIPESTATUS[0]}]\"", timeout=700)
    sys.stdout.write(p.stdout.read())


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
