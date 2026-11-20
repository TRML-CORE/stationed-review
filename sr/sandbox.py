"""`sr-run` backend for Modal: run .sr/run.sh in a per-review Modal Sandbox with no secrets."""
import io
import sys
import tarfile
from pathlib import Path

SKIP = {".git", "node_modules", ".venv", "__pycache__"}


def tar_tree(tree):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in Path(tree).rglob("*"):
            if not SKIP & set(path.relative_to(tree).parts) and path.is_file():
                tar.add(path, arcname=str(path.relative_to(tree)))
    return buf.getvalue()


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
    with sb.open("/tmp/tree.tgz", "wb") as f:
        f.write(tar_tree(tree))
    p = sb.exec("bash", "-c", "mkdir -p /w && tar -xzf /tmp/tree.tgz -C /w && cd /w && "
                "timeout 600 bash .sr/run.sh 2>&1 | tail -c 8000; echo \"[exit ${PIPESTATUS[0]}]\"", timeout=700)
    sys.stdout.write(p.stdout.read())


if __name__ == "__main__":
    main(sys.argv[1])
