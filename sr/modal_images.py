"""Container images: the reviewer (has secrets) and the verify sandbox (has none)."""
import modal

CLAUDE_CODE = "2.1.328"


def reviewer_image():
    return (modal.Image.debian_slim(python_version="3.12")
            .apt_install("git", "curl", "ca-certificates")
            .run_commands("curl -fsSL https://deb.nodesource.com/setup_22.x | bash -", "apt-get install -y nodejs",
                          f"npm install -g @anthropic-ai/claude-code@{CLAUDE_CODE}",
                          "useradd -m -s /bin/bash sr")
            .pip_install("pyyaml==6.0.2", "modal==1.6.4", "fastapi[standard]==0.115.12")
            .add_local_dir(".", "/opt/stationed-review", copy=True, ignore=[".git", "tests", "**/__pycache__"])
            .run_commands("install -m 755 /opt/stationed-review/bin/sr-run /usr/local/bin/sr-run"))


def sandbox_image():
    """Generic toolchain for running a PR's tests; repos install their own deps via verify.setup."""
    return (modal.Image.debian_slim(python_version="3.12")
            .apt_install("git", "curl", "ca-certificates", "build-essential", "postgresql", "postgresql-contrib")
            .run_commands("curl -fsSL https://deb.nodesource.com/setup_22.x | bash -", "apt-get install -y nodejs")
            .pip_install("pytest>=8", "uv"))
