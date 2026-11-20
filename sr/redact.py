import re

PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-(?:ant-)?[A-Za-z0-9_\-]{20,}"),
    re.compile(r"mnfst_[A-Za-z0-9_\-]{10,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[abpr]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]
MENTION = re.compile(r"(?<![\w`])@(?=[A-Za-z0-9])")
TAG = re.compile(r"<(?=[!/A-Za-z])")


def redact(text):
    text = str(text or "")
    for p in PATTERNS:
        text = p.sub("[redacted]", text)
    return text


def clean(text, cap=2000):
    """Redact secrets, defuse @mentions and HTML/comment markers, cap length."""
    text = redact(text)
    text = MENTION.sub("@\u200b", text)
    text = TAG.sub("&lt;", text)
    return text[:cap]
