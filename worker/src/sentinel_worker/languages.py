from __future__ import annotations


def language_for(path: str) -> str | None:
    suffix = path.rsplit(".", 1)[-1] if "." in path else ""
    return {
        "ts": "typescript",
        "tsx": "typescript",
        "js": "javascript",
        "jsx": "javascript",
        "py": "python",
        "rb": "ruby",
        "java": "java",
        "go": "go",
        "rs": "rust",
        "c": "c",
        "cpp": "cpp",
        "h": "c",
    }.get(suffix)
