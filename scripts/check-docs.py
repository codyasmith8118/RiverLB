#!/usr/bin/env python3
"""Check repository Markdown links without network access or extra dependencies."""
import argparse
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def unfenced(text):
    """Ignore code examples; their paths and headings are not document content."""
    lines = []
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence is None:
            lines.append(line)
    return "\n".join(lines)


def prose(text):
    return re.sub(r"(`+).*?\1", "", unfenced(text))


def anchors(text):
    found = set()
    counts = {}
    # Retain heading code spans: GitHub includes their text in the anchor.
    for line in unfenced(text).splitlines():
        match = re.match(r"^#{1,6}\s+(.+?)(?:\s+#+)?$", line)
        if not match:
            continue
        label = re.sub(r"<[^>]+>", "", match.group(1)).lower()
        slug = re.sub(r"[^\w\- ]", "", label).replace(" ", "-")
        count = counts.get(slug, 0)
        counts[slug] = count + 1
        found.add(f"{slug}-{count}" if count else slug)
    found.update(re.findall(r'(?:id|name)=["\']([^"\']+)["\']', unfenced(text)))
    return found


def destinations(text):
    text = prose(text)
    pattern = r"!?\[[^\]\n]*\]\(\s*(?:<([^>]+)>|([^\s)]+))(?:\s+[^)]*)?\)"
    for match in re.finditer(pattern, text):
        yield match.group(1) or match.group(2)
    for match in re.finditer(r"^\s{0,3}\[[^\]]+\]:\s*(?:<([^>]+)>|(\S+))", text, re.M):
        yield match.group(1) or match.group(2)


def check(root):
    root = root.resolve()
    # Walk source documentation, including GitHub templates and deployment guides.
    # Prune generated trees before descending so build artifacts cannot affect CI.
    documents = set()
    excluded = {"target", "dist", "node_modules", "__pycache__", "agents"}
    for directory, folders, files in os.walk(root, followlinks=False):
        folders[:] = [name for name in folders
                      if name not in excluded
                      and (not name.startswith(".") or name == ".github")
                      and not (Path(directory) / name).is_symlink()]
        documents.update(Path(directory) / name for name in files
                         if name.endswith(".md") and not (Path(directory) / name).is_symlink())
    errors = []
    checked = 0
    for document in sorted(documents):
        if not document.is_file():
            continue
        for destination in destinations(document.read_text()):
            url = urlsplit(destination)
            if url.scheme or url.netloc:
                continue
            checked += 1
            path = unquote(url.path)
            target = ((root / path.lstrip("/")) if path.startswith("/")
                      else document.parent / path).resolve() if path else document
            label = f"{document.relative_to(root)}: {destination}"
            if not target.is_relative_to(root.resolve()):
                errors.append(f"{label}: points outside the repository")
            elif not target.exists():
                errors.append(f"{label}: target does not exist")
            elif url.fragment and target.suffix == ".md" and target.is_file():
                if unquote(url.fragment) not in anchors(target.read_text()):
                    errors.append(f"{label}: heading does not exist")
    return len(documents), checked, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    documents, links, errors = check(args.root)
    for error in errors:
        print(error, file=sys.stderr)
    print(f"Checked {links} local links across {documents} Markdown files; {len(errors)} errors.")
    return bool(errors)


if __name__ == "__main__":
    sys.exit(main())
