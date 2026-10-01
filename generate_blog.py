#!/usr/bin/env python3
"""Build blog-data.js from markdown posts in blog/posts/.

Usage:
    python3 generate_blog.py

Each post is a markdown file with optional YAML-ish front matter:

    ---
    title: Defeating PIE with a leak
    date: 2026-10-01
    category: Binary Exploitation
    tags: pwn, gdb, rop
    difficulty: Medium
    summary: One line describing the post.
    ---

    # Body heading
    ...markdown...

If front matter is missing, the filename becomes the title and the file's
modification time becomes the date. Markdown is rendered with the same parser
used for CTF writeups (generate_data.py) so the styling stays consistent.
"""

import os
import re
import json
import datetime

from generate_data import parse_markdown

POSTS_DIR = os.path.join("blog", "posts")
OUT_FILE = "blog-data.js"


def parse_front_matter(text):
    """Return (meta dict, body str). Tolerates a missing front matter block."""
    meta = {}
    body = text
    if text.lstrip().startswith("---"):
        # find the closing --- on its own line
        stripped = text.lstrip()
        end = stripped.find("\n---", 3)
        if end != -1:
            block = stripped[3:end].strip("\n")
            body = stripped[end + 4:].lstrip("\n")
            for line in block.splitlines():
                if ":" in line:
                    key, val = line.split(":", 1)
                    meta[key.strip().lower()] = val.strip()
    return meta, body


def slugify(name):
    name = name.lower().strip()
    name = re.sub(r"[^a-z0-9]+", "-", name)
    return name.strip("-")


def reading_time(body):
    words = len(re.findall(r"\w+", body))
    return max(1, round(words / 200))


def main():
    posts = []

    if os.path.isdir(POSTS_DIR):
        for filename in sorted(os.listdir(POSTS_DIR)):
            if not filename.endswith(".md") or filename.startswith("_"):
                continue

            path = os.path.join(POSTS_DIR, filename)
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()

            meta, body = parse_front_matter(text)
            stem = filename[:-3]

            title = meta.get("title") or stem.replace("-", " ").title()
            slug = meta.get("slug") or slugify(stem)

            date = meta.get("date")
            if not date:
                date = datetime.date.fromtimestamp(os.path.getmtime(path)).isoformat()

            tags = [t.strip() for t in meta.get("tags", "").split(",") if t.strip()]

            posts.append({
                "slug": slug,
                "title": title,
                "date": date,
                "category": meta.get("category", "Miscellaneous"),
                "tags": tags,
                "difficulty": meta.get("difficulty", ""),
                "summary": meta.get("summary", ""),
                "readingTime": reading_time(body),
                "html": parse_markdown(body),
            })
            print(f"  + {filename} -> {title}")

    posts.sort(key=lambda p: p["date"], reverse=True)

    js = "const blogPosts = " + json.dumps(posts, indent=4) + ";\n"
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write(js)

    print(f"blog-data.js generated ({len(posts)} post(s)).")


if __name__ == "__main__":
    main()
