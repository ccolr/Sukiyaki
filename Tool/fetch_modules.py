#!/usr/bin/env python3
"""
Surge Module Fetcher
Purpose: fetch Surge modules/scripts into Surge_Modules/ based on surge_modules.txt
      - [Original] block: fetch as-is, optional rename
      - [Modified] block: fetch, then apply add / delete / replace rules, optional rename
      - inject #!category=🌸 Sukiyaki into every .sgmodule file
Usage: python fetch_modules.py [-i surge_modules.txt] [-o Surge_Modules]

surge_modules.txt format:
    [Original]
    <url>                       # keep original filename
    <url> <newname>             # rename to newname (keeps original extension if none given)

    [Modified]
    <url> [<newname>]
    ADD: <whole line>           # append a line at the end of the file
    DELETE: <whole line>        # delete lines matching the content (substring match)
    REPLACE: <old> <new>        # replace the "old" substring with "new"
    <url> [<newname>]           # next module entry
    ...

ADD / DELETE / REPLACE may appear any number of times; each one is applied as it appears.
"""

import argparse
import os
import sys
import time
import urllib.error
import urllib.request

CATEGORY_VALUE = "🌸 Sukiyaki"
CATEGORY_LINE = f"#!category={CATEGORY_VALUE}"

MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds


def fetch_content(url: str, retries: int = MAX_RETRIES, delay: int = RETRY_DELAY) -> str | None:
    """Fetch URL content, returning the raw text (None on failure)."""
    print(f"  Fetching: {url}")
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (surge-module-fetcher)"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read()
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("latin-1")
            if attempt > 1:
                print(f"  [retry ok] succeeded on attempt {attempt}: {url}")
            return text
        except urllib.error.HTTPError as e:
            print(f"  [error] HTTP {e.code}: {url}", file=sys.stderr)
            if 400 <= e.code < 500:
                print("  [give up] client error, not retrying", file=sys.stderr)
                return None
        except urllib.error.URLError as e:
            print(f"  [error] unreachable (attempt {attempt}/{retries}): {url} — {e.reason}", file=sys.stderr)
        except Exception as e:
            print(f"  [error] unknown error (attempt {attempt}/{retries}): {url} — {e}", file=sys.stderr)

        if attempt < retries:
            print(f"  [retry] retrying in {delay}s (attempt {attempt + 1})...", file=sys.stderr)
            time.sleep(delay)

    print(f"  [give up] still failing after {retries} retries: {url}", file=sys.stderr)
    return None


def resolve_filename(url: str, newname: str | None) -> str:
    """Compute the output filename from the URL and optional rename (keeps original extension if the rename has none)."""
    orig_base = os.path.basename(url.split("?", 1)[0].split("#", 1)[0])
    orig_ext = os.path.splitext(orig_base)[1]
    if not newname:
        return orig_base
    if os.path.splitext(newname)[1]:
        return newname
    return newname + orig_ext


def parse_modules_file(path: str):
    """Parse surge_modules.txt, returning (originals, modified).

    originals: list[(url, newname|None)]
    modified:  list[(url, newname|None, mods)], mods = list[(op, value)]
    """
    if not os.path.isfile(path):
        print(f"[error] config file not found: {path}", file=sys.stderr)
        sys.exit(1)

    originals: list[tuple[str, str | None]] = []
    modified: list[tuple[str, str | None, list[tuple[str, str]]]] = []

    section = None  # "original" | "modified"
    current_mod = None  # points to the mods of the current entry in the modified list

    with open(path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if line.lower() == "[original]":
            section = "original"
            current_mod = None
            continue
        if line.lower() == "[modified]":
            section = "modified"
            current_mod = None
            continue
        if line.lower() == "end":
            break

        if section == "original":
            url, _, name = line.partition(" ")
            originals.append((url, name.strip() or None))

        elif section == "modified":
            if line.upper().startswith(("ADD:", "DELETE:", "REPLACE:")):
                if current_mod is None:
                    print(f"[warning] modification rule has no module to attach to, ignored: {line}", file=sys.stderr)
                    continue
                op, _, value = line.partition(":")
                value = value.strip()
                if value:
                    current_mod.append((op.strip().upper(), value))
            else:
                url, _, name = line.partition(" ")
                mods: list[tuple[str, str]] = []
                modified.append((url, name.strip() or None, mods))
                current_mod = mods

    return originals, modified


def apply_modifications(content: str, mods: list[tuple[str, str]]) -> str:
    """Apply the add / delete / replace rules in order."""
    lines = content.splitlines()
    for op, value in mods:
        if op == "ADD":
            lines.append(value)
            print(f"    [ADD] appended: {value}")
        elif op == "DELETE":
            before = len(lines)
            lines = [ln for ln in lines if value not in ln]
            print(f"    [DELETE] removed {before - len(lines)} line(s) (match: {value})")
        elif op == "REPLACE":
            orig, _, repl = value.partition(" ")
            repl = repl.strip()
            text = "\n".join(lines)
            count = text.count(orig)
            text = text.replace(orig, repl)
            lines = text.splitlines()
            print(f"    [REPLACE] replaced {count} occurrence(s): {orig} -> {repl}")
    return "\n".join(lines) + "\n"


def inject_category(content: str) -> str:
    """Inject or rewrite #!category in .sgmodule content."""
    lines = content.splitlines()

    # 1) #!category already present -> rewrite
    for i, ln in enumerate(lines):
        if ln.lstrip().startswith("#!category"):
            lines[i] = CATEGORY_LINE
            print(f"    [category] rewrote existing category -> {CATEGORY_VALUE}")
            return "\n".join(lines) + "\n"

    # 2) no #!category -> insert after #!desc, otherwise after #!name
    desc_idx = next((i for i, ln in enumerate(lines) if ln.lstrip().startswith("#!desc")), None)
    name_idx = next((i for i, ln in enumerate(lines) if ln.lstrip().startswith("#!name")), None)
    insert_at = None
    if desc_idx is not None:
        insert_at = desc_idx + 1
    elif name_idx is not None:
        insert_at = name_idx + 1

    if insert_at is not None:
        lines.insert(insert_at, CATEGORY_LINE)
        print(f"    [category] added category -> {CATEGORY_VALUE}")
    else:
        lines.insert(0, CATEGORY_LINE)
        print(f"    [category] file has no #!name/#!desc, added category at top -> {CATEGORY_VALUE}")
    return "\n".join(lines) + "\n"


def write_module(url: str, newname: str | None, out_dir: str, mods: list[tuple[str, str]] | None = None) -> bool:
    content = fetch_content(url)
    if content is None:
        return False

    filename = resolve_filename(url, newname)

    if mods:
        content = apply_modifications(content, mods)

    if filename.endswith(".sgmodule"):
        content = inject_category(content)

    out_path = os.path.join(out_dir, filename)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  [done] -> {out_path}\n")
    return True


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)

    parser = argparse.ArgumentParser(description="Fetch and process Surge modules into Surge_Modules/")
    parser.add_argument("-i", "--input", default=os.path.join(script_dir, "surge_modules.txt"),
                        help="module list file (default: Tool/surge_modules.txt)")
    parser.add_argument("-o", "--output", default=os.path.join(repo_root, "Surge_Modules"),
                        help="output directory (default: Surge_Modules/)")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    originals, modified = parse_modules_file(args.input)

    ok = 0
    fail = 0

    print(f"\n=== [Original] {len(originals)} total ===")
    for url, name in originals:
        if write_module(url, name, args.output):
            ok += 1
        else:
            fail += 1

    print(f"\n=== [Modified] {len(modified)} total ===")
    for url, name, mods in modified:
        if write_module(url, name, args.output, mods):
            ok += 1
        else:
            fail += 1

    print(f"\n=== Done: {ok} succeeded, {fail} failed, output directory: {args.output} ===")
    if fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
