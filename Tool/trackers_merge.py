#!/usr/bin/env python3
"""
qBittorrent Tracker Merger
Purpose: aggregate multiple tracker lists based on trackers.txt, deduplicate, drop blank lines,
         strip leading/trailing whitespace, remove non-standard comments, keep only raw tracker URLs,
         and write one .txt file per group
Usage: python trackers_merge.py -b ./Tool/trackers.txt -o ./Trackers
"""

import re
import argparse
import os
import sys
import urllib.request
import urllib.error
import time

MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds between retries

# Valid tracker scheme prefixes (matched case-insensitively)
VALID_SCHEMES = ("udp://", "http://", "https://", "ws://", "wss://")

# Output ordering by scheme: udp first, then http, then https, then everything else
SCHEME_ORDER = ["udp", "http", "https"]

# Full tracker URL validation: scheme + host (no whitespace) + optional path
_TRACKER_RE = re.compile(
    r"^(udp|https?|wss?)://[^\s/]+(:\d+)?(/\S*)?$",
    re.IGNORECASE,
)


def scheme_of(tracker: str) -> str:
    """Return the lowercase scheme of a tracker URL (the part before "://")."""
    return tracker.split("://", 1)[0].lower()


def sort_by_scheme(trackers: list[str]) -> list[str]:
    """Sort by scheme in the order udp, http, https, then others; stable within each scheme."""
    order = {s: i for i, s in enumerate(SCHEME_ORDER)}
    return sorted(trackers, key=lambda t: order.get(scheme_of(t), len(SCHEME_ORDER)))


def fetch_content(url: str, retries: int = MAX_RETRIES, delay: int = RETRY_DELAY) -> list[str] | None:
    print(f"  Fetching: {url}")
    if not url.startswith("http://") and not url.startswith("https://"):
        if not os.path.isfile(url):
            print(f"  [error] local file not found: {url}", file=sys.stderr)
            return None
        try:
            with open(url, "r", encoding="utf-8") as f:
                return f.read().splitlines()
        except Exception as e:
            print(f"  [error] failed to read local file {url}: {e}", file=sys.stderr)
            return None

    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (trackers-merge-script)"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read()
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    text = raw.decode("latin-1")
                if attempt > 1:
                    print(f"  [retry ok] succeeded on attempt {attempt}: {url}")
                return text.splitlines()
        except urllib.error.HTTPError as e:
            print(f"  [error] HTTP {e.code}: {url}", file=sys.stderr)
            if 400 <= e.code < 500:
                print(f"  [give up] client error, not retrying", file=sys.stderr)
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


def parse_batch_file(batch_path: str) -> list[tuple[str, list[str]]]:
    """Parse trackers.txt: split into [group] sections, one tracker-list URL or local path per line."""
    if not os.path.isfile(batch_path):
        print(f"[error] batch config file not found: {batch_path}", file=sys.stderr)
        sys.exit(1)

    groups: list[tuple[str, list[str]]] = []
    current_name: str | None = None
    current_sources: list[str] = []

    with open(batch_path, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("[") and line.endswith("]"):
                if current_name is not None:
                    if not current_sources:
                        print(f"[error] group [{current_name}] has no sources", file=sys.stderr)
                        sys.exit(1)
                    groups.append((current_name, current_sources))
                current_name = line[1:-1].strip()
                current_sources = []
            else:
                if current_name is None:
                    print(f"[error] line {lineno}: source appears before any [group]", file=sys.stderr)
                    sys.exit(1)
                current_sources.append(line)

    if current_name is not None:
        if not current_sources:
            print(f"[error] group [{current_name}] has no sources", file=sys.stderr)
            sys.exit(1)
        groups.append((current_name, current_sources))

    if not groups:
        print("[error] no valid group found in the batch config file", file=sys.stderr)
        sys.exit(1)

    return groups


def clean_tracker(line: str) -> str | None:
    """
    Clean a single line:
    1. Strip leading/trailing whitespace
    2. Blank line -> drop
    3. Non-tracker URL (comment / description / junk) -> drop
    Keep only raw tracker URLs matching the udp/http/https/ws/wss schemes.
    """
    line = line.strip()
    if not line:
        return None
    if not line.lower().startswith(VALID_SCHEMES):
        return None
    if not _TRACKER_RE.match(line):
        return None
    return line


def merge_trackers(urls: list[str]) -> tuple[list[str] | None, dict]:
    all_lines: list[str] = []
    stats = {
        "sources": len(urls),
        "total_lines": 0,
        "comment_or_empty": 0,
        "before_dedup": 0,
        "final": 0,
    }

    print(f"\n[1/4] Fetching {len(urls)} tracker source(s)...")
    for url in urls:
        lines = fetch_content(url)
        if lines is None:
            print(f"\n[error] source {url} failed to load; aborting this task to avoid an incomplete result", file=sys.stderr)
            return None, stats
        stats["total_lines"] += len(lines)
        all_lines.extend(lines)

    print(f"\n[2/4] Cleaning (strip whitespace -> drop blank lines -> discard non-tracker lines)...")
    cleaned: list[str] = []
    for line in all_lines:
        result = clean_tracker(line)
        if result is None:
            stats["comment_or_empty"] += 1
        else:
            cleaned.append(result)
    stats["before_dedup"] = len(cleaned)

    print(f"\n[3/4] Deduplicating (preserving first-seen order)...")
    seen: set[str] = set()
    deduped: list[str] = []
    for tracker in cleaned:
        if tracker not in seen:
            seen.add(tracker)
            deduped.append(tracker)
    stats["final"] = len(deduped)

    print(f"\n[4/4] Sorting by scheme (udp -> http -> https -> others)...")
    ordered = sort_by_scheme(deduped)

    return ordered, stats


def write_output(trackers: list[str], output_dir: str, filename: str) -> str:
    """Write the raw tracker URL list, one per line, no comments and no blank lines; append .txt automatically."""
    os.makedirs(output_dir, exist_ok=True)

    if not filename.endswith(".txt"):
        filename += ".txt"

    output_path = os.path.join(output_dir, filename)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(trackers))
        f.write("\n")

    return output_path


def print_stats(stats: dict, output_path: str):
    print("\n" + "=" * 50)
    print("  Aggregation complete!")
    print("=" * 50)
    print(f"  Sources               : {stats['sources']}")
    print(f"  Raw total lines       : {stats['total_lines']}")
    print(f"  Comment/blank/invalid : {stats['comment_or_empty']}")
    print(f"  Valid trackers (pre-dedup) : {stats['before_dedup']}")
    print(f"  Valid trackers (final)     : {stats['final']}")
    print(f"  Duplicates removed    : {stats['before_dedup'] - stats['final']}")
    print(f"  Output file           : {output_path}")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(
        description="qBittorrent tracker aggregator: merge multiple tracker lists based on trackers.txt, deduplicate and denoise, output a raw URL list",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Batch aggregate by group (each [group] in trackers.txt produces one .txt):
  python trackers_merge.py -b ./Tool/trackers.txt -o ./Trackers

  # Single-group mode, passing source URLs directly:
  python trackers_merge.py \\
    -u https://example.com/trackers_all.txt \\
    -o ./Trackers -n all
        """,
    )

    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "-u", "--urls", nargs="+", metavar="URL_OR_PATH", help="one or more tracker-list URLs or local paths (space-separated)"
    )
    source_group.add_argument(
        "-b", "--batch", metavar="BATCH_FILE", help="batch config file (trackers.txt), split into [group] sections"
    )

    parser.add_argument("-o", "--output-dir", required=True, metavar="DIR", help="output directory (created if it does not exist)")
    parser.add_argument(
        "-n", "--name", required=False, default=None, metavar="FILENAME", help="output filename (no need to include the .txt extension)"
    )

    args = parser.parse_args()

    if args.urls:
        if not args.name:
            print("[error] -n/--name is required in single-group mode", file=sys.stderr)
            sys.exit(1)
        tasks = [(args.name, args.urls)]
    else:  # batch
        tasks = parse_batch_file(args.batch)

    total = len(tasks)
    success_count = 0
    for idx, (name, urls) in enumerate(tasks, 1):
        print(f"\n{'=' * 50}")
        print(f"  Task [{idx}/{total}]: {name}")
        print(f"{'=' * 50}")

        trackers, stats = merge_trackers(urls)

        if trackers is None:
            print(f"[error] task {name} aborted due to a source load failure, skipping output", file=sys.stderr)
            continue

        if not trackers:
            print(f"\n[warning] task {name} produced an empty result, skipping", file=sys.stderr)
            continue

        output_path = write_output(trackers, args.output_dir, name)
        print_stats(stats, output_path)
        success_count += 1

    if total > 1:
        print(f"\nAll tasks complete, generated {success_count}/{total} file(s), output directory: {args.output_dir}")


if __name__ == "__main__":
    main()
