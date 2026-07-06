#!/usr/bin/env python3
"""
Surge Rule Merger
Purpose: merge multiple Surge rule-set files (.conf/.list), strip comments and blank lines, deduplicate, output a .conf file
Usage: python surge_merge.py -u <url1> <url2> ... -o <output_dir> -n <filename>
"""

import re
import argparse
import os
import sys
import urllib.request
import urllib.error
import time

# ============================================================
# Exclude list — write regular expressions inside the quotes
EXCLUDE_RULES: list[str] = [
    # --- add rules to exclude below (regular expressions, case-insensitive) ---
    r"7h1s_rul35et_i5_mad3_by_5ukk4w",
    # --- end ---
]
# ============================================================


MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds between retries


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
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (surge-merge-script)"})
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
            # retrying 4xx errors is pointless, give up immediately
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


def parse_batch_file(batch_path: str) -> list[tuple[str, list[str], list[re.Pattern]]]:
    if not os.path.isfile(batch_path):
        print(f"[error] batch config file not found: {batch_path}", file=sys.stderr)
        sys.exit(1)

    groups = []
    current_name = None
    current_sources = []
    current_excludes = []
    phase = "sources"

    with open(batch_path, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            print(f"[debug] line {lineno} repr: {repr(raw)}", file=sys.stderr)
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("[") and line.endswith("]"):
                if current_name is not None:
                    if not current_sources:
                        print(f"[error] group [{current_name}] has no rule sources", file=sys.stderr)
                        sys.exit(1)
                    groups.append((current_name, current_sources, current_excludes))
                current_name = line[1:-1].strip()
                current_sources = []
                current_excludes = []
                phase = "sources"

            elif line.startswith("EXCLUDE:"):
                if phase == "sources" and not current_sources:
                    print(
                        f"[error] line {lineno}: exclude rule appears before any source (group: {current_name})", file=sys.stderr
                    )
                    sys.exit(1)
                phase = "excludes"
                pattern_str = line[len("EXCLUDE:") :].strip()
                if not pattern_str:
                    continue
                try:
                    compiled = re.compile(pattern_str, re.IGNORECASE)
                    current_excludes.append(compiled)
                except re.error as e:
                    print(
                        f"[error] line {lineno}: invalid regular expression ({pattern_str!r}): {e} (group: {current_name})",
                        file=sys.stderr,
                    )
                    sys.exit(1)

            else:
                if current_name is None:
                    print(f"[error] line {lineno}: rule line appears before any [group]", file=sys.stderr)
                    sys.exit(1)
                if phase == "excludes":
                    print(f"[error] line {lineno}: source appears after exclude rules (group: {current_name})", file=sys.stderr)
                    sys.exit(1)
                current_sources.append(line)

    if current_name is not None:
        if not current_sources:
            print(f"[error] group [{current_name}] has no rule sources", file=sys.stderr)
            sys.exit(1)
        groups.append((current_name, current_sources, current_excludes))

    if not groups:
        print("[error] no valid group found in the batch config file", file=sys.stderr)
        sys.exit(1)

    return groups


# Valid rule-type prefixes (case-sensitive, must match exactly)
VALID_PREFIXES = {
    "SUBNET",
    "SRC-IP",
    "SRC-PORT",
    "IN-PORT",
    "DEST-PORT",
    "PROTOCOL",
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "PROCESS-NAME",
    "USER-AGENT",
    "URL-REGEX",
    "HOSTNAME-TYPE",
    "AND",
    "OR",
    "NOT",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "IP-ASN",
}

# Plain domain: only letters/digits/"-"/".", may start with "."
_PLAIN_DOMAIN_RE = re.compile(r"^\.?[a-zA-Z0-9][a-zA-Z0-9\-]*(\.[a-zA-Z0-9\-]+)*$")

# Inline comment match: "one or more whitespace" + "comment marker (# ; //)" + "everything after"
# The comment marker must immediately follow whitespace, to avoid truncating a "#" inside a domain or rule
_INLINE_COMMENT_RE = re.compile(r"\s+(#|;|//).*$")

# Rule-type priority order
RULE_ORDER = [
    "SUBNET",
    "SRC-IP",
    "SRC-PORT",
    "IN-PORT",
    "DEST-PORT",
    "PROTOCOL",
    "PLAIN_DOMAIN",  # plain domain / starts with .
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "PROCESS-NAME",
    "USER-AGENT",
    "URL-REGEX",
    "HOSTNAME-TYPE",
    "AND",
    "OR",
    "NOT",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "IP-ASN",
]

NEED_NO_RESOLVE = {"IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN"}


def ensure_no_resolve(rule: str) -> str:
    """Append the no-resolve suffix to rules that need it (case-sensitive, always appended as lowercase no-resolve)."""
    # Check ignoring case, but always append using lowercase
    parts = rule.split(",")
    if parts[-1].strip().lower() != "no-resolve":
        return rule + ",no-resolve"
    return rule


def clean_rule(line: str) -> str | None:
    """
    Process each line strictly in this order:
    1. Strip leading/trailing whitespace
    2. Blank line, or not starting with an allowed type -> drop (return None)
    3. Strip inline comments ([whitespace + comment marker] structure and everything after)
    4. Strip whitespace around commas
    5. Append no-resolve
    """
    # Step 1: strip leading/trailing whitespace
    line = line.strip()

    # Step 2: drop blank lines
    if not line:
        return None

    # Step 2: whole-line comment (line starts with a comment marker) -> not an allowed type, drop
    if line.startswith("#") or line.startswith(";") or line.startswith("//"):
        return None

    # Step 2: validate the rule prefix (case-sensitive, no case conversion)
    if "," in line:
        # Has a comma: take the part before the comma as the prefix, match VALID_PREFIXES exactly
        prefix = line.split(",")[0].strip()
        if prefix not in VALID_PREFIXES:
            return None
    else:
        # No comma: must be a valid plain-domain format
        if not _PLAIN_DOMAIN_RE.match(line):
            return None

    # Step 3: strip inline comments
    # Match "one or more whitespace" + "# or ; or //" + "everything after"
    line = _INLINE_COMMENT_RE.sub("", line).strip()
    if not line:
        return None

    # Step 4: strip whitespace around commas
    line = re.sub(r"\s*,\s*", ",", line)

    # Step 5: append no-resolve (only for rule types that need it)
    if "," in line:
        rule_type = line.split(",")[0].strip()
        if rule_type in NEED_NO_RESOLVE:
            line = ensure_no_resolve(line)

    return line


def merge_rules(urls: list[str], group_excludes: list[re.Pattern] | None = None) -> tuple[list[str] | None, dict]:
    all_lines: list[str] = []
    stats = {
        "sources": len(urls),
        "total_lines": 0,
        "comment_or_empty": 0,
        "before_dedup": 0,
        "after_dedup": 0,  # after dedup, before exclusion
        "excluded": 0,
        "excluded_rules": [],
        "failed_sources": 0,
        "final": 0,  # final count after exclusion
    }

    # Compile global exclude rules to regex
    global_patterns = []
    for pattern_str in EXCLUDE_RULES:
        try:
            global_patterns.append(re.compile(pattern_str, re.IGNORECASE))
        except re.error as e:
            print(f"[warning] invalid global exclude regex ({pattern_str!r}): {e}", file=sys.stderr)
    all_patterns = global_patterns + (group_excludes or [])

    print(f"\n[1/5] Fetching {len(urls)} rule sources...")
    for url in urls:
        lines = fetch_content(url)
        if lines is None:
            print(f"\n[error] source {url} failed to load; aborting this task to avoid an incomplete rule set", file=sys.stderr)
            return None, stats
        stats["total_lines"] += len(lines)
        all_lines.extend(lines)

    print(f"\n[2/5] Cleaning (strip whitespace -> filter invalid lines -> strip inline comments -> append no-resolve)...")
    cleaned: list[str] = []
    for line in all_lines:
        result = clean_rule(line)
        if result is None:
            stats["comment_or_empty"] += 1
        else:
            cleaned.append(result)
    stats["before_dedup"] = len(cleaned)

    print(f"\n[3/5] Deduplicating (case-sensitive)...")
    seen: set[str] = set()
    deduped: list[str] = []
    for rule in cleaned:
        if rule not in seen:
            seen.add(rule)
            deduped.append(rule)
    stats["after_dedup"] = len(deduped)  # <- records the true post-dedup count

    print(f"\n[4/5] Applying exclude rules...")
    final: list[str] = []
    for rule in deduped:
        if any(p.search(rule) for p in all_patterns):
            stats["excluded"] += 1
            stats["excluded_rules"].append(rule)
            continue
        final.append(rule)
    stats["final"] = len(final)  # <- records the post-exclusion count

    print(f"\n[5/5] Sorting by rule type...")
    sorted_rules = sort_rules(final)

    return sorted_rules, stats


def get_rule_type(rule: str) -> str:
    """Identify the rule type (case-sensitive)."""
    stripped = rule.strip()
    if not stripped:
        return "UNKNOWN"
    # No comma, or starts with "." -> plain domain
    if "," not in stripped or stripped.startswith("."):
        return "PLAIN_DOMAIN"
    prefix = stripped.split(",")[0].strip()  # no case conversion
    return prefix if prefix in RULE_ORDER else "UNKNOWN"


def sort_rules(rules: list[str]) -> list[str]:
    """Sort by rule type (no-resolve is already handled in clean_rule, not repeated here)."""
    priority = {rtype: i for i, rtype in enumerate(RULE_ORDER)}

    processed = []
    for rule in rules:
        rtype = get_rule_type(rule)
        processed.append((priority.get(rtype, len(RULE_ORDER)), rule))

    processed.sort(key=lambda x: x[0])
    return [rule for _, rule in processed]


def write_output(rules: list[str], output_dir: str, filename: str, urls: list[str], stats: dict) -> str:
    """Write the .conf file, appending the .conf extension automatically."""
    os.makedirs(output_dir, exist_ok=True)

    if not filename.endswith(".conf"):
        filename += ".conf"

    output_path = os.path.join(output_dir, filename)

    header_lines = [
        "# ============================================================",
        "# Surge Rule Set — Auto-generated by surge_merge.py",
        f"# Sources  : {stats['sources']}",
        f"# Total    : {stats['final']} rules",
        "# ------------------------------------------------------------",
    ]
    for i, url in enumerate(urls, 1):
        header_lines.append(f"# [{i}] {url}")
    header_lines.append("# ============================================================")
    header_lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(header_lines))
        f.write("\n".join(rules))
        f.write("\n")

    return output_path


def print_stats(stats: dict, output_path: str):
    print("\n" + "=" * 50)
    print("  Merge complete!")
    print("=" * 50)
    print(f"  Rule sources          : {stats['sources']}")
    print(f"  Failed sources        : {stats['failed_sources']}")
    print(f"  Raw total lines       : {stats['total_lines']}")
    print(f"  Comment/blank/invalid : {stats['comment_or_empty']}")
    print(f"  Valid rules (pre-dedup) : {stats['before_dedup']}")
    print(f"  Valid rules (post-dedup): {stats['after_dedup']}")
    print(f"  Excluded rules        : {stats.get('excluded', 0)}")
    if stats.get("excluded_rules"):
        for r in stats["excluded_rules"]:
            print(f"    - {r}")
    print(f"  Valid rules (final)   : {stats['final']}")
    print(f"  Duplicates removed    : {stats['before_dedup'] - stats['after_dedup']}")
    print(f"  Output file           : {output_path}")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(
        description="Surge rule-set merger: merge multiple .conf/.list rule sources, deduplicate, output a .conf file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python surge_merge.py \\
    -u https://example.com/rules1.list https://example.com/rules2.conf \\
    -o ./output \\
    -n my_rules

  # You can also read the URL list from a file (one URL per line):
  python surge_merge.py -f urls.txt -o ./output -n merged
        """,
    )

    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "-u", "--urls", nargs="+", metavar="URL_OR_PATH", help="one or more rule-set URLs or local file paths (space-separated, may be mixed)"
    )
    source_group.add_argument(
        "-f", "--file", metavar="URL_FILE", help="text file with a URL list (one URL per line, lines starting with # are comments)"
    )
    source_group.add_argument(
        "-b", "--batch", metavar="BATCH_FILE", help="batch config file, grouped by [filename], one URL or local path per line"
    )

    parser.add_argument("-o", "--output-dir", required=True, metavar="DIR", help="output directory (created if it does not exist)")
    parser.add_argument(
        "-n", "--name", required=False, default=None, metavar="FILENAME", help="output filename (no need to include the .conf extension)"
    )

    args = parser.parse_args()

    # Collect the task list: [(output_name, [urls])]
    if args.urls:
        if not args.name:
            print("[error] -n/--name is required in single-group mode", file=sys.stderr)
            sys.exit(1)
        tasks = [(args.name, args.urls)]
    elif args.file:
        if not os.path.isfile(args.file):
            print(f"[error] URL file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        if not urls:
            print("[error] URL file is empty or all comments", file=sys.stderr)
            sys.exit(1)
        if not args.name:
            print("[error] -n/--name is required in single-group mode", file=sys.stderr)
            sys.exit(1)
        tasks = [(args.name, urls)]
    else:  # batch
        tasks = parse_batch_file(args.batch)

    total = len(tasks)
    success_count = 0
    for idx, task in enumerate(tasks, 1):
        if len(task) == 3:
            name, urls, group_excludes = task
        else:
            name, urls = task
            group_excludes = []

        print(f"\n{'=' * 50}")
        print(f"  Task [{idx}/{total}]: {name}")
        print(f"{'=' * 50}")

        rules, stats = merge_rules(urls, group_excludes)

        if rules is None:
            print(f"[error] task {name} aborted due to a source load failure, skipping output", file=sys.stderr)
            continue

        if not rules:
            print(f"\n[warning] task {name} produced an empty result, skipping", file=sys.stderr)
            continue

        output_path = write_output(rules, args.output_dir, name, urls, stats)
        print_stats(stats, output_path)
        success_count += 1

    if total > 1:
        print(f"\nAll tasks complete, generated {success_count}/{total} file(s), output directory: {args.output_dir}")


if __name__ == "__main__":
    main()
