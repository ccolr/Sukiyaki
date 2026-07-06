#!/usr/bin/env python3
"""
Surge Rule Classifier
Purpose: merge multiple rule sources, clean and deduplicate, then split by type into domains/non_ip/ip
     and push each to the Surge/domains, Surge/non_ip, Surge/ip directories of the ccolr/Rule repo
"""

import re
import argparse
import os
import sys
import urllib.request
import urllib.error
import time
from datetime import datetime, timezone

# ============================================================
# Rule classification definitions
# ============================================================
DOMAIN_ONLY_PREFIXES = set()  # plain domain, no prefix field

NON_IP_PREFIXES = {
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
}

LOGICAL_PREFIXES = {"AND", "OR", "NOT"}

IP_PREFIXES = {
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "IP-ASN",
}

NEED_NO_RESOLVE = {"IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN"}

ALL_KNOWN_PREFIXES = NON_IP_PREFIXES | IP_PREFIXES  # whitelist of inner fields for logical rules

VALID_PREFIXES = NON_IP_PREFIXES | IP_PREFIXES | LOGICAL_PREFIXES

_PLAIN_DOMAIN_RE = re.compile(r"^\.?[a-zA-Z0-9][a-zA-Z0-9\-]*(\.[a-zA-Z0-9\-]+)*$")

# Inline comment match: "one or more whitespace" + "comment marker (# ; //)" + "everything after"
_INLINE_COMMENT_RE = re.compile(r"\s+(#|;|//).*$")

# Match a single sub-rule inside parentheses; the third field only accepts no-resolve or extended-matching
# group(1)=TYPE  group(2)=VALUE  group(3)=third field (with comma) or None
_LOGICAL_INNER_RULE_RE = re.compile(
    r"\(([A-Z0-9\-]+),([^,)]+)(,no-resolve|,extended-matching)?\)",
    re.IGNORECASE,
)

# Detect whether an invalid-format sub-rule exists inside parentheses (third field is neither a valid value nor empty),
# i.e. the form (TYPE,VALUE,any other content)
_LOGICAL_INNER_ILLEGAL_RE = re.compile(
    r"\([^)]+,[^,)]+,(?!no-resolve\)|extended-matching\))[^)]+\)",
    re.IGNORECASE,
)

# ============================================================
# Exclude list
# ============================================================
EXCLUDE_RULES: list[str] = [
    # --- add rules to exclude below (regular expressions, case-insensitive) ---
    r"7h1s_rul35et_i5_mad3_by_5ukk4w",
    # --- end ---
]


# ============================================================
# Cleaning logic
# ============================================================


def ensure_no_resolve(rule: str) -> str:
    parts = rule.split(",")
    if parts[-1].strip().lower() != "no-resolve":
        return rule + ",no-resolve"
    return rule


def _extract_logical_inner_prefixes(rule: str) -> set[str]:
    return {m.group(1).upper() for m in _LOGICAL_INNER_RULE_RE.finditer(rule)}


def _fix_logical_no_resolve(rule: str) -> str | None:
    """
    Validate and complete the third field inside a logical rule's parentheses:
    - ip TYPE missing no-resolve -> append it
    - ip TYPE with extended-matching -> discard (return None)
    - non_ip TYPE with no-resolve -> discard (return None)
    - non_ip TYPE with extended-matching or no third field -> keep as-is
    - third field is an invalid value -> discard (return None)
    """
    # First detect whether an invalid third field exists (anything other than no-resolve/extended-matching)
    if _LOGICAL_INNER_ILLEGAL_RE.search(rule):
        return None

    def replacer(m: re.Match) -> str | None:
        type_field = m.group(1).upper()
        value = m.group(2)
        third = m.group(3)  # ",no-resolve" / ",extended-matching" / None

        if type_field in IP_PREFIXES:
            if third is not None and third.lower() == ",extended-matching":
                # ip TYPE cannot carry extended-matching
                raise _LogicalRuleInvalid()
            # Append no-resolve if missing
            return f"({m.group(1)},{value},no-resolve)"

        if type_field in NON_IP_PREFIXES:
            if third is not None and third.lower() == ",no-resolve":
                # non_ip TYPE cannot carry no-resolve
                raise _LogicalRuleInvalid()
            # Keep as-is (valid with or without extended-matching)
            return m.group(0)

        # LOGICAL_PREFIXES themselves are nested, not processed here
        return m.group(0)

    try:
        return _LOGICAL_INNER_RULE_RE.sub(replacer, rule)
    except _LogicalRuleInvalid:
        return None


class _LogicalRuleInvalid(Exception):
    """Sentinel exception used to abort processing inside the re.sub replacer."""

    pass


def _classify_logical_rule(rule: str) -> str | None:
    """
    Return "non_ip" / "ip" / None (discard).
    This function only decides the category; it does not complete fields — that happens after exclusion in merge_and_clean.
    """
    # Contains an invalid third-field format -> discard
    if _LOGICAL_INNER_ILLEGAL_RE.search(rule):
        return None

    inner_prefixes = _extract_logical_inner_prefixes(rule)
    known = inner_prefixes - LOGICAL_PREFIXES

    if not known:
        return None

    # Contains an unknown TYPE -> discard
    unknown_fields = known - NON_IP_PREFIXES - IP_PREFIXES
    if unknown_fields:
        return None

    has_non_ip = bool(known & NON_IP_PREFIXES)
    has_ip = bool(known & IP_PREFIXES)

    if has_non_ip and has_ip:
        return None  # mixed

    # Cross-check the third field against the TYPE category
    for m in _LOGICAL_INNER_RULE_RE.finditer(rule):
        type_field = m.group(1).upper()
        third = m.group(3)
        if type_field in IP_PREFIXES and third is not None and third.lower() == ",extended-matching":
            return None
        if type_field in NON_IP_PREFIXES and third is not None and third.lower() == ",no-resolve":
            return None

    return "ip" if has_ip else "non_ip"


def clean_rule(line: str) -> str | None:
    # Step 1: strip leading/trailing whitespace
    line = line.strip()

    # Step 2: drop blank lines and comments
    if not line:
        return None
    if line.startswith("#") or line.startswith(";") or line.startswith("//"):
        return None
    if "," in line:
        prefix = line.split(",")[0].strip()  # case-sensitive
        if prefix not in VALID_PREFIXES:
            return None
    else:
        if not _PLAIN_DOMAIN_RE.match(line):
            return None

    # Step 3: strip inline comments
    line = _INLINE_COMMENT_RE.sub("", line).strip()
    if not line:
        return None

    # Step 4: strip whitespace around commas
    line = re.sub(r"\s*,\s*", ",", line)

    # Step 5: special handling for logical rules
    if "," in line:
        prefix = line.split(",")[0].strip()
        if prefix in LOGICAL_PREFIXES:
            category = _classify_logical_rule(line)
            if category is None:
                return None  # discard: no fields / mixed / contains unknown fields
            return line

    # Step 6: append no-resolve for normal rules
    if "," in line:
        rule_type = line.split(",")[0].strip()
        if rule_type in NEED_NO_RESOLVE:
            line = ensure_no_resolve(line)

    return line


# ============================================================
# Fetching
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


# ============================================================
# Merge, clean, deduplicate
# ============================================================


def merge_and_clean(urls: list[str], group_excludes: list[re.Pattern] | None = None) -> tuple[list[str] | None, dict]:
    stats = {
        "sources": len(urls),
        "total_lines": 0,
        "discarded": 0,
        "before_dedup": 0,
        "after_dedup": 0,
        "excluded": 0,
        "excluded_rules": [],
        "failed_sources": 0,
        "final": 0,
    }

    print(f"\n[1/4] Fetching {len(urls)} rule sources...")
    all_lines = []
    for url in urls:
        lines = fetch_content(url)
        if lines is None:
            print(f"\n[error] source {url} failed to load; aborting this task to avoid an incomplete rule set", file=sys.stderr)
            return None, stats
        stats["total_lines"] += len(lines)
        all_lines.extend(lines)

    print(f"\n[2/4] Cleaning (strip whitespace -> filter invalid lines -> strip inline comments -> validate logical rules -> append no-resolve)...")
    cleaned = []
    for line in all_lines:
        result = clean_rule(line)
        if result is None:
            stats["discarded"] += 1
        else:
            cleaned.append(result)

    global_patterns = []
    for pattern_str in EXCLUDE_RULES:
        try:
            global_patterns.append(re.compile(pattern_str, re.IGNORECASE))
        except re.error as e:
            print(f"[warning] invalid global exclude regex ({pattern_str!r}): {e}", file=sys.stderr)
    all_patterns = global_patterns + (group_excludes or [])
    stats["before_dedup"] = len(cleaned)

    print(f"\n[3/4] Deduplicating (case-sensitive)...")
    seen: set[str] = set()
    deduped: list[str] = []
    for rule in cleaned:
        if rule not in seen:
            seen.add(rule)
            deduped.append(rule)
    stats["after_dedup"] = len(deduped)

    print(f"\n[4/4] Applying exclude rules...")
    final: list[str] = []
    for rule in deduped:
        if any(p.search(rule) for p in all_patterns):
            stats["excluded"] += 1
            stats["excluded_rules"].append(rule)
            continue
        final.append(rule)
    stats["final"] = len(final)

    # [5/5] Append no-resolve inside surviving logical rules (done after exclusion to avoid wasted work)
    print(f"\n[5/5] Appending no-resolve inside logical rules...")
    final = [
        _fix_logical_no_resolve(rule) if rule.split(",")[0].strip() in LOGICAL_PREFIXES else rule for rule in final
    ]

    return final, stats


# ============================================================
# Classification
# ============================================================


def classify_rules(rules: list[str]) -> tuple[list[str], list[str], list[str]]:
    """
    Return (domains, non_ip, ip).
    A logical rule (AND/OR/NOT) is assigned to non_ip or ip based on its inner fields.
    """
    domains, non_ip, ip = [], [], []
    for rule in rules:
        if "," not in rule:
            domains.append(rule)
            continue

        prefix = rule.split(",")[0].strip()

        if prefix in LOGICAL_PREFIXES:
            # Already validated by clean_rule, just look up the category
            category = _classify_logical_rule(rule)
            if category == "ip":
                ip.append(rule)
            else:
                non_ip.append(rule)  # "non_ip" or an unexpected None both go to non_ip (None should not reach here)
        elif prefix in IP_PREFIXES:
            ip.append(rule)
        else:
            non_ip.append(rule)

    return domains, non_ip, ip


NON_IP_ORDER = [
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
]

IP_ORDER = [
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "IP-ASN",
    "AND",
    "OR",
    "NOT",
]


def sort_classified(
    domains: list[str],
    non_ip: list[str],
    ip: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """Sort non_ip and ip in the defined order; domains keep their original order."""

    def sort_by_order(rules: list[str], order: list[str]) -> list[str]:
        priority = {p: i for i, p in enumerate(order)}
        return sorted(rules, key=lambda r: priority.get(r.split(",")[0].strip(), len(order)))

    return domains, sort_by_order(non_ip, NON_IP_ORDER), sort_by_order(ip, IP_ORDER)


# ============================================================
# Writing output
# ============================================================


def write_classified(
    domains: list[str],
    non_ip: list[str],
    ip: list[str],
    output_base: str,
    name: str,
    stats: dict,
) -> dict[str, str]:
    category_map = {
        "domains": domains,
        "non_ip": non_ip,
        "ip": ip,
    }

    filename = name if name.endswith(".conf") else name + ".conf"
    written = {}

    build_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    for category, rule_list in category_map.items():
        if not rule_list:
            print(f"  [{category}] empty, skipping generation")
            continue

        out_dir = os.path.join(output_base, "Surge", category)
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, filename)

        header = "\n".join(
            [
                "# ============================================================",
                f"# Surge Rule Set [{category.upper()}] — Auto-generated",
                f"# Group    : {name}",
                f"# Category : {category}",
                f"# Count    : {len(rule_list)}",
                f"# Built    : {build_time}",
                "# ============================================================",
                "",
            ]
        )

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(header)
            f.write("\n".join(rule_list))
            f.write("\n")

        written[category] = out_path
        print(f"  [{category}] {len(rule_list)} rules -> {out_path}")

    return written


def print_stats(stats: dict, name: str):
    print(f"{'=' * 50}")
    print(f"  {name} complete!")
    print(f"{'=' * 50}")
    print(f"  Rule sources          : {stats['sources']}")
    print(f"  Failed sources        : {stats['failed_sources']}")
    print(f"  Raw total lines       : {stats['total_lines']}")
    print(f"  Discarded in cleaning : {stats['discarded']}")
    print(f"  Valid rules (pre-dedup) : {stats['before_dedup']}")
    print(f"  Valid rules (post-dedup): {stats['after_dedup']}")
    print(f"  Excluded rules        : {stats['excluded']}")
    if stats.get("excluded_rules"):
        for r in stats["excluded_rules"]:
            print(f"    - {r}")
    print(f"  Valid rules (final)   : {stats['final']}")
    print(f"  Duplicates removed    : {stats['before_dedup'] - stats['after_dedup']}")
    print(f"{'=' * 50}")


# ============================================================
# Batch config parsing
# ============================================================


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


# ============================================================
# Entry point
# ============================================================


def main():
    parser = argparse.ArgumentParser(description="Surge rule classifier: merge rule sources, split into domains/non_ip/ip outputs")
    parser.add_argument(
        "-b",
        "--batch",
        required=True,
        metavar="BATCH_FILE",
        help="path to the batch config file",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        required=True,
        metavar="DIR",
        help="path to the root of the ccolr/Rule repo",
    )

    args = parser.parse_args()

    all_tasks = parse_batch_file(args.batch)

    tasks = all_tasks

    total = len(tasks)
    success_count = 0
    for idx, (name, urls, group_excludes) in enumerate(tasks, 1):
        print(f"\n{'=' * 50}")
        print(f"  Task [{idx}/{total}]: {name}")
        print(f"{'=' * 50}")
        rules, stats = merge_and_clean(urls, group_excludes)

        if rules is None:
            print(f"[error] task {name} aborted due to a source load failure, skipping output", file=sys.stderr)
            continue

        if not rules:
            print(f"[warning] {name} produced an empty result, skipping", file=sys.stderr)
            continue

        domains, non_ip, ip = classify_rules(rules)
        domains, non_ip, ip = sort_classified(domains, non_ip, ip)
        write_classified(domains, non_ip, ip, args.output_dir, name, stats)
        print_stats(stats, name)
        success_count += 1

    if total > 1:
        print(f"\nAll done, successfully processed {success_count}/{total} group(s)")


if __name__ == "__main__":
    main()
