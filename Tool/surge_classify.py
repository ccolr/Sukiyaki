#!/usr/bin/env python3
"""
Surge Rule Classifier
功能: 合并多个规则源, 清洗去重后按类型拆分为 domains/non_ip/ip 三类
     分别推送至 ccolr/Rule 仓库的 Surge/domains, Surge/non_ip, Surge/ip 目录
"""

import argparse
import os
import sys
import re
import urllib.request
import urllib.error

# ============================================================
# 规则分类定义
# ============================================================
DOMAIN_ONLY_PREFIXES = set()  # 纯域名, 无前缀字段

NON_IP_PREFIXES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "PROCESS-NAME",
    "USER-AGENT",
    "URL-REGEX",
    "PROTOCOL",
    "HOSTNAME-TYPE",
    "AND",
    "OR",
    "NOT",
    "SRC-IP",
    "SUBNET",
    "DEST-PORT",
    "IN-PORT",
    "SRC-PORT",
}

IP_PREFIXES = {
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "IP-ASN",
}

NEED_NO_RESOLVE = {"IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN"}

VALID_PREFIXES = NON_IP_PREFIXES | IP_PREFIXES

_PLAIN_DOMAIN_RE = re.compile(r"^\.?[a-zA-Z0-9][a-zA-Z0-9\-]*(\.[a-zA-Z0-9\-]+)*$")

# ============================================================
# 排除规则列表
# ============================================================
EXCLUDE_RULES: set[str] = {
    rule.upper()
    for rule in [
        # --- 在下方填写要排除的规则 ---
        # --- 结束 ---
    ]
    if rule.strip()
}


# ============================================================
# 清洗逻辑 (与 surge_merge.py 保持一致)
# ============================================================


def strip_inline_comment(line: str) -> str:
    for marker in ("#", "//", ";"):
        pos = line.find(marker)
        if pos != -1:
            line = line[:pos]
    return line.strip()


def clean_rule(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith(";") or line.startswith("//"):
        return None
    line = strip_inline_comment(line)
    line = line.replace("'", " ").replace('"', " ")
    line = line.strip()
    if not line:
        return None
    if "," in line:
        prefix = line.split(",")[0].strip().upper()
        if prefix not in VALID_PREFIXES:
            return None
    else:
        if not _PLAIN_DOMAIN_RE.match(line):
            return None
    return line


def ensure_no_resolve(rule: str) -> str:
    if ",no-resolve" not in rule.lower():
        return rule + ",no-resolve"
    return rule


# ============================================================
# 拉取
# ============================================================


def fetch_content(url: str) -> list[str]:
    print(f"  正在读取: {url}")
    if not url.startswith("http://") and not url.startswith("https://"):
        if not os.path.isfile(url):
            print(f"  [错误] 本地文件不存在: {url}", file=sys.stderr)
            return []
        try:
            with open(url, "r", encoding="utf-8") as f:
                return f.read().splitlines()
        except Exception as e:
            print(f"  [错误] 读取本地文件失败 {url}: {e}", file=sys.stderr)
            return []
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (surge-classify-script)"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("latin-1")
            return text.splitlines()
    except urllib.error.HTTPError as e:
        print(f"  [错误] HTTP {e.code}: {url}", file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"  [错误] 无法访问 {url}: {e.reason}", file=sys.stderr)
    except Exception as e:
        print(f"  [错误] {url}: {e}", file=sys.stderr)
    return []


# ============================================================
# 合并、清洗、去重
# ============================================================


def merge_and_clean(urls: list[str]) -> tuple[list[str], dict]:
    stats = {
        "sources": len(urls),
        "total_lines": 0,
        "discarded": 0,
        "before_dedup": 0,
        "excluded": 0,
        "after_dedup": 0,
    }

    print(f"\n[1/3] 拉取 {len(urls)} 个规则源...")
    all_lines = []
    for url in urls:
        lines = fetch_content(url)
        stats["total_lines"] += len(lines)
        all_lines.extend(lines)

    print(f"\n[2/3] 清洗...")
    cleaned = []
    for line in all_lines:
        result = clean_rule(line)
        if result is None:
            stats["discarded"] += 1
        else:
            cleaned.append(result)
    stats["before_dedup"] = len(cleaned)

    print(f"\n[3/3] 去重并应用排除规则...")
    seen: set[str] = set()
    deduped = []
    for rule in cleaned:
        key = rule.upper()
        if key in EXCLUDE_RULES:
            stats["excluded"] += 1
            continue
        if key not in seen:
            seen.add(key)
            deduped.append(rule)
    stats["after_dedup"] = len(deduped)

    return deduped, stats


# ============================================================
# 分类
# ============================================================


def classify_rules(rules: list[str]) -> tuple[list[str], list[str], list[str]]:
    """
    返回 (domains, non_ip, ip)
    """
    domains, non_ip, ip = [], [], []
    for rule in rules:
        if "," in rule:
            prefix = rule.split(",")[0].strip().upper()
            if prefix in IP_PREFIXES:
                ip.append(ensure_no_resolve(rule))
            else:
                non_ip.append(rule)
        else:
            # 纯域名
            domains.append(rule)
    return domains, non_ip, ip


# ============================================================
# 写出
# ============================================================


def write_classified(
    domains: list[str],
    non_ip: list[str],
    ip: list[str],
    output_base: str,
    name: str,
    urls: list[str],
    stats: dict,
) -> dict[str, str]:
    """
    写出三个分类文件
    output_base: ccolr/Rule 仓库根目录路径
    返回写出的文件路径字典
    """
    category_map = {
        "domains": domains,
        "non_ip": non_ip,
        "ip": ip,
    }

    filename = name if name.endswith(".conf") else name + ".conf"
    written = {}

    source_comment = "\n".join(f"# [{i}] {u}" for i, u in enumerate(urls, 1))

    for category, rule_list in category_map.items():
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
                "# ------------------------------------------------------------",
                source_comment,
                "# ============================================================",
                "",
            ]
        )

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(header)
            f.write("\n".join(rule_list))
            if rule_list:
                f.write("\n")

        written[category] = out_path
        print(f"  [{category}] {len(rule_list)} 条 → {out_path}")

    return written


def print_stats(stats: dict, name: str):
    print(f"\n{'=' * 50}")
    print(f"  {name} 完成!")
    print(f"{'=' * 50}")
    print(f"  规则源数量        : {stats['sources']}")
    print(f"  原始总行数        : {stats['total_lines']}")
    print(f"  清洗丢弃          : {stats['discarded']}")
    print(f"  有效规则(去重前)  : {stats['before_dedup']}")
    print(f"  排除规则          : {stats['excluded']}")
    print(f"  有效规则(去重后)  : {stats['after_dedup']}")
    print(f"{'=' * 50}")


# ============================================================
# 批量配置解析
# ============================================================


def parse_batch_file(batch_path: str) -> list[tuple[str, list[str]]]:
    if not os.path.isfile(batch_path):
        print(f"[错误] 找不到批量配置文件: {batch_path}", file=sys.stderr)
        sys.exit(1)

    groups = []
    current_name = None
    current_sources = []

    with open(batch_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                if current_name is not None:
                    groups.append((current_name, current_sources))
                current_name = line[1:-1].strip()
                current_sources = []
            else:
                if current_name is None:
                    print("[错误] 规则行出现在任何 [分组] 之前", file=sys.stderr)
                    sys.exit(1)
                current_sources.append(line)

    if current_name is not None:
        groups.append((current_name, current_sources))

    if not groups:
        print("[错误] 批量配置文件中未找到任何有效分组", file=sys.stderr)
        sys.exit(1)

    return groups


# ============================================================
# 入口
# ============================================================


def main():
    parser = argparse.ArgumentParser(description="Surge 规则分类工具: 合并规则源, 拆分为 domains/non_ip/ip 三类输出")
    parser.add_argument(
        "-b",
        "--batch",
        required=True,
        metavar="BATCH_FILE",
        help="批量配置文件路径",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        required=True,
        metavar="DIR",
        help="ccolr/Rule 仓库根目录路径",
    )
    parser.add_argument(
        "--only",
        nargs="+",
        metavar="GROUP_NAME",
        help="只处理指定组别名称 (用于增量构建, 空格分隔)",
    )

    args = parser.parse_args()

    all_tasks = parse_batch_file(args.batch)

    # 增量模式: 只处理指定组别
    if args.only:
        only_set = set(args.only)
        tasks = [(n, u) for n, u in all_tasks if n in only_set]
        not_found = only_set - {n for n, _ in tasks}
        if not_found:
            print(f"[警告] 以下组别在配置文件中未找到: {', '.join(not_found)}", file=sys.stderr)
        if not tasks:
            print("[错误] 没有匹配的组别, 退出", file=sys.stderr)
            sys.exit(1)
    else:
        tasks = all_tasks

    total = len(tasks)
    for idx, (name, urls) in enumerate(tasks, 1):
        print(f"\n{'=' * 50}")
        print(f"  任务 [{idx}/{total}]: {name}")
        print(f"{'=' * 50}")

        rules, stats = merge_and_clean(urls)

        if not rules:
            print(f"[警告] {name} 合并结果为空, 跳过", file=sys.stderr)
            continue

        domains, non_ip, ip = classify_rules(rules)
        write_classified(domains, non_ip, ip, args.output_dir, name, urls, stats)
        print_stats(stats, name)

    if total > 1:
        print(f"\n全部完成, 共处理 {total} 个组别")


if __name__ == "__main__":
    main()
