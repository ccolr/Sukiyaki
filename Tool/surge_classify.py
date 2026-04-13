#!/usr/bin/env python3
"""
Surge Rule Classifier
功能: 合并多个规则源, 清洗去重后按类型拆分为 domains/non_ip/ip 三类
     分别推送至 ccolr/Rule 仓库的 Surge/domains, Surge/non_ip, Surge/ip 目录
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
# 规则分类定义
# ============================================================
DOMAIN_ONLY_PREFIXES = set()  # 纯域名, 无前缀字段

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

ALL_KNOWN_PREFIXES = NON_IP_PREFIXES | IP_PREFIXES  # logical rule 内部字段白名单

VALID_PREFIXES = NON_IP_PREFIXES | IP_PREFIXES | LOGICAL_PREFIXES

_PLAIN_DOMAIN_RE = re.compile(r"^\.?[a-zA-Z0-9][a-zA-Z0-9\-]*(\.[a-zA-Z0-9\-]+)*$")

# 行内注释匹配：「一个或多个空白字符」+「注释符(# ; //)」+「后面所有内容」
_INLINE_COMMENT_RE = re.compile(r"\s+(#|;|//).*$")

# 匹配 logical rule 括号内的单条子规则，形如 (TYPE,VALUE) 或 (TYPE,VALUE,no-resolve)
# 用于提取内部字段 + 补全 no-resolve
_LOGICAL_INNER_RULE_RE = re.compile(
    r"\(([A-Z0-9\-]+),([^,)]+)(,no-resolve)?\)",
    re.IGNORECASE,
)

# ============================================================
# 排除规则列表
# ============================================================
EXCLUDE_RULES: list[str] = [
    # --- 在下方填写要排除的规则 (正则表达式, 大小写不敏感) ---
    r"7h1s_rul35et_i5_mad3_by_5ukk4w",
    # --- 结束 ---
]


# ============================================================
# 清洗逻辑
# ============================================================


def ensure_no_resolve(rule: str) -> str:
    parts = rule.split(",")
    if parts[-1].strip().lower() != "no-resolve":
        return rule + ",no-resolve"
    return rule


def _extract_logical_inner_prefixes(rule: str) -> set[str]:
    """
    从 logical rule 的括号内容中提取所有子规则的字段名（大写）。
    例: AND,((IP-CIDR,1.1.1.0/24),(DOMAIN-SUFFIX,cn)) → {"IP-CIDR", "DOMAIN-SUFFIX"}
    """
    return {m.group(1).upper() for m in _LOGICAL_INNER_RULE_RE.finditer(rule)}


def _fix_logical_no_resolve(rule: str) -> str:
    """
    对 logical rule 括号内缺少 no-resolve 的 IP 类子规则补全。
    例: (GEOIP,CN) → (GEOIP,CN,no-resolve)
        (GEOIP,CN,no-resolve) → 不变
    """

    def replacer(m: re.Match) -> str:
        type_field = m.group(1).upper()
        value = m.group(2)
        no_resolve = m.group(3)  # 已有则不为 None
        if type_field in NEED_NO_RESOLVE and no_resolve is None:
            return f"({m.group(1)},{value},no-resolve)"
        return m.group(0)  # 原样返回

    return _LOGICAL_INNER_RULE_RE.sub(replacer, rule)


def _classify_logical_rule(rule: str) -> str | None:
    """
    分析 logical rule 内部字段，返回应归属的类别，或 None 表示丢弃。

    - 内部无任何已知字段 → None（丢弃）
    - 内部同时含 non_ip 和 ip 字段 → None（丢弃，混用）
    - 内部仅含 non_ip 字段 → "non_ip"
    - 内部仅含 ip 字段 → "ip"
    """
    inner_prefixes = _extract_logical_inner_prefixes(rule)

    if not inner_prefixes:
        return None  # 没有任何可识别字段

    # 过滤掉嵌套 logical 关键字本身（AND/OR/NOT 可以嵌套）
    known = inner_prefixes - LOGICAL_PREFIXES
    if not known:
        return None  # 仅剩嵌套 logical，没有实际字段

    has_non_ip = bool(known & NON_IP_PREFIXES)
    has_ip = bool(known & IP_PREFIXES)
    unknown_fields = known - NON_IP_PREFIXES - IP_PREFIXES

    if unknown_fields:
        # 含有未知字段，丢弃
        return None
    if has_non_ip and has_ip:
        # 混用，丢弃
        return None
    if has_ip:
        return "ip"
    return "non_ip"


def clean_rule(line: str) -> str | None:
    # 步骤1: 去除首尾空字符
    line = line.strip()

    # 步骤2: 空行或注释直接删除
    if not line:
        return None
    if line.startswith("#") or line.startswith(";") or line.startswith("//"):
        return None
    if "," in line:
        prefix = line.split(",")[0].strip()  # 严格区分大小写
        if prefix not in VALID_PREFIXES:
            return None
    else:
        if not _PLAIN_DOMAIN_RE.match(line):
            return None

    # 步骤3: 去除行内注释
    line = _INLINE_COMMENT_RE.sub("", line).strip()
    if not line:
        return None

    # 步骤4: logical rule 特殊处理
    if "," in line:
        prefix = line.split(",")[0].strip()
        if prefix in LOGICAL_PREFIXES:
            category = _classify_logical_rule(line)
            if category is None:
                return None  # 丢弃：无字段 / 混用 / 含未知字段
            return line

    # 步骤5: 普通规则补全 no-resolve
    if "," in line:
        rule_type = line.split(",")[0].strip()
        if rule_type in NEED_NO_RESOLVE:
            line = ensure_no_resolve(line)

    return line


# ============================================================
# 拉取
# ============================================================


MAX_RETRIES = 3
RETRY_DELAY = 5  # 秒，每次重试间隔


def fetch_content(url: str, retries: int = MAX_RETRIES, delay: int = RETRY_DELAY) -> list[str] | None:
    print(f"  正在读取: {url}")
    if not url.startswith("http://") and not url.startswith("https://"):
        if not os.path.isfile(url):
            print(f"  [错误] 本地文件不存在: {url}", file=sys.stderr)
            return None
        try:
            with open(url, "r", encoding="utf-8") as f:
                return f.read().splitlines()
        except Exception as e:
            print(f"  [错误] 读取本地文件失败 {url}: {e}", file=sys.stderr)
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
                    print(f"  [重试成功] 第 {attempt} 次尝试成功: {url}")
                return text.splitlines()
        except urllib.error.HTTPError as e:
            print(f"  [错误] HTTP {e.code}: {url}", file=sys.stderr)
            if 400 <= e.code < 500:
                print(f"  [放弃] 客户端错误，不再重试", file=sys.stderr)
                return None
        except urllib.error.URLError as e:
            print(f"  [错误] 无法访问 (第 {attempt}/{retries} 次): {url} — {e.reason}", file=sys.stderr)
        except Exception as e:
            print(f"  [错误] 未知错误 (第 {attempt}/{retries} 次): {url} — {e}", file=sys.stderr)

        if attempt < retries:
            print(f"  [重试] {delay} 秒后进行第 {attempt + 1} 次尝试...", file=sys.stderr)
            time.sleep(delay)

    print(f"  [放弃] 已重试 {retries} 次，仍无法读取: {url}", file=sys.stderr)
    return None


# ============================================================
# 合并、清洗、去重
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

    print(f"\n[1/4] 拉取 {len(urls)} 个规则源...")
    all_lines = []
    for url in urls:
        lines = fetch_content(url)
        if lines is None:
            print(f"\n[错误] 源 {url} 读取失败，终止当前任务以避免规则集不完整", file=sys.stderr)
            return None, stats
        stats["total_lines"] += len(lines)
        all_lines.extend(lines)

    print(f"\n[2/4] 清洗（去首尾空白 → 过滤非法行 → 去行内注释 → logical 规则校验 → 补全 no-resolve）...")
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
            print(f"[警告] 全局排除规则正则有误 ({pattern_str!r}): {e}", file=sys.stderr)
    all_patterns = global_patterns + (group_excludes or [])
    stats["before_dedup"] = len(cleaned)

    print(f"\n[3/4] 去重（严格区分大小写）...")
    seen: set[str] = set()
    deduped: list[str] = []
    for rule in cleaned:
        if rule not in seen:
            seen.add(rule)
            deduped.append(rule)
    stats["after_dedup"] = len(deduped)

    print(f"\n[4/4] 应用排除规则...")
    final: list[str] = []
    for rule in deduped:
        if any(p.search(rule) for p in all_patterns):
            stats["excluded"] += 1
            stats["excluded_rules"].append(rule)
            continue
        final.append(rule)
    stats["final"] = len(final)

    # [5/5] 对存活的 logical rule 补全括号内 no-resolve（排除后再做，避免无效计算）
    print(f"\n[5/5] 补全 logical rule 括号内 no-resolve...")
    final = [
        _fix_logical_no_resolve(rule) if rule.split(",")[0].strip() in LOGICAL_PREFIXES else rule for rule in final
    ]

    return final, stats


# ============================================================
# 分类
# ============================================================


def classify_rules(rules: list[str]) -> tuple[list[str], list[str], list[str]]:
    """
    返回 (domains, non_ip, ip)
    logical rule (AND/OR/NOT) 根据内部字段归属到 non_ip 或 ip
    """
    domains, non_ip, ip = [], [], []
    for rule in rules:
        if "," not in rule:
            domains.append(rule)
            continue

        prefix = rule.split(",")[0].strip()

        if prefix in LOGICAL_PREFIXES:
            # clean_rule 已校验通过，直接查归属
            category = _classify_logical_rule(rule)
            if category == "ip":
                ip.append(rule)
            else:
                non_ip.append(rule)  # "non_ip" 或意外的 None 都归 non_ip（理论上 None 不会到这里）
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
    """对 non_ip 和 ip 按规定顺序排序, domains 保持原序"""

    def sort_by_order(rules: list[str], order: list[str]) -> list[str]:
        priority = {p: i for i, p in enumerate(order)}
        return sorted(rules, key=lambda r: priority.get(r.split(",")[0].strip(), len(order)))

    return domains, sort_by_order(non_ip, NON_IP_ORDER), sort_by_order(ip, IP_ORDER)


# ============================================================
# 写出
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
            print(f"  [{category}] 为空, 跳过生成")
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
        print(f"  [{category}] {len(rule_list)} 条 → {out_path}")

    return written


def print_stats(stats: dict, name: str):
    print(f"{'=' * 50}")
    print(f"  {name} 完成!")
    print(f"{'=' * 50}")
    print(f"  规则源数量        : {stats['sources']}")
    print(f"  读取失败源        : {stats['failed_sources']}")
    print(f"  原始总行数        : {stats['total_lines']}")
    print(f"  清洗丢弃          : {stats['discarded']}")
    print(f"  有效规则(去重前)  : {stats['before_dedup']}")
    print(f"  有效规则(去重后)  : {stats['after_dedup']}")
    print(f"  排除规则          : {stats['excluded']}")
    if stats.get("excluded_rules"):
        for r in stats["excluded_rules"]:
            print(f"    - {r}")
    print(f"  有效规则(最终)    : {stats['final']}")
    print(f"  重复去除          : {stats['before_dedup'] - stats['after_dedup']}")
    print(f"{'=' * 50}")


# ============================================================
# 批量配置解析
# ============================================================


def parse_batch_file(batch_path: str) -> list[tuple[str, list[str], list[re.Pattern]]]:
    if not os.path.isfile(batch_path):
        print(f"[错误] 找不到批量配置文件: {batch_path}", file=sys.stderr)
        sys.exit(1)

    groups = []
    current_name = None
    current_sources = []
    current_excludes = []
    phase = "sources"

    with open(batch_path, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            print(f"[调试] 第{lineno}行 repr: {repr(raw)}", file=sys.stderr)
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("[") and line.endswith("]"):
                if current_name is not None:
                    if not current_sources:
                        print(f"[错误] 组别 [{current_name}] 没有任何规则源", file=sys.stderr)
                        sys.exit(1)
                    groups.append((current_name, current_sources, current_excludes))
                current_name = line[1:-1].strip()
                current_sources = []
                current_excludes = []
                phase = "sources"

            elif line.startswith("EXCLUDE:"):
                if phase == "sources" and not current_sources:
                    print(
                        f"[错误] 第 {lineno} 行: 排除规则出现在任何源地址之前 (组别: {current_name})", file=sys.stderr
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
                        f"[错误] 第 {lineno} 行: 正则表达式有误 ({pattern_str!r}): {e} (组别: {current_name})",
                        file=sys.stderr,
                    )
                    sys.exit(1)

            else:
                if current_name is None:
                    print(f"[错误] 第 {lineno} 行: 规则行出现在任何 [分组] 之前", file=sys.stderr)
                    sys.exit(1)
                if phase == "excludes":
                    print(f"[错误] 第 {lineno} 行: 源地址出现在排除规则之后 (组别: {current_name})", file=sys.stderr)
                    sys.exit(1)
                current_sources.append(line)

    if current_name is not None:
        if not current_sources:
            print(f"[错误] 组别 [{current_name}] 没有任何规则源", file=sys.stderr)
            sys.exit(1)
        groups.append((current_name, current_sources, current_excludes))

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

    args = parser.parse_args()

    all_tasks = parse_batch_file(args.batch)

    tasks = all_tasks

    total = len(tasks)
    success_count = 0
    for idx, (name, urls, group_excludes) in enumerate(tasks, 1):
        print(f"\n{'=' * 50}")
        print(f"  任务 [{idx}/{total}]: {name}")
        print(f"{'=' * 50}")
        rules, stats = merge_and_clean(urls, group_excludes)

        if rules is None:
            print(f"[错误] 任务 {name} 因源读取失败而终止，跳过输出", file=sys.stderr)
            continue

        if not rules:
            print(f"[警告] {name} 合并结果为空, 跳过", file=sys.stderr)
            continue

        domains, non_ip, ip = classify_rules(rules)
        domains, non_ip, ip = sort_classified(domains, non_ip, ip)
        write_classified(domains, non_ip, ip, args.output_dir, name, stats)
        print_stats(stats, name)
        success_count += 1

    if total > 1:
        print(f"\n全部完成, 成功处理 {success_count}/{total} 个组别")


if __name__ == "__main__":
    main()
