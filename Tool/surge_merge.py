#!/usr/bin/env python3
"""
Surge Rule Merger
功能: 合并多个 Surge 规则集文件 (.conf/.list), 清洗注释和空行, 去重, 输出 .conf 文件
用法: python surge_merge.py -u <url1> <url2> ... -o <output_dir> -n <filename>
"""

import re
import argparse
import os
import sys
import urllib.request
import urllib.error
import time

# ============================================================
# 排除规则列表 — 引号内写正则表达式
EXCLUDE_RULES: list[str] = [
    # --- 在下方填写要排除的规则 (正则表达式, 大小写不敏感) ---
    r"7h1s_rul35et_i5_mad3_by_5ukk4w",
    # --- 结束 ---
]
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
            # 4xx 错误重试无意义，直接放弃
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


# 合法的规则类型前缀（区分大小写，必须严格匹配）
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

# 纯域名：只允许字母/数字/"-"/"."，可以以"."开头
_PLAIN_DOMAIN_RE = re.compile(r"^\.?[a-zA-Z0-9][a-zA-Z0-9\-]*(\.[a-zA-Z0-9\-]+)*$")

# 行内注释匹配：「一个或多个空白字符」+「注释符(# ; //)」+「后面所有内容」
# 注释符必须紧跟在空白字符后面，防止误截断域名或规则内容中的 # 字符
_INLINE_COMMENT_RE = re.compile(r"\s+(#|;|//).*$")

# 规则类型优先级顺序
RULE_ORDER = [
    "SUBNET",
    "SRC-IP",
    "SRC-PORT",
    "IN-PORT",
    "DEST-PORT",
    "PROTOCOL",
    "PLAIN_DOMAIN",  # 纯域名 / . 开头
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
    """为需要 no-resolve 的规则补全后缀（大小写严格，统一补全为小写 no-resolve）"""
    # 检查时忽略大小写，但补全时统一使用小写
    parts = rule.split(",")
    if parts[-1].strip().lower() != "no-resolve":
        return rule + ",no-resolve"
    return rule


def clean_rule(line: str) -> str | None:
    """
    严格按以下顺序处理每一行：
    1. 去除首尾空字符
    2. 空行 或 非指定类别开头 → 直接删除（返回 None）
    3. 去除行内注释（[空字符+注释符]结构及其后内容）
    4. 补全 no-resolve
    """
    # 步骤 1：去除首尾空字符
    line = line.strip()

    # 步骤 2：空行直接删除
    if not line:
        return None

    # 步骤 2：整行注释（行首就是注释符）→ 非指定类别，直接删除
    if line.startswith("#") or line.startswith(";") or line.startswith("//"):
        return None

    # 步骤 2：验证规则前缀（严格区分大小写，不做任何大小写转换）
    if "," in line:
        # 含逗号：取逗号前的部分作为前缀，严格匹配 VALID_PREFIXES
        prefix = line.split(",")[0].strip()
        if prefix not in VALID_PREFIXES:
            return None
    else:
        # 不含逗号：必须是合法的纯域名格式
        if not _PLAIN_DOMAIN_RE.match(line):
            return None

    # 步骤 3：去除行内注释
    # 匹配「一个或多个空白」+「# 或 ; 或 //」+「之后所有内容」
    line = _INLINE_COMMENT_RE.sub("", line).strip()
    if not line:
        return None

    # 步骤 4：补全 no-resolve（仅针对需要的规则类型）
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
        "after_dedup": 0,  # 去重后、排除前
        "excluded": 0,
        "excluded_rules": [],
        "failed_sources": 0,
        "final": 0,  # 排除后的最终数量
    }

    # 全局排除规则转为正则
    global_patterns = []
    for pattern_str in EXCLUDE_RULES:
        try:
            global_patterns.append(re.compile(pattern_str, re.IGNORECASE))
        except re.error as e:
            print(f"[警告] 全局排除规则正则有误 ({pattern_str!r}): {e}", file=sys.stderr)
    all_patterns = global_patterns + (group_excludes or [])

    print(f"\n[1/5] 拉取 {len(urls)} 个规则源...")
    for url in urls:
        lines = fetch_content(url)
        if lines is None:
            print(f"\n[错误] 源 {url} 读取失败，终止当前任务以避免规则集不完整", file=sys.stderr)
            return None, stats
        stats["total_lines"] += len(lines)
        all_lines.extend(lines)

    print(f"\n[2/5] 清洗（去首尾空白 → 过滤非法行 → 去行内注释 → 补全 no-resolve）...")
    cleaned: list[str] = []
    for line in all_lines:
        result = clean_rule(line)
        if result is None:
            stats["comment_or_empty"] += 1
        else:
            cleaned.append(result)
    stats["before_dedup"] = len(cleaned)

    print(f"\n[3/5] 去重（严格区分大小写）...")
    seen: set[str] = set()
    deduped: list[str] = []
    for rule in cleaned:
        if rule not in seen:
            seen.add(rule)
            deduped.append(rule)
    stats["after_dedup"] = len(deduped)  # ← 这里记录真正的去重后数量

    print(f"\n[4/5] 应用排除规则...")
    final: list[str] = []
    for rule in deduped:
        if any(p.search(rule) for p in all_patterns):
            stats["excluded"] += 1
            stats["excluded_rules"].append(rule)
            continue
        final.append(rule)
    stats["final"] = len(final)  # ← 这里记录排除后数量

    print(f"\n[5/5] 按规则类型排序...")
    sorted_rules = sort_rules(final)

    return sorted_rules, stats


def get_rule_type(rule: str) -> str:
    """识别规则类型（严格区分大小写）"""
    stripped = rule.strip()
    if not stripped:
        return "UNKNOWN"
    # 不含逗号，或以 "." 开头 → 纯域名
    if "," not in stripped or stripped.startswith("."):
        return "PLAIN_DOMAIN"
    prefix = stripped.split(",")[0].strip()  # 不做大小写转换
    return prefix if prefix in RULE_ORDER else "UNKNOWN"


def sort_rules(rules: list[str]) -> list[str]:
    """按规则类型排序（no-resolve 已在 clean_rule 阶段处理，此处不再重复）"""
    priority = {rtype: i for i, rtype in enumerate(RULE_ORDER)}

    processed = []
    for rule in rules:
        rtype = get_rule_type(rule)
        processed.append((priority.get(rtype, len(RULE_ORDER)), rule))

    processed.sort(key=lambda x: x[0])
    return [rule for _, rule in processed]


def write_output(rules: list[str], output_dir: str, filename: str, urls: list[str], stats: dict) -> str:
    """写出 .conf 文件, 自动补全 .conf 后缀"""
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
    print("  合并完成!")
    print("=" * 50)
    print(f"  规则源数量        : {stats['sources']}")
    print(f"  读取失败源        : {stats['failed_sources']}")
    print(f"  原始总行数        : {stats['total_lines']}")
    print(f"  注释/空行/非法    : {stats['comment_or_empty']}")
    print(f"  有效规则(去重前)  : {stats['before_dedup']}")
    print(f"  有效规则(去重后)  : {stats['after_dedup']}")  # 现在语义准确
    print(f"  排除规则          : {stats.get('excluded', 0)}")
    if stats.get("excluded_rules"):
        for r in stats["excluded_rules"]:
            print(f"    - {r}")
    print(f"  有效规则(最终)    : {stats['final']}")
    print(f"  重复去除          : {stats['before_dedup'] - stats['after_dedup']}")  # 不再混入 excluded
    print(f"  输出文件          : {output_path}")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(
        description="Surge 规则集合并工具: 合并多个 .conf/.list 规则源, 去重后输出 .conf 文件",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python surge_merge.py \\
    -u https://example.com/rules1.list https://example.com/rules2.conf \\
    -o ./output \\
    -n my_rules

  # 也可以从文件读取 URL 列表 (每行一个 URL):
  python surge_merge.py -f urls.txt -o ./output -n merged
        """,
    )

    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "-u", "--urls", nargs="+", metavar="URL_OR_PATH", help="一个或多个规则集 URL 或本地文件路径 (空格分隔, 可混用)"
    )
    source_group.add_argument(
        "-f", "--file", metavar="URL_FILE", help="包含 URL 列表的文本文件 (每行一个 URL, # 开头为注释)"
    )
    source_group.add_argument(
        "-b", "--batch", metavar="BATCH_FILE", help="批量配置文件, 用 [文件名] 分组, 每行一个 URL 或本地路径"
    )

    parser.add_argument("-o", "--output-dir", required=True, metavar="DIR", help="输出目录 (不存在会自动创建)")
    parser.add_argument(
        "-n", "--name", required=False, default=None, metavar="FILENAME", help="输出文件名 (无需包含 .conf 后缀)"
    )

    args = parser.parse_args()

    # 收集任务列表: [(output_name, [urls])]
    if args.urls:
        if not args.name:
            print("[错误] 单组模式下 -n/--name 为必填项", file=sys.stderr)
            sys.exit(1)
        tasks = [(args.name, args.urls)]
    elif args.file:
        if not os.path.isfile(args.file):
            print(f"[错误] 找不到 URL 文件: {args.file}", file=sys.stderr)
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        if not urls:
            print("[错误] URL 文件为空或全为注释", file=sys.stderr)
            sys.exit(1)
        if not args.name:
            print("[错误] 单组模式下 -n/--name 为必填项", file=sys.stderr)
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
        print(f"  任务 [{idx}/{total}]: {name}")
        print(f"{'=' * 50}")

        rules, stats = merge_rules(urls, group_excludes)

        if rules is None:
            print(f"[错误] 任务 {name} 因源读取失败而终止，跳过输出", file=sys.stderr)
            continue

        if not rules:
            print(f"\n[警告] 任务 {name} 合并结果为空, 跳过", file=sys.stderr)
            continue

        output_path = write_output(rules, args.output_dir, name, urls, stats)
        print_stats(stats, output_path)
        success_count += 1

    if total > 1:
        print(f"\n所有任务完成, 共生成 {success_count}/{total} 个文件, 输出目录: {args.output_dir}")


if __name__ == "__main__":
    main()
