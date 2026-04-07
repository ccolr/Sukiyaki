#!/usr/bin/env python3
"""
Surge Rule Merger
功能: 合并多个 Surge 规则集文件 (.conf/.list), 清洗注释和空行, 去重, 输出 .conf 文件
用法: python surge_merge.py -u <url1> <url2> ... -o <output_dir> -n <filename>
"""

import argparse
import os
import sys
import urllib.request
import urllib.error

# ============================================================
# 排除规则列表 — 在此处填写需要从最终输出中剔除的规则
# 每行一条, 与规则集中的格式保持一致, 大小写不敏感
# 示例:
#   DOMAIN-SUFFIX,example.com,DIRECT
#   IP-CIDR,192.168.0.0/16,DIRECT
EXCLUDE_RULES: set[str] = {
    rule.upper()
    for rule in [
        # --- 在下方填写要排除的规则 ---
        "7h1s_rul35et_i5_mad3_by_5ukk4w-ruleset.skk.moe",
        "DOMAIN,7h1s_rul35et_i5_mad3_by_5ukk4w-ruleset.skk.moe",
        # --- 结束 ---
    ]
    if rule.strip()
}
# ============================================================


def fetch_content(url: str) -> list[str]:
    """从 URL 或本地路径获取文件内容, 返回行列表"""
    print(f"  正在读取: {url}")

    # 本地文件
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

    # 远程 URL (原有逻辑不变)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (surge-merge-script)"})
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


def parse_batch_file(batch_path: str) -> list[tuple[str, list[str]]]:
    """
    解析批量配置文件
    返回: [(output_name, [url_or_path, ...]), ...]
    """
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
                    print(f"[错误] 配置文件格式错误: 规则行出现在任何 [分组] 之前", file=sys.stderr)
                    sys.exit(1)
                current_sources.append(line)

    if current_name is not None:
        groups.append((current_name, current_sources))

    if not groups:
        print("[错误] 批量配置文件中未找到任何有效分组", file=sys.stderr)
        sys.exit(1)

    return groups


def is_comment_or_empty(line: str) -> bool:
    """判断是否为注释行或空行"""
    stripped = line.strip()
    return stripped == "" or stripped.startswith("#") or stripped.startswith(";") or stripped.startswith("//")


# 合法的规则类型前缀
VALID_PREFIXES = {
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
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "IP-ASN",
    "SRC-IP",
    "SUBNET",
    "DEST-PORT",
    "IN-PORT",
    "SRC-PORT",
}

import re

# 纯域名: 只允许字母开头或 "." 开头, 且只包含字母/数字/"-"/"."
# 不允许连续两个 ".", 不允许除上述字符之外的其他字符
_PLAIN_DOMAIN_RE = re.compile(r"^\.?[a-zA-Z0-9][a-zA-Z0-9\-]*(\.[a-zA-Z0-9\-]+)*$")


def strip_inline_comment(line: str) -> str:
    """去除行尾注释: 支持 #, //, ; 风格"""
    # 按顺序尝试, 取最早出现的注释符位置
    # 但要避免误伤规则内容本身(规则内容不含这些符号, 所以直接切割是安全的)
    for marker in ("#", "//", ";"):
        pos = line.find(marker)
        if pos != -1:
            line = line[:pos]
    return line.strip()


def clean_rule(line: str) -> str | None:
    """
    清洗单行规则, 返回清洗后的规则字符串, 或 None 表示丢弃该行
    处理顺序:
      1. 去除前后空格
      2. 跳过空行和整行注释
      3. 去除行尾注释
      4. 将引号替换为空格
      5. 再次去除前后空格
      6. 校验规则类型, 不合法则丢弃
    """
    # 1. 去除前后空格
    line = line.strip()

    # 2. 跳过空行和整行注释
    if not line or line.startswith("#") or line.startswith(";") or line.startswith("//"):
        return None

    # 3. 去除行尾注释
    line = strip_inline_comment(line)

    # 4. 引号转空格
    line = line.replace("'", " ").replace('"', " ")

    # 5. 再次清理空格
    line = line.strip()

    if not line:
        return None

    # 6. 校验规则类型
    if "," in line:
        # 有逗号: 取第一个字段作为类型
        prefix = line.split(",")[0].strip().upper()
        if prefix not in VALID_PREFIXES:
            return None
    else:
        # 无逗号: 必须是合法的纯域名
        if not _PLAIN_DOMAIN_RE.match(line):
            return None

    return line


def merge_rules(urls: list[str]) -> tuple[list[str], dict]:
    """
    拉取所有 URL 内容并合并规则
    返回: (去重后的有序规则列表, 统计信息)
    """
    all_lines: list[str] = []
    stats = {
        "sources": len(urls),
        "total_lines": 0,
        "comment_or_empty": 0,
        "before_dedup": 0,
        "after_dedup": 0,
    }

    print(f"\n[1/3] 拉取 {len(urls)} 个规则源...")
    for url in urls:
        lines = fetch_content(url)
        stats["total_lines"] += len(lines)
        all_lines.extend(lines)

    print(f"\n[2/4] 清洗注释、空行、行尾注释及非法规则...")
    cleaned: list[str] = []
    discarded = 0
    for line in all_lines:
        result = clean_rule(line)
        if result is None:
            stats["comment_or_empty"] += 1
        else:
            cleaned.append(result)

    stats["before_dedup"] = len(cleaned)

    print(f"\n[3/3] 去重并应用排除规则...")
    seen: set[str] = set()
    deduped: list[str] = []
    excluded_count = 0
    for rule in cleaned:
        key = rule.upper()
        if key in EXCLUDE_RULES:
            excluded_count += 1
            continue
        if key not in seen:
            seen.add(key)
            deduped.append(rule)

    stats["after_dedup"] = len(deduped)
    stats["excluded"] = excluded_count

    print(f"\n[4/4] 按规则类型排序并补全 no-resolve...")
    sorted_rules = sort_rules(deduped)

    stats["after_dedup"] = len(sorted_rules)
    stats["excluded"] = excluded_count
    return sorted_rules, stats


# 规则类型优先级顺序
RULE_ORDER = [
    "PLAIN_DOMAIN",  # 纯域名 / . 开头
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
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "IP-ASN",
    "SRC-IP",
    "SUBNET",
    "DEST-PORT",
    "IN-PORT",
    "SRC-PORT",
]

NEED_NO_RESOLVE = {"IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN"}


def get_rule_type(rule: str) -> str:
    """识别规则类型"""
    stripped = rule.strip()
    if not stripped:
        return "UNKNOWN"
    # 纯域名: 不含逗号, 或以 "." 开头
    if "," not in stripped or stripped.startswith("."):
        return "PLAIN_DOMAIN"
    prefix = stripped.split(",")[0].upper()
    return prefix if prefix in RULE_ORDER else "UNKNOWN"


def ensure_no_resolve(rule: str) -> str:
    """为需要 no-resolve 的规则补全后缀"""
    if ",no-resolve" not in rule.lower():
        return rule + ",no-resolve"
    return rule


def sort_rules(rules: list[str]) -> list[str]:
    """按规则类型排序, 并为 IP 类规则补全 no-resolve"""
    priority = {rtype: i for i, rtype in enumerate(RULE_ORDER)}

    processed = []
    for rule in rules:
        rtype = get_rule_type(rule)
        if rtype in NEED_NO_RESOLVE:
            rule = ensure_no_resolve(rule)
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
        f"# Total    : {stats['after_dedup']} rules",
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
    print(f"  规则源数量      : {stats['sources']}")
    print(f"  原始总行数      : {stats['total_lines']}")
    print(f"  注释/空行/非法  : {stats['comment_or_empty']}")
    print(f"  有效规则(去重前) : {stats['before_dedup']}")
    print(f"  排除规则        : {stats.get('excluded', 0)}")
    print(f"  有效规则(去重后) : {stats['after_dedup']}")
    print(f"  重复去除        : {stats['before_dedup'] - stats['after_dedup'] - stats.get('excluded', 0)}")
    print(f"  输出文件        : {output_path}")
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

    # 批量执行
    total = len(tasks)
    for idx, (name, urls) in enumerate(tasks, 1):
        print(f"\n{'=' * 50}")
        print(f"  任务 [{idx}/{total}]: {name}")
        print(f"{'=' * 50}")

        rules, stats = merge_rules(urls)

        if not rules:
            print(f"\n[警告] 任务 {name} 合并结果为空, 跳过", file=sys.stderr)
            continue

        output_path = write_output(rules, args.output_dir, name, urls, stats)
        print_stats(stats, output_path)

    if total > 1:
        print(f"\n所有任务完成, 共生成 {total} 个文件, 输出目录: {args.output_dir}")


if __name__ == "__main__":
    main()
