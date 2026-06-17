#!/usr/bin/env python3
"""
Surge Module Fetcher
功能: 根据 surge_modules.txt 拉取 Surge 模块/脚本到 Surge_Modules/ 目录
      - [Original] 区块: 直接拉取, 可重命名
      - [Modified] 区块: 拉取后按 add / delete / replace 规则修改, 可重命名
      - 对 .sgmodule 文件统一注入 #!category=🌸 Sukiyaki
用法: python fetch_modules.py [-i surge_modules.txt] [-o Surge_Modules]

surge_modules.txt 格式:
    [Original]
    <url>                       # 保持原文件名
    <url> <newname>             # 重命名为 newname (无扩展名则沿用原扩展名)

    [Modified]
    <url> [<newname>]
    add: <整行内容>             # 在文件末尾追加一行
    delete: <整行内容>          # 删除内容匹配的行 (子串匹配)
    replace: <原内容> <新内容>  # 将「原内容」子串替换为「新内容」
    <url> [<newname>]           # 下一个模块条目
    ...

add / delete / replace 可任意出现 (含多条), 出现哪条就按哪条改。
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
RETRY_DELAY = 5  # 秒


def fetch_content(url: str, retries: int = MAX_RETRIES, delay: int = RETRY_DELAY) -> str | None:
    """拉取 URL 内容, 返回原始文本 (失败返回 None)。"""
    print(f"  正在拉取: {url}")
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
                print(f"  [重试成功] 第 {attempt} 次尝试成功: {url}")
            return text
        except urllib.error.HTTPError as e:
            print(f"  [错误] HTTP {e.code}: {url}", file=sys.stderr)
            if 400 <= e.code < 500:
                print("  [放弃] 客户端错误, 不再重试", file=sys.stderr)
                return None
        except urllib.error.URLError as e:
            print(f"  [错误] 无法访问 (第 {attempt}/{retries} 次): {url} — {e.reason}", file=sys.stderr)
        except Exception as e:
            print(f"  [错误] 未知错误 (第 {attempt}/{retries} 次): {url} — {e}", file=sys.stderr)

        if attempt < retries:
            print(f"  [重试] {delay} 秒后进行第 {attempt + 1} 次尝试...", file=sys.stderr)
            time.sleep(delay)

    print(f"  [放弃] 已重试 {retries} 次, 仍无法拉取: {url}", file=sys.stderr)
    return None


def resolve_filename(url: str, newname: str | None) -> str:
    """根据 URL 与可选重命名计算输出文件名 (重命名无扩展名时沿用原扩展名)。"""
    orig_base = os.path.basename(url.split("?", 1)[0].split("#", 1)[0])
    orig_ext = os.path.splitext(orig_base)[1]
    if not newname:
        return orig_base
    if os.path.splitext(newname)[1]:
        return newname
    return newname + orig_ext


def parse_modules_file(path: str):
    """解析 surge_modules.txt, 返回 (originals, modified)。

    originals: list[(url, newname|None)]
    modified:  list[(url, newname|None, mods)]，mods = list[(op, value)]
    """
    if not os.path.isfile(path):
        print(f"[错误] 找不到配置文件: {path}", file=sys.stderr)
        sys.exit(1)

    originals: list[tuple[str, str | None]] = []
    modified: list[tuple[str, str | None, list[tuple[str, str]]]] = []

    section = None  # "original" | "modified"
    current_mod = None  # 指向 modified 列表中当前条目的 mods

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
            lower = line.lower()
            if lower.startswith(("add:", "delete:", "replace:")):
                if current_mod is None:
                    print(f"[警告] 修改规则没有对应的模块, 已忽略: {line}", file=sys.stderr)
                    continue
                op, _, value = line.partition(":")
                value = value.strip()
                if value:
                    current_mod.append((op.strip().lower(), value))
            else:
                url, _, name = line.partition(" ")
                mods: list[tuple[str, str]] = []
                modified.append((url, name.strip() or None, mods))
                current_mod = mods

    return originals, modified


def apply_modifications(content: str, mods: list[tuple[str, str]]) -> str:
    """按顺序应用 add / delete / replace 规则。"""
    lines = content.splitlines()
    for op, value in mods:
        if op == "add":
            lines.append(value)
            print(f"    [add] 追加: {value}")
        elif op == "delete":
            before = len(lines)
            lines = [ln for ln in lines if value not in ln]
            print(f"    [delete] 删除 {before - len(lines)} 行 (匹配: {value})")
        elif op == "replace":
            orig, _, repl = value.partition(" ")
            repl = repl.strip()
            text = "\n".join(lines)
            count = text.count(orig)
            text = text.replace(orig, repl)
            lines = text.splitlines()
            print(f"    [replace] 替换 {count} 处: {orig} -> {repl}")
    return "\n".join(lines) + "\n"


def inject_category(content: str) -> str:
    """对 .sgmodule 内容注入/改写 #!category。"""
    lines = content.splitlines()

    # 1) 已存在 #!category -> 改写
    for i, ln in enumerate(lines):
        if ln.lstrip().startswith("#!category"):
            lines[i] = CATEGORY_LINE
            print(f"    [category] 改写已有类别 -> {CATEGORY_VALUE}")
            return "\n".join(lines) + "\n"

    # 2) 无 #!category -> 插入到 #!desc 之后, 否则 #!name 之后
    desc_idx = next((i for i, ln in enumerate(lines) if ln.lstrip().startswith("#!desc")), None)
    name_idx = next((i for i, ln in enumerate(lines) if ln.lstrip().startswith("#!name")), None)
    insert_at = None
    if desc_idx is not None:
        insert_at = desc_idx + 1
    elif name_idx is not None:
        insert_at = name_idx + 1

    if insert_at is not None:
        lines.insert(insert_at, CATEGORY_LINE)
        print(f"    [category] 新增类别 -> {CATEGORY_VALUE}")
    else:
        lines.insert(0, CATEGORY_LINE)
        print(f"    [category] 文件无 #!name/#!desc, 已置顶新增类别 -> {CATEGORY_VALUE}")
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
    print(f"  [完成] -> {out_path}\n")
    return True


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)

    parser = argparse.ArgumentParser(description="拉取并处理 Surge 模块到 Surge_Modules/")
    parser.add_argument("-i", "--input", default=os.path.join(script_dir, "surge_modules.txt"),
                        help="模块清单文件 (默认: Tool/surge_modules.txt)")
    parser.add_argument("-o", "--output", default=os.path.join(repo_root, "Surge_Modules"),
                        help="输出目录 (默认: Surge_Modules/)")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    originals, modified = parse_modules_file(args.input)

    ok = 0
    fail = 0

    print(f"\n=== [Original] 共 {len(originals)} 个 ===")
    for url, name in originals:
        if write_module(url, name, args.output):
            ok += 1
        else:
            fail += 1

    print(f"\n=== [Modified] 共 {len(modified)} 个 ===")
    for url, name, mods in modified:
        if write_module(url, name, args.output, mods):
            ok += 1
        else:
            fail += 1

    print(f"\n=== 完成: 成功 {ok} 个, 失败 {fail} 个, 输出目录: {args.output} ===")
    if fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
