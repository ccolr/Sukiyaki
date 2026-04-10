#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import shutil


def clone_structure(src_dir, dst_dir):
    src = Path(src_dir)
    dst = Path(dst_dir)

    if not src.exists() or not src.is_dir():
        raise ValueError(f"源目录不存在或不是目录: {src}")

    # 如果目标目录已存在，可选先删除
    if dst.exists():
        shutil.rmtree(dst)

    for item in src.rglob("*"):
        relative_path = item.relative_to(src)
        target_path = dst / relative_path

        if item.is_dir():
            target_path.mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.touch(exist_ok=True)  # 创建空同名文件


if __name__ == "__main__":
    source_directory = input("请输入源目录路径: ").strip()
    target_directory = input("请输入目标输出目录路径: ").strip()

    try:
        clone_structure(source_directory, target_directory)
        print("目录结构和空文件复制完成。")
    except Exception as e:
        print(f"错误: {e}")
