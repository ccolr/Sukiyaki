#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import shutil


def clone_structure(src_dir, dst_dir):
    src = Path(src_dir)
    dst = Path(dst_dir)

    if not src.exists() or not src.is_dir():
        raise ValueError(f"source directory does not exist or is not a directory: {src}")

    # If the target directory already exists, optionally delete it first
    if dst.exists():
        shutil.rmtree(dst)

    for item in src.rglob("*"):
        relative_path = item.relative_to(src)
        target_path = dst / relative_path

        if item.is_dir():
            target_path.mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.touch(exist_ok=True)  # create an empty file with the same name


if __name__ == "__main__":
    source_directory = input("Enter the source directory path: ").strip()
    target_directory = input("Enter the target output directory path: ").strip()

    try:
        clone_structure(source_directory, target_directory)
        print("Directory structure and empty files copied.")
    except Exception as e:
        print(f"Error: {e}")
