#!/usr/bin/python3
# Copyright (c) 2026 AWA <https://www.akkdiy.cn>. All rights reserved.
"""主机目录压缩备份：把本机某个同步目录打成 tar.gz，放进另一个目录，按份数轮转。

为什么不复用同步引擎
--------------------
同步解决的是「两台机器保持一致」，这里解决的是「本机留历史快照」：同一份数据
可能被另一端的旧版本覆盖，只有压缩包才是时间点上的原始副本。所以它独立于
同步流程，只在本机执行，出问题也不会影响同步结果。

命名规则
--------
`<源目录名>-YYYYmmdd-HHMMSS.tar.gz`，前缀固定，轮转时只清理自己产生的文件，
备份目录里用户放的其它东西一概不碰。
"""

import fnmatch
import os
import shutil
import subprocess
import tarfile
import time

import common

TAR_BIN = shutil.which("tar") or "/bin/tar"

# 与同步引擎一致的排除项：@eaDir 里是缩略图，回收站里是待删文件，
# 打包它们既慢又没意义，还会让压缩包膨胀好几倍。
BASE_EXCLUDES = ["@eaDir", "#recycle", "#snapshot", "@tmp", common.TRASH_NAME]

ARCHIVE_TIMEOUT = 6 * 3600


class ArchiveError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# 命名与列举
# --------------------------------------------------------------------------
def archive_prefix(source):
    base = os.path.basename((source or "/").rstrip("/"))
    return base or "root"


def archive_name(source, when=None):
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(when if when is not None else time.time()))
    return "%s-%s.tar.gz" % (archive_prefix(source), stamp)


def list_archives(source, target_dir):
    """列出该源目录的备份，最新的排在前面。"""
    prefix = archive_prefix(source)
    try:
        with os.scandir(target_dir) as entries:
            raw = list(entries)
    except OSError:
        return []
    items = []
    for entry in raw:
        if not (entry.name.startswith(prefix + "-") and entry.name.endswith(".tar.gz")):
            continue
        try:
            info = entry.stat()
        except OSError:
            continue
        items.append({
            "name": entry.name,
            "path": entry.path,
            "size": info.st_size,
            "mtime": int(info.st_mtime),
        })
    items.sort(key=lambda item: (item["mtime"], item["name"]), reverse=True)
    return items


# --------------------------------------------------------------------------
# 打包
# --------------------------------------------------------------------------
def _clean_patterns(excludes):
    patterns = []
    for item in list(excludes or []) + BASE_EXCLUDES:
        pattern = (item or "").strip().rstrip("/")
        if pattern and pattern not in patterns:
            patterns.append(pattern)
    return patterns


def _run_tar(parent, base, output, patterns, timeout=ARCHIVE_TIMEOUT):
    # Windows 上（仅本地调试）tar 不认 C:/ 这样的盘符路径，直接走 Python 兜底；
    # DSM 上始终是 Linux，用系统 tar 更快也更省内存。
    if os.name != "nt" and os.path.exists(TAR_BIN):
        args = [TAR_BIN, "-czf", output, "-C", parent]
        for pattern in patterns:
            args.append("--exclude=" + pattern)
        args.append(base)
        try:
            proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise ArchiveError("打包超时（超过 %d 小时）" % (timeout // 3600))
        except OSError as exc:
            raise ArchiveError("无法执行 tar：%s" % exc)
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            raise ArchiveError("打包失败：" + ((detail[-1] if detail else "tar 代码 " + str(proc.returncode))[:300]))
        return

    # 没有 tar 的环境（本地调试）用 Python 实现兜底，行为与 tar 一致
    def skipped(rel):
        base_name = rel.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(base_name, p) for p in patterns)

    root = os.path.join(parent, base)
    try:
        with tarfile.open(output, "w:gz") as handle:
            for dirpath, dirnames, filenames in os.walk(root):
                rel_dir = os.path.relpath(dirpath, root)
                prefix = "" if rel_dir == "." else rel_dir.replace(os.sep, "/") + "/"
                dirnames[:] = [d for d in dirnames if not skipped(prefix + d)]
                for name in filenames:
                    rel = prefix + name
                    if skipped(rel):
                        continue
                    handle.add(os.path.join(dirpath, name), arcname=base + "/" + rel, recursive=False)
    except (OSError, tarfile.TarError) as exc:
        raise ArchiveError("打包失败：%s" % exc)


def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def create_archive(source, target_dir, keep=7, excludes=()):
    """把 source 目录打包成 target_dir 下的 tar.gz，并按份数清理旧包。

    返回 {"name","path","size","keep","removed"}；失败抛 ArchiveError。
    """
    source = (source or "").rstrip("/")
    target_dir = (target_dir or "").rstrip("/")
    if not source or not os.path.isdir(source):
        raise ArchiveError("本机目录不可用：" + (source or "（未设置）"))
    if not target_dir:
        raise ArchiveError("还没有设置备份目录")
    if common.paths_overlap(source, target_dir):
        raise ArchiveError("备份目录不能和本机同步目录重叠：" + target_dir)
    parent, base = os.path.split(source)
    if not base:
        raise ArchiveError("不能直接备份根目录 /")

    try:
        os.makedirs(target_dir, exist_ok=True)
    except OSError as exc:
        raise ArchiveError("无法创建备份目录 %s：%s" % (target_dir, exc))

    final = os.path.join(target_dir, archive_name(source))
    temp = final + ".part"
    try:
        _run_tar(parent, base, temp, _clean_patterns(excludes))
        os.replace(temp, final)
    except Exception:
        _unlink(temp)
        raise

    try:
        size = os.path.getsize(final)
    except OSError:
        size = 0
    removed = prune(source, target_dir, keep, keep_path=final)
    return {"name": os.path.basename(final), "path": final, "size": size,
            "keep": int(keep or 7), "removed": removed}


def prune(source, target_dir, keep, keep_path=None):
    """只保留最新的 keep 份，返回删掉的份数。刚打好的包永远不删。"""
    try:
        keep = max(1, int(keep))
    except (TypeError, ValueError):
        keep = 7
    items = list_archives(source, target_dir)
    removed = 0
    for item in items[keep:]:
        if keep_path and os.path.abspath(item["path"]) == os.path.abspath(keep_path):
            continue
        try:
            os.unlink(item["path"])
            removed += 1
        except OSError:
            continue
    return removed
