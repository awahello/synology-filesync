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
默认 `<源目录名>-YYYYmmdd-HHMMSS.zip`（Windows 上双击即可打开，不用额外解压工具）；
前缀固定，轮转时只清理自己产生的文件，备份目录里用户放的其它东西一概不碰。
也兼容旧的 `.tar.gz` 包（列举与轮转时一并识别）。
"""

import fnmatch
import os
import shutil
import subprocess
import tarfile
import time
import zipfile

import common

TAR_BIN = shutil.which("tar") or "/bin/tar"

# 备份格式：zip（默认，Windows 上直接双击可开）或 tar.gz
FORMAT_EXT = {"zip": ".zip", "tar": ".tar.gz"}
DEFAULT_FORMAT = "zip"
ARCHIVE_EXTS = (".zip", ".tar.gz")

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


def archive_name(source, fmt=DEFAULT_FORMAT, when=None):
    ext = FORMAT_EXT.get(fmt or DEFAULT_FORMAT, ".zip")
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(when if when is not None else time.time()))
    return "%s-%s%s" % (archive_prefix(source), stamp, ext)


def list_archives(source, target_dir):
    """列出该源目录的备份（zip 与 tar.gz 都算），最新的排在前面。"""
    prefix = archive_prefix(source)
    try:
        with os.scandir(target_dir) as entries:
            raw = list(entries)
    except OSError:
        return []
    items = []
    for entry in raw:
        if not (entry.name.startswith(prefix + "-") and entry.name.endswith(ARCHIVE_EXTS)):
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


def _free_space(path):
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return None


def _tar_error(lines, returncode, target_dir):
    """把 tar 的原始报错翻译成用户能看懂的话。

    `Wrote only 4096 of 10240 bytes` / `No space left on device` /
    `Disk quota exceeded` 都是「写不进去」——磁盘满或用户配额满，
    和权限、路径无关，所以单独给一句明确的提示。
    """
    text = " ".join(lines).lower()
    if ("no space left" in text or "wrote only" in text
            or "disk quota exceeded" in text or "quota" in text):
        free = _free_space(target_dir)
        extra = "（备份目录所在卷当前剩余 %s）" % common.human_size(free) if free is not None else ""
        return ("备份目录空间不足或用户配额已满%s。请清理空间、把「保留份数」调小，"
                "或把备份目录换到空间更大的卷" % extra)
    detail = " | ".join(lines[-3:]) if lines else "tar 代码 " + str(returncode)
    return "打包失败：" + detail[:400]


def _skipped(rel, patterns):
    base_name = rel.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(base_name, p) for p in patterns)


def _os_error_text(exc, target_dir):
    """把 zipfile/os 抛出的 OSError 翻译成能看懂的提示。"""
    code = getattr(exc, "errno", None)
    if code in (28, 122):  # ENOSPC / EDQUOT
        free = _free_space(target_dir)
        extra = "（剩余 %s）" % common.human_size(free) if free is not None else ""
        return ("备份目录空间不足或用户配额已满%s。请清理空间、把「保留份数」调小，"
                "或把备份目录换到空间更大的卷" % extra)
    if code in (1, 13):  # EPERM / EACCES
        return ("没有权限写入备份目录：调度进程没以 root 运行。两种修法任选其一——"
                "① SSH 登录群晖执行：sed -i 's/\"run-as\": \"package\"/\"run-as\": \"root\"/' "
                "/var/packages/FileSync/conf/privilege && synopkg restart FileSync ；"
                "② 在 File Station 里给 filesync 用户授予该文件夹读写权限")
    return "打包失败：%s" % exc


def _run_zip(parent, base, output, patterns):
    """用 Python 的 zipfile 打包（不依赖系统 zip 命令），中文文件名按 UTF-8 写入。"""
    root = os.path.join(parent, base)
    try:
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for dirpath, dirnames, filenames in os.walk(root):
                rel_dir = os.path.relpath(dirpath, root)
                prefix = "" if rel_dir == "." else rel_dir.replace(os.sep, "/") + "/"
                dirnames[:] = [d for d in dirnames if not _skipped(prefix + d, patterns)]
                for name in filenames:
                    rel = prefix + name
                    if _skipped(rel, patterns):
                        continue
                    zf.write(os.path.join(dirpath, name), arcname=base + "/" + rel)
    except OSError as exc:
        raise ArchiveError(_os_error_text(exc, os.path.dirname(output) or "."))
    except zipfile.BadZipFile as exc:
        raise ArchiveError("打包失败：%s" % exc)


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
        # tar 退出码：0=成功；1=有文件在打包过程中被改动/消失（网站目录、日志、
        # 会话文件极常见），此时包仍然完整可用，不能当成失败；>=2 才是真错误。
        if proc.returncode not in (0, 1):
            lines = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            raise ArchiveError(_tar_error(lines, proc.returncode, os.path.dirname(output) or "."))
        return

    # 没有 tar 的环境（本地调试）用 Python 实现兜底，行为与 tar 一致
    root = os.path.join(parent, base)
    try:
        with tarfile.open(output, "w:gz") as handle:
            for dirpath, dirnames, filenames in os.walk(root):
                rel_dir = os.path.relpath(dirpath, root)
                prefix = "" if rel_dir == "." else rel_dir.replace(os.sep, "/") + "/"
                dirnames[:] = [d for d in dirnames if not _skipped(prefix + d, patterns)]
                for name in filenames:
                    rel = prefix + name
                    if _skipped(rel, patterns):
                        continue
                    handle.add(os.path.join(dirpath, name), arcname=base + "/" + rel, recursive=False)
    except (OSError, tarfile.TarError) as exc:
        raise ArchiveError("打包失败：%s" % exc)


def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def create_archive(source, target_dir, keep=7, excludes=(), fmt=DEFAULT_FORMAT):
    """把 source 目录打包成 target_dir 下的 zip（默认）或 tar.gz，并按份数清理旧包。

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
    except PermissionError:
        raise ArchiveError(
            "没有权限创建备份目录 %s（备份到 /volume1/homes 这类目录需要调度进程以 root 运行；"
            "请重装或重启套件让 run-as:root 生效）" % target_dir)
    except OSError as exc:
        raise ArchiveError("无法创建备份目录 %s：%s" % (target_dir, exc))

    # 空间检查：卷只剩不到 2 MB 时直接给出明确提示，别等 tar 写到一半才失败
    free = _free_space(target_dir)
    if free is not None and free < 2 * 1024 * 1024:
        raise ArchiveError("备份目录空间不足（仅剩 %s），请清理空间或换到更大的卷"
                           % common.human_size(free))

    final = os.path.join(target_dir, archive_name(source, fmt))
    temp = final + ".part"
    patterns = _clean_patterns(excludes)
    try:
        if (fmt or DEFAULT_FORMAT) == "tar":
            _run_tar(parent, base, temp, patterns)
        else:
            _run_zip(parent, base, temp, patterns)
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
