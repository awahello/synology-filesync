#!/usr/bin/python3
# Copyright (c) 2026 AWA <https://www.akkdiy.cn>. All rights reserved.
"""FileSync 远端层：SSH 密钥、连通性探测、目录扫描、rsync 传输、回收站删除。

兼容性说明
----------
A 站是 OpenWrt，远端只有 BusyBox（find/stat/mv 都是精简版，没有 GNU 扩展），
所以扫描命令统一用 `find -type f -exec stat -c '%s|%Y|%n' {} +`，
这个写法 GNU coreutils 与 BusyBox 都支持，不依赖 -printf。
rsync 在 OpenWrt 上是可选安装包，因此探测不到 rsync 时自动降级为 tar 流。
"""

import fnmatch
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

import common
import localroot

# 系统级必须排除的目录（服务端就过滤掉，避免 @eaDir 里的海量缩略图拖慢扫描）
SYSTEM_EXCLUDES = ("@eaDir", "#recycle", "#snapshot", ".filesync-trash", "@tmp")

SSH_BIN = shutil.which("ssh") or "/usr/bin/ssh"
RSYNC_BIN = shutil.which("rsync") or "/usr/bin/rsync"


class RemoteError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# 密钥
# --------------------------------------------------------------------------
def key_path(key_id):
    if not key_id or not re.fullmatch(r"[0-9a-f-]{36}", str(key_id)):
        return ""
    path = common.KEYS_DIR / (key_id + ".key")
    return str(path) if path.exists() else ""


def generate_key(name):
    """生成 ed25519 密钥对。私钥写 0600 文件，库里只存公钥。"""
    common.ensure_private_dir()
    common.KEYS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(common.KEYS_DIR, 0o700)
    import uuid
    key_id = str(uuid.uuid4())
    private_path = common.KEYS_DIR / (key_id + ".key")
    keygen = shutil.which("ssh-keygen") or "/usr/bin/ssh-keygen"
    if not os.path.exists(keygen):
        raise RemoteError("系统缺少 ssh-keygen，无法生成密钥")
    try:
        subprocess.run(
            [keygen, "-t", "ed25519", "-N", "", "-C", "filesync@dsm", "-f", str(private_path)],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
    except subprocess.CalledProcessError as exc:
        raise RemoteError("生成密钥失败：" + exc.stderr.decode("utf-8", "replace")[:200])
    os.chmod(private_path, 0o600)
    public_line = (common.KEYS_DIR / (key_id + ".key.pub")).read_text(encoding="utf-8").strip()
    (common.KEYS_DIR / (key_id + ".key.pub")).unlink(missing_ok=True)
    return key_id, public_line


def delete_key_file(key_id):
    path = common.KEYS_DIR / (str(key_id) + ".key")
    try:
        path.unlink()
    except OSError:
        pass


# --------------------------------------------------------------------------
# SSH 命令构造
# --------------------------------------------------------------------------
def ssh_options(site):
    opts = [
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "UserKnownHostsFile=" + str(common.KNOWN_HOSTS),
        "-o", "ConnectTimeout=15",
        "-o", "ServerAliveInterval=20",
        "-o", "ServerAliveCountMax=3",
        "-o", "PreferredAuthentications=publickey",
        "-o", "LogLevel=ERROR",
    ]
    key = key_path(site["key_id"])
    if key:
        opts += ["-i", key]
    try:
        port = int(site["port"] or 22)
    except (TypeError, ValueError):
        port = 22
    opts += ["-p", str(port)]
    return opts


def ssh_target(site):
    user = (site["ssh_user"] or "root").strip()
    host = (site["host"] or "").strip()
    if not host:
        raise RemoteError("站点未填写主机地址")
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    return user + "@" + host


def ssh_argv(site, remote_command):
    return [SSH_BIN] + ssh_options(site) + [ssh_target(site), remote_command]


# --------------------------------------------------------------------------
# 密码认证（只用于"一次性部署公钥"，密码不会被保存）
# --------------------------------------------------------------------------
PUBKEY_RE = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/=]{32,}(?: [^\r\n']{0,180})?$")


def _password_ssh_options(site):
    """密码认证专用参数：必须去掉 BatchMode，否则 ssh 根本不读密码。"""
    try:
        port = int(site["port"] or 22)
    except (TypeError, ValueError):
        port = 22
    return [
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "UserKnownHostsFile=" + str(common.KNOWN_HOSTS),
        "-o", "ConnectTimeout=15",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        "-o", "PubkeyAuthentication=no",
        "-o", "NumberOfPasswordPrompts=1",
        "-o", "LogLevel=ERROR",
        "-p", str(port),
    ]


def _make_askpass(password):
    """生成临时 askpass 脚本。密码写在单独的 0600 文件里，脚本只负责 cat 它。"""
    common.ensure_private_dir()
    handle, script_path = tempfile.mkstemp(prefix="askpass-", dir=str(common.PKG_VAR))
    os.close(handle)
    secret_path = script_path + ".secret"
    fd = os.open(secret_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(password)
    try:
        os.chmod(secret_path, 0o600)  # 显式再设一次，防止 umask 干扰
    except OSError:
        pass
    with open(script_path, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\ncat %s\n" % shlex.quote(secret_path))
    os.chmod(script_path, 0o700)
    return script_path, secret_path


def _cleanup_askpass(paths):
    for path in paths:
        try:
            os.unlink(path)
        except OSError:
            pass


def password_ssh(site, password, remote_command, timeout=60):
    """用密码执行一次远程命令。

    优先 sshpass；没有就退回 OpenSSH 的 SSH_ASKPASS。
    askpass 必须配合"无控制终端"才生效：这里用 subprocess 的 start_new_session
    （等价于 setsid）让子进程脱离终端，不依赖系统里是否有 setsid 命令。
    """
    opts = _password_ssh_options(site)
    sshpass = shutil.which("sshpass")

    if sshpass:
        env = os.environ.copy()
        env["SSHPASS"] = password
        argv = [sshpass, "-e", SSH_BIN] + opts + [ssh_target(site), remote_command]
        try:
            proc = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise RemoteError("密码连接超时（%d 秒）" % timeout)
        return (proc.returncode,
                proc.stdout.decode("utf-8", "replace"),
                proc.stderr.decode("utf-8", "replace"))

    script_path, secret_path = _make_askpass(password)
    try:
        env = os.environ.copy()
        env["SSH_ASKPASS"] = script_path
        env["SSH_ASKPASS_REQUIRE"] = "force"   # OpenSSH 8.4+：强制用 askpass
        env["DISPLAY"] = ":0"                  # 旧版本：有 DISPLAY 且无 tty 才走 askpass
        argv = [SSH_BIN] + opts + [ssh_target(site), remote_command]
        try:
            proc = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=timeout, start_new_session=True)
        except subprocess.TimeoutExpired:
            raise RemoteError("密码连接超时（%d 秒）" % timeout)
        return (proc.returncode,
                proc.stdout.decode("utf-8", "replace"),
                proc.stderr.decode("utf-8", "replace"))
    finally:
        _cleanup_askpass([script_path, secret_path])


DEPLOY_SCRIPT = r'''
umask 077
KEY=__KEY__
for DIR in /etc/dropbear "$HOME/.ssh"; do
  mkdir -p "$DIR" 2>/dev/null || continue
  FILE="$DIR/authorized_keys"
  touch "$FILE" 2>/dev/null || continue
  chmod 600 "$FILE" 2>/dev/null
  grep -qxF "$KEY" "$FILE" 2>/dev/null || printf '%s\n' "$KEY" >> "$FILE" 2>/dev/null
done
if grep -qxF "$KEY" /etc/dropbear/authorized_keys 2>/dev/null || grep -qxF "$KEY" "$HOME/.ssh/authorized_keys" 2>/dev/null; then
  echo FS_DEPLOY_OK
else
  echo FS_DEPLOY_FAIL
fi
'''


def deploy_public_key(site, password, public_line):
    """用密码登录一次，把公钥写入对方的 authorized_keys。密码用完即弃，不落库。"""
    public_line = (public_line or "").strip()
    if not PUBKEY_RE.match(public_line):
        raise RemoteError("公钥格式不正确")
    if not password:
        raise RemoteError("请填写 SSH 密码")

    script = DEPLOY_SCRIPT.replace("__KEY__", "'" + public_line + "'")
    rc, out, err = password_ssh(site, password, script, timeout=60)

    if "FS_DEPLOY_OK" in out:
        return True
    low_err = (err or "").lower()
    detail = (err or out or "").strip().splitlines()
    last = detail[-1] if detail else ""
    if "askpass" in low_err or "no tty" in low_err or "no controlling" in low_err:
        raise RemoteError("当前 OpenSSH 版本不支持免交互密码（缺 SSH_ASKPASS_REQUIRE）。"
                          "请改用手工方式：把公钥粘贴到对方的 authorized_keys。")
    if "permission denied" in low_err:
        raise RemoteError("密码认证失败：密码不正确，或对方关闭了密码登录。"
                          "Linux 需在 sshd_config 里设 PasswordAuthentication yes；"
                          "也可直接手工粘贴公钥。")
    if "connection refused" in low_err:
        raise RemoteError("对方 SSH 端口未开放（Connection refused）")
    if "no route to host" in low_err or "timed out" in low_err:
        raise RemoteError("网络不通，无法连接到对方 SSH 端口")
    raise RemoteError("部署公钥失败：" + (last[:200] or "未知错误"))


def run_ssh(site, remote_command, timeout=120, stdin_data=None):
    argv = ssh_argv(site, remote_command)
    try:
        proc = subprocess.run(
            argv, input=stdin_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        raise RemoteError("连接超时（%d 秒）：%s" % (timeout, site["host"]))
    except OSError as exc:
        raise RemoteError("无法启动 ssh：%s" % exc)
    return (
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


# --------------------------------------------------------------------------
# 探测
# --------------------------------------------------------------------------
PROBE_SCRIPT = r'''
echo "FS_OS=$(uname -s 2>/dev/null || echo unknown)"
echo "FS_KERNEL=$(uname -r 2>/dev/null || echo unknown)"
if command -v rsync >/dev/null 2>&1; then
  echo "FS_RSYNC=$(rsync --version 2>/dev/null | head -n 1 | tr -d '\r')"
else
  echo "FS_RSYNC=none"
fi
if command -v tar >/dev/null 2>&1; then echo "FS_TAR=yes"; else echo "FS_TAR=no"; fi
if command -v sha256sum >/dev/null 2>&1; then echo "FS_SHA=sha256sum";
elif command -v md5sum >/dev/null 2>&1; then echo "FS_SHA=md5sum";
else echo "FS_SHA=none"; fi
echo "FS_STAT=$(stat -c %s / 2>/dev/null >/dev/null && echo yes || echo no)"
echo "FS_DF=$(df -Pk . 2>/dev/null | tail -n 1)"
'''


def probe(site):
    """探测远端能力。返回 dict，失败抛 RemoteError。"""
    rc, out, err = run_ssh(site, PROBE_SCRIPT, timeout=45)
    if rc != 0:
        message = (err or out or "").strip().splitlines()
        detail = message[-1] if message else ("ssh 返回代码 " + str(rc))
        raise RemoteError(detail[:300])
    caps = {}
    for line in out.splitlines():
        if not line.startswith("FS_"):
            continue
        key, _, value = line.partition("=")
        caps[key[3:].lower()] = value.strip()
    if not caps.get("os"):
        raise RemoteError("远端没有返回系统信息，可能不是标准 shell 环境")
    caps["rsync"] = caps.get("rsync", "none")
    caps["has_rsync"] = bool(caps["rsync"] and caps["rsync"] != "none")
    return caps


def test_local():
    caps = {
        "os": os.uname().sysname if hasattr(os, "uname") else "Linux",
        "rsync": "local",
        "has_rsync": os.path.exists(RSYNC_BIN) or bool(shutil.which("rsync")),
        "tar": "yes" if shutil.which("tar") else "no",
    }
    return caps


# --------------------------------------------------------------------------
# 扫描
# --------------------------------------------------------------------------
def _server_exclude_args():
    # BusyBox 的 find 不认 -not，只认 !（GNU find 两者都认）。
    # 用 ! 才能同时兼容 OpenWrt 的 BusyBox 和 Linux 的 GNU find。
    return " ".join("! -path './%s/*'" % name for name in SYSTEM_EXCLUDES)


SCAN_SCRIPT_TEMPLATE = (
    "cd __DIR__ 2>/dev/null || { echo 'FS_ERR=目录不存在或无权限'; exit 3; }; "
    # OpenWrt 的 BusyBox 常常没有 stat 命令（stat: not found），
    # 因此改用 ls -l 取大小和时间，GNU 与 BusyBox 都支持。
    "find . -type f " + _server_exclude_args() + " -exec ls -l {} + 2>/dev/null"
)


def norm_mtime(value):
    """统一 mtime 精度为整数秒。

    远端 `stat -c '%Y'` 返回整数秒，而本机 `st_mtime` 带小数。若不统一，同一个
    文件在两端比较 `(size, mtime)` 时永远不相等，结果就是每轮都把「没变」的文件
    重新拉取/推送一遍。统一到整数秒后，内容一致的文件才会被判为一致、跳过传输。
    """
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def parse_scan_output(text):
    """解析 size|mtime|path，path 允许包含 | 字符（只切前两段）。"""
    result = {}
    for line in text.splitlines():
        if not line or line.startswith("FS_ERR="):
            continue
        parts = line.split("|", 2)
        if len(parts) != 3:
            continue
        size_s, mtime_s, path = parts
        try:
            size = int(size_s)
            mtime = norm_mtime(mtime_s)
        except ValueError:
            continue
        rel = common.norm_rel(path)
        if not rel:
            continue
        result[rel] = (size, mtime)
    return result


def parse_ls_output(text):
    """解析 `ls -l` 输出（BusyBox 与 GNU 通用）。

    OpenWrt 的 BusyBox 常把 stat 裁掉（stat: not found），只能用 ls -l
    取大小和修改时间。ls 显示的是本地时区时间，按当前机器时区还原。
    """
    import datetime
    months = {name: i for i, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
    now = datetime.datetime.now()
    result = {}
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.startswith("total "):
            continue
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        try:
            size = int(parts[4])
            month = months.get(parts[5][:3])
            if not month:
                continue
            day = int(parts[6])
            clock = parts[7]
            if ":" in clock:
                hour, minute = clock.split(":")
                year = now.year
                hour, minute, second = int(hour), int(minute), 0
            else:
                year = int(clock)
                hour = minute = second = 0
            stamp = datetime.datetime(year, month, day, hour, minute, second).timestamp()
        except (ValueError, TypeError):
            continue
        rel = common.norm_rel(parts[8])
        if rel:
            result[rel] = (size, int(stamp))
    return result


def scan_remote(site, directory, timeout=600):
    script = SCAN_SCRIPT_TEMPLATE.replace("__DIR__", shlex.quote(directory))
    rc, out, err = run_ssh(site, script, timeout=timeout)
    if "FS_ERR=" in out:
        raise RemoteError("远端目录不可用：" + directory)
    if rc not in (0, 1):
        detail = (err or "").strip().splitlines()
        raise RemoteError((detail[-1] if detail else "扫描失败，ssh 代码 " + str(rc))[:300])
    return parse_ls_output(out)


def scan_local(directory):
    root = Path(directory)
    if not root.is_dir():
        raise RemoteError("本机目录不可用：" + directory)
    # 先探一次目录权限：os.walk 遇到没权限的目录会静默跳过，
    # 结果就是"0 个文件"，看起来像目录是空的，比直接报错更误导人。
    try:
        with os.scandir(str(root)):
            pass
    except PermissionError:
        raise RemoteError("本机没有权限读取：" + directory)
    except OSError as exc:
        raise RemoteError("本机目录不可用：%s（%s）" % (directory, exc))
    result = {}
    skip_names = set(SYSTEM_EXCLUDES)
    for dirpath, dirnames, filenames in os.walk(str(root), followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in skip_names]
        rel_dir = os.path.relpath(dirpath, str(root))
        prefix = "" if rel_dir == "." else rel_dir.replace(os.sep, "/") + "/"
        for name in filenames:
            if name in skip_names:
                continue
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if not os.path.isfile(full) or os.path.islink(full):
                continue
            # 与远端 stat %Y 对齐到整数秒，否则两端比较永远不相等、每轮都重传
            result[prefix + name] = (st.st_size, norm_mtime(st.st_mtime))
    return result


def scan_side(site, directory):
    if site["kind"] == "local":
        return scan_local(directory)
    return scan_remote(site, directory)


# --------------------------------------------------------------------------
# 内容哈希：区分「时间不同但内容相同」，避免整批文件被反复重传
# --------------------------------------------------------------------------
def hash_local(directory, files):
    result = {}
    for rel in files:
        path = os.path.join(directory, rel)
        try:
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
            result[rel] = digest.hexdigest()
        except OSError:
            continue
    return result


HASH_SCRIPT = (
    "cd __DIR__ 2>/dev/null || exit 3\n"
    "for f in __FILES__; do\n"
    "  if command -v sha256sum >/dev/null 2>&1; then h=$(sha256sum \"$f\" 2>/dev/null);\n"
    "  elif command -v md5sum >/dev/null 2>&1; then h=$(md5sum \"$f\" 2>/dev/null);\n"
    "  else h=; fi\n"
    "  [ -n \"$h\" ] && printf '%s|%s\\n' \"${h%% *}\" \"$f\"\n"
    "done\n"
    "echo FS_HASH_DONE\n"
)


def hash_remote(site, directory, files, batch=40, timeout=600):
    result = {}
    for start in range(0, len(files), batch):
        chunk = files[start:start + batch]
        script = (HASH_SCRIPT
                  .replace("__DIR__", shlex.quote(directory))
                  .replace("__FILES__", " ".join(shlex.quote(f) for f in chunk)))
        rc, out, err = run_ssh(site, script, timeout=timeout)
        if rc not in (0, 1) or "FS_HASH_DONE" not in out:
            detail = (err or out or "").strip().splitlines()
            raise RemoteError("计算文件哈希失败：" + ((detail[-1] if detail else "代码 " + str(rc))[:300]))
        for line in out.splitlines():
            if "|" not in line or line.startswith("FS_"):
                continue
            digest, _, rel = line.partition("|")
            rel = common.norm_rel(rel)
            if rel:
                result[rel] = digest
    return result


def hash_side(site, directory, files):
    if not files:
        return {}
    if site["kind"] == "local":
        return hash_local(directory, files)
    return hash_remote(site, directory, files)


# --------------------------------------------------------------------------
# 目录浏览（界面上「选择目录」用，只列直接子目录，不递归）
# --------------------------------------------------------------------------
MAX_DIR_ENTRIES = 500

# 只用 POSIX sh 的基础语法，BusyBox ash 与 GNU bash 都能跑。
LIST_DIRS_SCRIPT = (
    "DIR=__DIR__\n"
    "if [ ! -d \"$DIR\" ]; then echo 'FS_ERR=目录不存在'; exit 3; fi\n"
    "cd \"$DIR\" 2>/dev/null || { echo 'FS_ERR=没有权限进入该目录'; exit 3; }\n"
    "for d in .[!.]* *; do\n"
    "  if [ -d \"$d\" ]; then printf 'D|%s\\n' \"$d\"; fi\n"
    "done\n"
    "echo 'FS_DONE'\n"
)


def join_posix(base, name):
    base = base or "/"
    if base == "/":
        return "/" + name
    return base.rstrip("/") + "/" + name


def parent_posix(path):
    if not path or path == "/":
        return "/"
    parent = path.rstrip("/").rsplit("/", 1)[0]
    return parent or "/"


def _sort_names(names):
    # 目录名可能是任意 UTF-8，按小写排序更接近用户预期
    return sorted(names, key=lambda s: (s.lower(), s))


def list_dirs_local(directory):
    try:
        with os.scandir(directory) as entries:
            names = []
            for entry in entries:
                try:
                    if entry.is_dir(follow_symlinks=True):
                        names.append(entry.name)
                except OSError:
                    continue
    except FileNotFoundError:
        raise RemoteError("目录不存在：" + directory)
    except NotADirectoryError:
        raise RemoteError("这不是一个目录：" + directory)
    except PermissionError:
        # 套件账号进不去（/volume1/homes 这类只有 root 能列），
        # 交给以 root 运行的调度进程代读，见 localroot.py
        try:
            names = localroot.list_dirs_via_worker(directory)
        except localroot.LocalRootError as exc:
            raise RemoteError("没有权限访问：%s；%s" % (directory, exc))
    except OSError as exc:
        raise RemoteError("无法读取目录：%s" % exc)
    return _sort_names(names)


def list_dirs_remote(site, directory, timeout=45):
    script = LIST_DIRS_SCRIPT.replace("__DIR__", shlex.quote(directory))
    rc, out, err = run_ssh(site, script, timeout=timeout)
    if "FS_ERR=" in out:
        message = ""
        for line in out.splitlines():
            if line.startswith("FS_ERR="):
                message = line.split("=", 1)[1].strip()
                break
        raise RemoteError((message or "目录不可用") + "：" + directory)
    if rc not in (0, 1) or "FS_DONE" not in out:
        detail = (err or out or "").strip().splitlines()
        message = detail[-1] if detail else "ssh 返回代码 " + str(rc)
        low = (err or "").lower()
        if "permission denied" in low or "publickey" in low:
            raise RemoteError("密钥登录被拒绝，公钥还没装到这台机器上。"
                              "请到「站点」卡片点「测试连接」按提示安装公钥。")
        if "connection refused" in low:
            raise RemoteError("对方 SSH 端口未开放（Connection refused）")
        raise RemoteError(message[:300])
    names = [line[2:] for line in out.splitlines() if line.startswith("D|")]
    return _sort_names(names)


def list_dirs(site, directory):
    if site["kind"] == "local":
        return list_dirs_local(directory)
    return list_dirs_remote(site, directory)


# --------------------------------------------------------------------------
# 排除规则匹配
# --------------------------------------------------------------------------
def compile_excludes(text):
    patterns = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    for item in common.DEFAULT_EXCLUDES:
        if item not in patterns:
            patterns.append(item)
    return patterns


def is_excluded(rel, patterns):
    """glob 匹配。

    - `xxx`（不带 /）：匹配任意层级的文件名，如 `*.log`、`config.inc.php`
    - `dir/`（结尾带 /）：匹配该目录及其下所有文件，如 `cache/`
    - `a/b/*`（中间含 /）：按整条相对路径匹配
    """
    base = rel.rsplit("/", 1)[-1]
    for raw in patterns:
        pattern = raw.strip()
        if not pattern:
            continue
        dir_rule = pattern.endswith("/")
        pattern = pattern.rstrip("/")
        if not pattern:
            continue
        if dir_rule or "/" in pattern:
            if rel == pattern or fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, pattern + "/*"):
                return True
        else:
            if fnmatch.fnmatch(base, pattern) or fnmatch.fnmatch(rel, pattern):
                return True
    return False


def filter_manifest(manifest, patterns):
    return {rel: meta for rel, meta in manifest.items() if not is_excluded(rel, patterns)}


# --------------------------------------------------------------------------
# 传输
# --------------------------------------------------------------------------
def _rsync_remote_shell(site):
    return " ".join([SSH_BIN] + ssh_options(site))


def _write_list(paths):
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, prefix="filesync-list-")
    try:
        for rel in paths:
            handle.write(rel.replace("\n", "") + "\n")
    finally:
        handle.close()
    return handle.name


def rsync_push(site, local_dir, remote_dir, files, timeout=7200):
    """本机 → 远端。files 是相对 local_dir 的路径列表。"""
    if not files:
        return 0
    list_path = _write_list(files)
    try:
        argv = [
            RSYNC_BIN, "-rlpt", "--no-owner", "--no-group",
            "--files-from=" + list_path,
            "-e", _rsync_remote_shell(site),
            local_dir.rstrip("/") + "/",
            ssh_target(site) + ":" + remote_dir.rstrip("/") + "/",
        ]
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        # 24 = 传输前文件被删除（扫描与传输之间的正常竞态），不算失败
        if proc.returncode not in (0, 24):
            raise RemoteError("rsync 推送失败：" + proc.stderr.decode("utf-8", "replace").strip()[:400])
        return proc.returncode
    finally:
        _unlink(list_path)


def rsync_pull(site, remote_dir, local_dir, files, timeout=7200):
    """远端 → 本机。"""
    if not files:
        return 0
    list_path = _write_list(files)
    try:
        argv = [
            RSYNC_BIN, "-rlpt", "--no-owner", "--no-group",
            "--files-from=" + list_path,
            "-e", _rsync_remote_shell(site),
            ssh_target(site) + ":" + remote_dir.rstrip("/") + "/",
            local_dir.rstrip("/") + "/",
        ]
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if proc.returncode not in (0, 24):
            raise RemoteError("rsync 拉取失败：" + proc.stderr.decode("utf-8", "replace").strip()[:400])
        return proc.returncode
    finally:
        _unlink(list_path)


def tar_push(site, local_dir, remote_dir, files, timeout=7200):
    """无 rsync 时降级：tar 流经 ssh 推送。"""
    if not files:
        return 0
    list_path = _write_list(files)
    try:
        # 远端命令整体作为一个参数引用，避免路径里的引号破坏 shell 解析
        remote_cmd = "tar -C %s -xf -" % shlex.quote(remote_dir)
        tar_cmd = "tar -C %s -cf - -T - 2>/dev/null | %s %s %s %s" % (
            shlex.quote(local_dir),
            SSH_BIN,
            " ".join(ssh_options(site)),
            ssh_target(site),
            shlex.quote(remote_cmd),
        )
        with open(list_path, "rb") as handle:
            proc = subprocess.run(
                ["sh", "-c", tar_cmd], stdin=handle,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
            )
        if proc.returncode != 0:
            raise RemoteError("tar 推送失败：" + proc.stderr.decode("utf-8", "replace").strip()[:400])
        return proc.returncode
    finally:
        _unlink(list_path)


def tar_pull(site, remote_dir, local_dir, files, timeout=7200):
    if not files:
        return 0
    list_path = _write_list(files)
    try:
        remote_cmd = "tar -C %s -cf - -T -" % shlex.quote(remote_dir)
        pull_cmd = "%s %s %s %s | tar -C %s -xf -" % (
            SSH_BIN,
            " ".join(ssh_options(site)),
            ssh_target(site),
            shlex.quote(remote_cmd),
            shlex.quote(local_dir),
        )
        with open(list_path, "rb") as handle:
            proc = subprocess.run(
                ["sh", "-c", pull_cmd], stdin=handle,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
            )
        if proc.returncode != 0:
            raise RemoteError("tar 拉取失败：" + proc.stderr.decode("utf-8", "replace").strip()[:400])
        return proc.returncode
    finally:
        _unlink(list_path)


def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def transfer(site_src, dir_src, site_dst, dir_dst, files, timeout=7200):
    """把 files 从源侧传到目标侧。两端至少有一端是本机。"""
    if not files:
        return 0
    src_local = site_src["kind"] == "local"
    dst_local = site_dst["kind"] == "local"
    if src_local and dst_local:
        return _copy_local(dir_src, dir_dst, files)
    if src_local:
        caps = site_caps(site_dst)
        if caps.get("has_rsync"):
            return rsync_push(site_dst, dir_src, dir_dst, files, timeout)
        return tar_push(site_dst, dir_src, dir_dst, files, timeout)
    if dst_local:
        caps = site_caps(site_src)
        if caps.get("has_rsync"):
            return rsync_pull(site_src, dir_src, dir_dst, files, timeout)
        return tar_pull(site_src, dir_src, dir_dst, files, timeout)
    # 两端都是远端：经本机临时目录中转
    staging = tempfile.mkdtemp(prefix="filesync-relay-")
    try:
        transfer(site_src, dir_src, {"kind": "local"}, staging, files, timeout)
        return transfer({"kind": "local"}, staging, site_dst, dir_dst, files, timeout)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _utc_stamp(epoch):
    """epoch 秒 → UTC 的 'YYYYMMDDhhmm.ss'，供 touch -t 使用（配合 TZ=UTC）。"""
    import datetime
    dt = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc)
    return dt.strftime("%Y%m%d%H%M.%S")


def set_mtime_local(directory, entries):
    """entries: [(rel, epoch), ...]，把本机文件 mtime 设为指定值。"""
    changed = 0
    for rel, epoch in entries:
        path = os.path.join(directory, rel)
        try:
            os.utime(path, (int(epoch), int(epoch)))
            changed += 1
        except OSError:
            pass
    return changed


def set_mtime_remote(site, directory, entries, batch=60, timeout=600):
    """把远端文件 mtime 设为指定值。

    用 `TZ=UTC touch -t` 而不是 `touch -d @epoch`：BusyBox 的 touch 不支持 @epoch，
    而 `-t` 在 GNU 与 BusyBox 上都可用；TZ=UTC 保证与 epoch 精确对应，不受时区影响。
    """
    if not entries:
        return 0
    total = 0
    for start in range(0, len(entries), batch):
        chunk = entries[start:start + batch]
        lines = ["cd %s 2>/dev/null || exit 3" % shlex.quote(directory)]
        for rel, epoch in chunk:
            # BusyBox 的 touch 不认 GNU 的 `--` 结束符，这里不加；同步的文件名不会以 - 开头
            lines.append("TZ=UTC touch -t %s %s 2>/dev/null && echo done" % (
                _utc_stamp(epoch), shlex.quote(rel)))
        rc, out, err = run_ssh(site, "\n".join(lines), timeout=timeout)
        total += out.count("done")
        if rc not in (0, 1):
            detail = (err or "").strip().splitlines()
            raise RemoteError("设置文件时间失败：" + ((detail[-1] if detail else "代码 " + str(rc))[:300]))
    return total


def set_mtime(site, directory, entries):
    """把一批文件的 mtime 统一到指定值（本机/远端通用）。"""
    if not entries:
        return 0
    if site["kind"] == "local":
        return set_mtime_local(directory, entries)
    return set_mtime_remote(site, directory, entries)


def _copy_local(dir_src, dir_dst, files):
    for rel in files:
        src = os.path.join(dir_src, rel)
        dst = os.path.join(dir_dst, rel)
        try:
            os.makedirs(os.path.dirname(dst) or dir_dst, exist_ok=True)
            shutil.copy2(src, dst)
        except OSError as exc:
            raise RemoteError("复制失败 %s：%s" % (rel, exc))
    return 0


def site_caps(site):
    """读取站点缓存的能力，未探测过则按最保守假设。"""
    import json
    try:
        caps = json.loads(site["caps_json"] or "{}")
    except (ValueError, TypeError):
        caps = {}
    if "has_rsync" not in caps:
        caps["has_rsync"] = False
    return caps


# --------------------------------------------------------------------------
# 删除（进回收站，可恢复）
# --------------------------------------------------------------------------
def trash_local(directory, files, tag):
    moved = 0
    for rel in files:
        src = os.path.join(directory, rel)
        if not os.path.lexists(src):
            continue
        dst = os.path.join(directory, common.TRASH_NAME, tag, rel)
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.move(src, dst)
            moved += 1
        except OSError:
            try:
                os.unlink(src)
                moved += 1
            except OSError:
                pass
    return moved


TRASH_SCRIPT_HEAD = (
    "cd %s 2>/dev/null || exit 3\n"
    "mkdir -p %s 2>/dev/null\n"
)


def trash_remote(site, directory, files, tag, batch=150, timeout=600):
    """远端批量删除到回收站。分批执行，避免命令行超长。"""
    total = 0
    for start in range(0, len(files), batch):
        chunk = files[start:start + batch]
        trash_root = common.TRASH_NAME + "/" + tag
        lines = [TRASH_SCRIPT_HEAD % (shlex.quote(directory), shlex.quote(trash_root))]
        lines.append("for p in %s; do" % " ".join(shlex.quote(f) for f in chunk))
        lines.append('  [ -e "$p" ] || continue')
        lines.append('  d=$(dirname "$p")')
        lines.append('  mkdir -p %s/"$d" 2>/dev/null' % shlex.quote(trash_root))
        lines.append('  mv -f -- "$p" %s/"$p" 2>/dev/null || rm -f -- "$p"' % shlex.quote(trash_root))
        lines.append("  echo done")
        lines.append("done")
        script = "\n".join(lines)
        rc, out, err = run_ssh(site, script, timeout=timeout)
        total += out.count("done")
        if rc not in (0, 1):
            detail = (err or "").strip().splitlines()
            raise RemoteError("远端删除失败：" + ((detail[-1] if detail else "代码 " + str(rc))[:300]))
    return total


def trash_side(site, directory, files, tag):
    if not files:
        return 0
    if site["kind"] == "local":
        return trash_local(directory, files, tag)
    return trash_remote(site, directory, files, tag)


def purge_side(site, directory, files, batch=150, timeout=600):
    """直接删除（不进回收站）。仅当用户显式选择 delete_policy=purge 时使用。"""
    if not files:
        return 0
    if site["kind"] == "local":
        count = 0
        for rel in files:
            target = os.path.join(directory, rel)
            try:
                os.unlink(target)
                count += 1
            except OSError:
                pass
        return count
    total = 0
    for start in range(0, len(files), batch):
        chunk = files[start:start + batch]
        lines = ["cd %s 2>/dev/null || exit 3" % shlex.quote(directory)]
        lines.append("for p in %s; do" % " ".join(shlex.quote(f) for f in chunk))
        lines.append('  rm -f -- "$p" 2>/dev/null && echo done')
        lines.append("done")
        rc, out, err = run_ssh(site, "\n".join(lines), timeout=timeout)
        total += out.count("done")
        if rc not in (0, 1):
            detail = (err or "").strip().splitlines()
            raise RemoteError("远端删除失败：" + ((detail[-1] if detail else "代码 " + str(rc))[:300]))
    return total


def purge_trash(site, directory, keep_days):
    """清理回收站中超过保留天数的内容。"""
    if keep_days <= 0:
        return
    script = (
        "cd %s 2>/dev/null || exit 0\n"
        "find %s -mindepth 1 -maxdepth 1 -type d -mtime +%d -exec rm -rf {} + 2>/dev/null\n"
        "echo purged"
    ) % (shlex.quote(directory), shlex.quote(common.TRASH_NAME), int(keep_days))
    if site["kind"] == "local":
        subprocess.run(["sh", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
        return
    run_ssh(site, script, timeout=600)


def clear_trash(site, directory, timeout=600):
    """删除同步目录下的 .filesync-trash 回收站。"""
    if site["kind"] == "local":
        path = os.path.join(directory, common.TRASH_NAME)
        if not os.path.isdir(path):
            return 0
        shutil.rmtree(path, ignore_errors=True)
        return 1
    script = "cd %s 2>/dev/null || exit 0; rm -rf %s 2>/dev/null; echo done" % (
        shlex.quote(directory), shlex.quote(common.TRASH_NAME))
    rc, out, err = run_ssh(site, script, timeout=timeout)
    return 1 if "done" in out else 0


def ensure_remote_dir(site, directory, timeout=60):
    rc, out, err = run_ssh(site, "mkdir -p %s 2>/dev/null && test -d %s && echo ok" % (
        shlex.quote(directory), shlex.quote(directory)), timeout=timeout)
    return rc == 0 and "ok" in out
