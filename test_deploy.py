"""测试密码部署公钥相关的工具函数（不需要真实远端）。"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "pkg" / "share"))

import common

SANDBOX = Path(tempfile.mkdtemp(prefix="filesync-deploy-"))
common.PKG_VAR = SANDBOX / "var"
common.DB_PATH = common.PKG_VAR / "state.sqlite3"
common.KEYS_DIR = common.PKG_VAR / "keys"
common.KNOWN_HOSTS = common.PKG_VAR / "known_hosts"

import remote


def check(label, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + label + ("  " + str(detail)[:140] if detail else ""))
    if not cond:
        raise SystemExit("测试失败：" + label)


print("=== 公钥格式校验 ===")
GOOD = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialHere filesync@dsm"
check("正常 ed25519 公钥通过", bool(remote.PUBKEY_RE.match(GOOD)))
check("带引号的公钥被拒", not remote.PUBKEY_RE.match(GOOD.replace("@dsm", "'@dsm")))
check("换行注入被拒", not remote.PUBKEY_RE.match(GOOD + "\nrm -rf /"))
check("空公钥被拒", not remote.PUBKEY_RE.match(""))
check("缺少 base64 被拒", not remote.PUBKEY_RE.match("ssh-ed25519 文件"))

print("\n=== 部署脚本语法 ===")
script = remote.DEPLOY_SCRIPT.replace("__KEY__", "'" + GOOD + "'")
proc = subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True)
check("sh -n 语法检查通过", proc.returncode == 0, proc.stderr[:200])
check("脚本里公钥被单引号包裹", "'" + GOOD + "'" in script)
check("同时覆盖 dropbear 与 ~/.ssh", "/etc/dropbear" in script and "$HOME/.ssh" in script)
check("不会重复追加", "grep -qxF" in script)

print("\n=== askpass 临时文件 ===")
common.ensure_private_dir()
script_path, secret_path = remote._make_askpass("p@ss w'ord\"$x")
try:
    check("脚本与密码文件都已创建", os.path.exists(script_path) and os.path.exists(secret_path))
    mode = oct(os.stat(secret_path).st_mode & 0o777)
    if os.name == "posix":
        check("密码文件权限 0600", mode == "0o600", mode)
    else:
        print("  SKIP  密码文件权限（Windows 不模拟 POSIX 权限，DSM 上由 chmod 保证）")
    out = subprocess.run(["sh", script_path], capture_output=True, text=True).stdout
    check("脚本能原样输出密码", out.strip() == "p@ss w'ord\"$x", repr(out))
    check("密码没有被写进脚本本体", "p@ss" not in Path(script_path).read_text(encoding="utf-8"))
finally:
    remote._cleanup_askpass([script_path, secret_path])
check("清理后文件已删除", not os.path.exists(script_path) and not os.path.exists(secret_path))

print("\n=== 密码 SSH 参数 ===")
site = {"host": "127.0.0.1", "port": 2222, "ssh_user": "root", "key_id": ""}
opts = remote._password_ssh_options(site)
check("去掉了 BatchMode", "BatchMode=yes" not in opts)
check("禁用公钥认证", "PubkeyAuthentication=no" in opts)
check("只允许密码类认证", "PreferredAuthentications=password,keyboard-interactive" in opts)
check("只尝试一次密码", "NumberOfPasswordPrompts=1" in opts)
check("端口正确", opts[opts.index("-p") + 1] == "2222")

print("\n=== 错误映射（连不上时的提示）===")
try:
    remote.deploy_public_key({"host": "127.0.0.1", "port": 1, "ssh_user": "root", "key_id": ""},
                             "whatever", GOOD)
    check("应当抛错", False)
except remote.RemoteError as exc:
    msg = str(exc)
    check("抛出了可读的错误", "端口" in msg or "网络" in msg or "失败" in msg, msg)

print("\n=== 空密码拦截 ===")
try:
    remote.deploy_public_key(site, "", GOOD)
    check("空密码应当被拒", False)
except remote.RemoteError as exc:
    check("空密码被拒", "密码" in str(exc), str(exc))

print("\n密码部署相关测试全部通过")
shutil.rmtree(SANDBOX, ignore_errors=True)
