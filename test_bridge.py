"""目录代读测试：CGI 读不到的目录由调度进程代读。

DSM 上 api.cgi 以套件账号运行，/volume1/homes 这类 root:root 711 的目录列不出
内容；调度进程是 root，所以在它那里开 socket 代读。本文件验证协议与回退逻辑。
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "pkg" / "share"))

import common

SANDBOX = Path(tempfile.mkdtemp(prefix="filesync-bridge-"))
common.PKG_VAR = SANDBOX / "var"
common.DB_PATH = common.PKG_VAR / "state.sqlite3"

import localroot
import remote


def check(label, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + label + ("  " + str(detail)[:160] if detail else ""))
    if not cond:
        raise SystemExit("测试失败：" + label)


root = Path(tempfile.mkdtemp(prefix="fsb-"))
for name in ("homes", "photo", "Photo2"):
    (root / name).mkdir()
(root / "note.txt").write_text("x", encoding="utf-8")

print("=== 代读协议 ===")
payload = localroot.respond({"path": str(root)})
check("列出子目录成功", payload.get("ok") is True, payload)
check("只返回目录、不返回文件", "note.txt" not in payload["dirs"], payload["dirs"])
check("按名称排序（忽略大小写）", payload["dirs"] == sorted(payload["dirs"], key=lambda s: (s.lower(), s)),
      payload["dirs"])

payload = localroot.respond({"path": str(root / "note.txt")})
check("文件路径被拒", payload.get("ok") is False and "不是一个目录" in payload["error"], payload)

payload = localroot.respond({"path": str(root / "definitely-not-here-9527")})
check("不存在的目录被拒", payload.get("ok") is False and "不存在" in payload["error"], payload)

payload = localroot.respond({"path": "relative/path"})
check("相对路径被拒", payload.get("ok") is False and "路径不正确" in payload["error"], payload)

payload = localroot.respond({})
check("空请求被拒", payload.get("ok") is False, payload)

print("\n=== 无权限时回退到调度进程 ===")


class DeniedOS:
    """模拟套件账号被拒绝的场景：scandir 一律 PermissionError。"""

    def __init__(self, real):
        self._real = real

    def scandir(self, path):
        raise PermissionError(13, "Permission denied", str(path))

    def __getattr__(self, name):
        return getattr(self._real, name)


real_os = remote.os
remote.os = DeniedOS(real_os)
try:
    original = localroot.list_dirs_via_worker
    localroot.list_dirs_via_worker = lambda path, timeout=None: ["homes", "photo"]
    try:
        names = remote.list_dirs_local(str(root))
    finally:
        localroot.list_dirs_via_worker = original
    check("代读结果被采用", names == ["homes", "photo"], names)

    localroot.list_dirs_via_worker = lambda path, timeout=None: (_ for _ in ()).throw(
        localroot.LocalRootError("调度进程未运行"))
    try:
        try:
            remote.list_dirs_local(str(root))
            raised = ""
        except remote.RemoteError as exc:
            raised = str(exc)
    finally:
        localroot.list_dirs_via_worker = original
    check("代读失败时报出权限问题", "没有权限访问" in raised and "调度进程未运行" in raised, raised)
finally:
    remote.os = real_os

print("\n=== 本机目录扫描：无权限要报错而不是静默 0 个文件 ===")
remote.os = DeniedOS(real_os)
try:
    try:
        remote.scan_local(str(root))
        scan_error = ""
    except remote.RemoteError as exc:
        scan_error = str(exc)
finally:
    remote.os = real_os
check("扫描无权限目录直接报错", "没有权限读取" in scan_error, scan_error)

print("\n=== 后台线程服务：主线程忙时浏览仍能秒回 ===")
import socket as pysock
import threading
import time

# Windows 的 Python 没有 AF_UNIX，这里用 TCP 回环模拟同一条协议，
# 只为验证「服务在独立线程上，主线程忙也不会卡住浏览」。
ADDR = ["127.0.0.1", 0]


def _fake_af_unix():
    return pysock.AF_INET


def _fake_socket_path():
    return (ADDR[0], ADDR[1])


def _fake_start_server():
    srv = pysock.socket(pysock.AF_INET, pysock.SOCK_STREAM)
    srv.setsockopt(pysock.SOL_SOCKET, pysock.SO_REUSEADDR, 1)
    srv.bind((ADDR[0], 0))
    ADDR[1] = srv.getsockname()[1]
    srv.listen(8)
    return srv  # 阻塞模式，与生产一致（空闲时不空转）


def _fake_stop_server(srv):
    try:
        srv.close()
    except OSError:
        pass


saved = (localroot.af_unix, localroot.socket_path, localroot.start_server, localroot.stop_server)
localroot.af_unix = _fake_af_unix
localroot.socket_path = _fake_socket_path
localroot.start_server = _fake_start_server
localroot.stop_server = _fake_stop_server
server = None
stop_flag = {"v": False}
try:
    server = localroot.start_server()

    def _serve():
        while not stop_flag["v"]:
            try:
                localroot.handle_one(server)  # 与 worker.serve_socket 相同
            except Exception:
                continue

    threading.Thread(target=_serve, daemon=True).start()

    def _busy():
        time.sleep(1.5)  # 模拟主线程正在同步

    busy = threading.Thread(target=_busy)
    busy.start()
    t0 = time.time()
    dirs = localroot.list_dirs_via_worker(str(root), timeout=5)
    elapsed = time.time() - t0
    busy.join()
    check("同步进行中仍能列目录", "homes" in dirs, dirs)
    check("响应没被 1.5 秒忙等拖住", elapsed < 1.2, "%.2fs" % elapsed)
finally:
    stop_flag["v"] = True
    if server is not None:
        localroot.stop_server(server)
    localroot.af_unix, localroot.socket_path, localroot.start_server, localroot.stop_server = saved

print("\n目录代读测试全部通过")
