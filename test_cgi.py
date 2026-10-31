"""CGI 层测试：模拟 DSM 的 CGI 环境，验证页面渲染与 JSON API。"""
import io
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "pkg" / "share"))

import common

SANDBOX = Path(tempfile.mkdtemp(prefix="filesync-cgi-"))
common.PKG_VAR = SANDBOX / "var"
common.DB_PATH = common.PKG_VAR / "state.sqlite3"
common.KEYS_DIR = common.PKG_VAR / "keys"
common.KNOWN_HOSTS = common.PKG_VAR / "known_hosts"
common.CSRF_PATH = common.PKG_VAR / "csrf.key"

import cgi_app


class FakeStdout:
    """替换 sys.stdout，同时兼容 write 与 buffer.write。"""
    def __init__(self):
        self.buf = io.BytesIO()
        self.buffer = self

    def write(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.buf.write(data)
        return len(data)

    def flush(self):
        pass

    def value(self):
        return self.buf.getvalue().decode("utf-8", "replace")


def run(argv, method="GET", query="", body=None, extra_env=None):
    """模拟一次 CGI 调用，返回 (headers, body)。"""
    os.environ["REMOTE_USER"] = "admin"
    os.environ["REQUEST_METHOD"] = method
    os.environ["QUERY_STRING"] = query
    os.environ["HTTP_COOKIE"] = "id=abc"
    os.environ["HTTP_HOST"] = "nas:5000"
    for key in ("HTTP_X_CSRF_TOKEN", "HTTP_ORIGIN", "CONTENT_LENGTH"):
        os.environ.pop(key, None)
    if extra_env:
        os.environ.update(extra_env)
    if body is not None:
        raw = json.dumps(body).encode("utf-8")
        os.environ["CONTENT_LENGTH"] = str(len(raw))
        sys.stdin = type("S", (), {"buffer": io.BytesIO(raw)})()
    old = sys.stdout
    old_argv = sys.argv
    sys.argv = list(argv)
    sys.stdout = FakeStdout()
    try:
        cgi_app.main()
        output = sys.stdout.value()
    finally:
        sys.stdout = old
        sys.argv = old_argv
    head, _, payload = output.partition("\r\n\r\n")
    return head, payload


def check(label, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + label + ("  " + str(detail)[:160] if detail else ""))
    if not cond:
        raise SystemExit("测试失败：" + label)


# ---------------------------------------------------------------- 页面渲染
print("=== 页面渲染 ===")
head, html = run(["cgi_app.py", "index"])
check("返回 200", "200 OK" in head, head.splitlines()[0])
check("Content-Type 是 HTML", "text/html" in head)
check("CSP 头存在", "Content-Security-Policy" in head)
check("没有残留占位符", "__NONCE__" not in html and "__CSRF__" not in html and "__SYNO_TOKEN__" not in html)
check("页面标题正确", "<title>多站文件同步</title>" in html)
check("nonce 已注入 style", 'nonce="' in html)
csrf_token = html.split("const CSRF = '")[1].split("'")[0]
check("CSRF token 已注入", len(csrf_token) > 30, csrf_token[:20] + "...")

# ---------------------------------------------------------------- API 读取
print("\n=== API 读取 ===")
head, body = run(["cgi_app.py"], query="action=bootstrap")
data = json.loads(body)
check("bootstrap 成功", data.get("ok") is True)
check("含本机站点", any(s["kind"] == "local" for s in data["sites"]), [s["name"] for s in data["sites"]])
check("返回版本号", data.get("version") == common.APP_VERSION)
check("返回默认设置", data["settings"].get("trash_days") == "30")

# ---------------------------------------------------------------- 未授权
print("\n=== 安全校验 ===")
head, body = run(["cgi_app.py"], method="POST", body={"action": "save_site", "name": "x"})
check("缺 CSRF 被拒", "403" in head and json.loads(body)["ok"] is False)

head, body = run(["cgi_app.py"], method="POST", body={"action": "save_site", "name": "x"},
                 extra_env={"HTTP_X_CSRF_TOKEN": "forged.token.value"})
check("伪造 CSRF 被拒", "403" in head)

# ---------------------------------------------------------------- 写操作
print("\n=== 站点与规则 ===")
head, body = run(["cgi_app.py"], method="POST", body={
    "action": "save_site", "name": "A 站", "kind": "openwrt", "host": "192.168.1.1",
    "port": 22, "ssh_user": "root", "key_id": "", "note": "测试",
}, extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
data = json.loads(body)
check("新增站点成功", data.get("ok") is True, data)
site_a = data["id"]

head, body = run(["cgi_app.py"], method="POST", body={
    "action": "save_site", "name": "", "kind": "openwrt", "host": "1.2.3.4", "port": 22, "ssh_user": "root",
}, extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("空名称被拒", "400" in head and "名称" in json.loads(body)["error"])

# 不选密钥时后端应自动补一把，用户不该被"请先生成密钥"卡住
head, body = run(["cgi_app.py"], method="POST", body={
    "action": "save_site", "name": "自动密钥站", "kind": "linux", "host": "10.0.0.9",
    "port": 22, "ssh_user": "root", "key_id": "",
}, extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("未选密钥也能保存站点", json.loads(body).get("ok") is True, json.loads(body))
auto_id = json.loads(body)["id"]

head, body = run(["cgi_app.py"], query="action=bootstrap")
snapshot = json.loads(body)
auto_site = [s for s in snapshot["sites"] if s["id"] == auto_id]
check("站点已自动绑定密钥", bool(auto_site and auto_site[0]["key_id"]), auto_site)
check("密钥列表里确实有这把密钥", any(k["id"] == auto_site[0]["key_id"] for k in snapshot["keys"]), snapshot["keys"])

head, body = run(["cgi_app.py"], method="POST", body={
    "action": "save_site", "name": "坏路径", "kind": "linux", "host": "a b", "port": 22, "ssh_user": "root",
}, extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("非法地址被拒", "400" in head)

head, body = run(["cgi_app.py"], method="POST", body={
    "action": "save_rule", "name": "照片同步", "site_a": "local", "dir_a": "/volume1/photo",
    "site_b": site_a, "dir_b": "/mnt/photo", "mode": "both", "delete_policy": "trash",
    "interval_min": 10, "excludes": "*.log",
}, extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
data = json.loads(body)
check("新增规则成功", data.get("ok") is True, data)
rule_id = data["id"]

head, body = run(["cgi_app.py"], method="POST", body={
    "action": "save_rule", "name": "穿越", "site_a": "local", "dir_a": "/volume1/../../etc",
    "site_b": site_a, "dir_b": "/mnt", "mode": "both", "delete_policy": "trash", "interval_min": 10,
}, extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("路径穿越被拒", "400" in head and ".." in json.loads(body)["error"], json.loads(body)["error"])

head, body = run(["cgi_app.py"], method="POST", body={
    "action": "save_rule", "name": "同目录", "site_a": "local", "dir_a": "/volume1/x",
    "site_b": "local", "dir_b": "/volume1/x", "mode": "both", "delete_policy": "trash", "interval_min": 10,
}, extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("同站点同目录被拒", "400" in head)

head, body = run(["cgi_app.py"], method="POST", body={"action": "delete_site", "id": site_a},
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("站点被规则占用时不能删", "400" in head and "规则" in json.loads(body)["error"])

head, body = run(["cgi_app.py"], method="POST", body={"action": "delete_site", "id": "local"},
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("本机站点不能删", "400" in head)

head, body = run(["cgi_app.py"], method="POST", body={"action": "delete_rule", "id": rule_id},
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("删除规则成功", json.loads(body).get("ok") is True)

head, body = run(["cgi_app.py"], method="POST", body={"action": "delete_site", "id": site_a},
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("规则删除后站点可删", json.loads(body).get("ok") is True)

# ---------------------------------------------------------------- 目录浏览
print("\n=== 目录浏览 ===")
import remote

browse_root = Path(tempfile.mkdtemp(prefix="filesync-browse-"))
(browse_root / "photo").mkdir()
(browse_root / "video").mkdir()
(browse_root / "readme.txt").write_text("x", encoding="utf-8")

names = remote.list_dirs_local(str(browse_root))
check("本机列目录只返回子目录", names == ["photo", "video"], names)

try:
    remote.list_dirs_local(str(browse_root / "nope"))
    check("不存在的目录应报错", False)
except remote.RemoteError as exc:
    check("不存在的目录报错信息友好", "目录不存在" in str(exc), exc)

check("posix 路径拼接正确", remote.join_posix("/volume1", "photo") == "/volume1/photo")
check("根目录拼接正确", remote.join_posix("/", "volume1") == "/volume1")
check("上级路径正确", remote.parent_posix("/volume1/photo") == "/volume1")
check("根目录的上级还是根", remote.parent_posix("/") == "/")

head, body = run(["cgi_app.py"], method="POST",
                 body={"action": "browse", "site_id": "local", "path": "relative/dir"},
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("相对路径被拒", "400" in head and "绝对路径" in json.loads(body)["error"], body)

head, body = run(["cgi_app.py"], method="POST",
                 body={"action": "browse", "site_id": "local", "path": "/volume1/../../etc"},
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("浏览路径穿越被拒", "400" in head, body)

head, body = run(["cgi_app.py"], method="POST",
                 body={"action": "browse", "site_id": "not-exist", "path": "/"},
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("不存在的站点被拒", "400" in head and "站点" in json.loads(body)["error"], body)

# ---------------------------------------------------------------- 设置
print("\n=== 设置 ===")
head, body = run(["cgi_app.py"], method="POST", body={"action": "save_settings", "trash_days": 7, "conflict_copy": "0"},
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("保存设置成功", json.loads(body).get("ok") is True)

head, body = run(["cgi_app.py"], method="POST", body={"action": "save_settings", "trash_days": 99999},
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("超范围设置被拒", "400" in head)

head, body = run(["cgi_app.py"], query="action=bootstrap")
data = json.loads(body)
check("设置已持久化", data["settings"]["trash_days"] == "7" and data["settings"]["conflict_copy"] == "0", data["settings"])

# ---------------------------------------------------------------- 日志
print("\n=== 日志接口 ===")
# 此前 POST_HANDLERS 漏注册 logs，前端点「日志」会一直停在「加载中…」
import uuid as _uuid
rule_id = str(_uuid.uuid4())
group_key = "group:" + str(_uuid.uuid4())
db = common.connect_db()
db.execute("INSERT INTO runs(rule_id,started,status,message) VALUES(?,?,?,?)",
           (rule_id, common.now_iso(), "ok", "规则日志测试"))
db.execute("INSERT INTO runs(rule_id,started,status,message) VALUES(?,?,?,?)",
           (group_key, common.now_iso(), "ok", "组日志测试"))
db.commit()

head, body = run(["cgi_app.py"], method="POST", body={"action": "logs", "id": rule_id},
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
data = json.loads(body)
check("POST 规则日志成功", data.get("ok") is True, data)
check("返回规则日志内容", any("规则日志测试" in (r.get("message") or "") for r in data.get("runs", [])), data)

head, body = run(["cgi_app.py"], method="POST", body={"action": "logs", "id": group_key},
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
data = json.loads(body)
check("POST 组日志成功", data.get("ok") is True, data)
check("返回组日志内容", any("组日志测试" in (r.get("message") or "") for r in data.get("runs", [])), data)

head, body = run(["cgi_app.py"], method="POST", body={"action": "logs", "id": "../../etc/passwd"},
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("非法编号被拒", "400" in head and json.loads(body)["ok"] is False, body)

print("\nCGI 层全部测试通过")
import shutil
shutil.rmtree(SANDBOX, ignore_errors=True)
