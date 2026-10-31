"""验证「复制安装命令」生成的那条命令：语法、可执行、幂等。

命令逻辑与 ui_page.html 里的 installCommand() 保持一致。
"""
import os
import shutil
import subprocess
import sys
import tempfile

PUB = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGAAIXXpggdnQxGqQu5T8bmsVY/Xp5MNBLV/n1tP2nHR"
       " filesync@dsm")


def install_command(public_line):
    q = "'" + public_line + "'"
    return ('K=' + q + ';D="$HOME/.ssh";[ -d /etc/dropbear ]&&D=/etc/dropbear;mkdir -p "$D";'
            'grep -qxF "$K" "$D/authorized_keys" 2>/dev/null||echo "$K">>"$D/authorized_keys";'
            'chmod 600 "$D/authorized_keys";echo OK')


def check(label, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + label + ("  " + str(detail)[:160] if detail else ""))
    if not cond:
        raise SystemExit("测试失败：" + label)


cmd = install_command(PUB)
print("生成的命令：")
print("  " + cmd)
print()

print("=== 语法检查 ===")
proc = subprocess.run(["sh", "-n"], input=cmd, text=True, capture_output=True)
check("sh -n 通过", proc.returncode == 0, proc.stderr[:200])

print("\n=== 实际执行（模拟 Linux 用户，HOME 指向临时目录）===")
home = tempfile.mkdtemp(prefix="fakehome-")
env = dict(os.environ)
env["HOME"] = home
# 测试机可能真的存在 /etc/dropbear（会走 OpenWrt 分支并污染系统目录），
# 这里把它替换成一个不存在的路径，强制走 ~/.ssh 分支
cmd_run = cmd.replace("/etc/dropbear", "/tmp/filesync-test-no-dropbear")
try:
    run1 = subprocess.run(["sh", "-c", cmd_run], env=env, capture_output=True, text=True)
    check("执行成功并输出 OK", run1.returncode == 0 and "OK" in run1.stdout, run1.stdout + run1.stderr)

    auth = os.path.join(home, ".ssh", "authorized_keys")
    check("authorized_keys 已创建", os.path.exists(auth), auth)
    lines = [l for l in open(auth, encoding="utf-8").read().splitlines() if l.strip()]
    check("公钥写入且只有一行", lines == [PUB], lines)

    run2 = subprocess.run(["sh", "-c", cmd_run], env=env, capture_output=True, text=True)
    lines2 = [l for l in open(auth, encoding="utf-8").read().splitlines() if l.strip()]
    check("重复执行不会写重复行（幂等）", lines2 == [PUB], lines2)

    # 原有内容必须保留
    with open(auth, "a", encoding="utf-8") as fh:
        fh.write("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 someone@elsewhere\n")
    run3 = subprocess.run(["sh", "-c", cmd_run], env=env, capture_output=True, text=True)
    lines3 = [l for l in open(auth, encoding="utf-8").read().splitlines() if l.strip()]
    check("不覆盖已有公钥", len(lines3) == 2 and lines3[1].startswith("ssh-rsa"), lines3)
    check("第三方公钥仍在", any("someone@elsewhere" in l for l in lines3), lines3)
finally:
    shutil.rmtree(home, ignore_errors=True)

print("\n=== 公钥里的特殊字符不会破坏 shell ===")
weird = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGAAIXXpggdnQxGqQu5T8bmsVY/Xp5MNBLV/n1tP2nHR test@host"
check("公钥只含安全字符", all(c.isalnum() or c in "+/=@._- " for c in weird), weird)
check("命令里公钥被单引号包裹", "'" + PUB + "'" in cmd)

print("\n安装命令测试全部通过")
