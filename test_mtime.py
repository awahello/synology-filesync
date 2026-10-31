#!/usr/bin/python3
# Copyright (c) 2026 AWA <https://www.akkdiy.cn>. All rights reserved.
"""mtime 精度回归测试。

背景：远端 `stat -c '%Y'` 返回整数秒，本机 `st_mtime` 带小数。若两边不统一，
同一个文件比较 `(size, mtime)` 永远不相等，导致每轮都把「没变」的文件重新
拉取/推送。本测试锁定：扫描结果必须是整数秒，且本机浮点 mtime 与远端整数
mtime 能被判为一致。
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "pkg" / "share"))

import remote  # noqa: E402


def main():
    tmp = tempfile.mkdtemp(prefix="filesync-mtime-")
    try:
        target = os.path.join(tmp, "a.txt")
        Path(target).write_text("hello", encoding="utf-8")

        # 1) 人为设置带小数的 mtime，scan_local 必须取整
        os.utime(target, (1698750000.75, 1698750000.75))
        man = remote.scan_local(tmp)
        mtime = man["a.txt"][1]
        assert isinstance(mtime, int), "scan_local 的 mtime 应为 int，实际 %r" % (mtime,)
        assert mtime == 1698750000, "mtime 应取整到 1698750000，实际 %r" % (mtime,)
        print("  PASS  scan_local mtime 取整为整数秒：%r" % (mtime,))

        # 2) 模拟远端 stat -c '%Y'（整数秒），解析后应与本机判定一致
        remote_man = remote.parse_scan_output("5|1698750000|./a.txt\n")
        assert remote_man["a.txt"] == man["a.txt"], \
            "远端整数 mtime 与本机应一致：%r vs %r" % (remote_man["a.txt"], man["a.txt"])
        print("  PASS  远端整数 mtime 与本机判定一致：%r" % (remote_man["a.txt"],))

        # 3) 内容不变、mtime 变化时仍要能区分
        os.utime(target, (1698750001.2, 1698750001.2))
        man2 = remote.scan_local(tmp)
        assert man2["a.txt"] != man["a.txt"], "mtime 变化后应判定不同"
        print("  PASS  mtime 变化后能正确判定不同：%r" % (man2["a.txt"],))

        # 4) 旧基线里的浮点 mtime 经 norm_mtime 后与整数一致
        assert remote.norm_mtime(1698750000.9) == 1698750000
        assert remote.norm_mtime("1698750000") == 1698750000
        assert remote.norm_mtime(None) == 0
        print("  PASS  旧浮点/字符串/None 的 mtime 都被归一化")

        # 5) 两个内容相同的文件、不同小数 mtime，取整后应判为一致
        left = os.path.join(tmp, "left")
        right = os.path.join(tmp, "right")
        os.makedirs(left)
        os.makedirs(right)
        for folder, fraction in ((left, 0.11), (right, 0.87)):
            path = os.path.join(folder, "same.txt")
            Path(path).write_text("identical", encoding="utf-8")
            os.utime(path, (1698750100 + fraction, 1698750100 + fraction))
        man_l = remote.scan_local(left)
        man_r = remote.scan_local(right)
        assert man_l["same.txt"] == man_r["same.txt"], \
            "同一文件不同小数 mtime 应判为一致：%r vs %r" % (man_l["same.txt"], man_r["same.txt"])
        print("  PASS  同内容不同小数 mtime 判为一致：%r" % (man_l["same.txt"],))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\nmtime 精度测试全部通过")


if __name__ == "__main__":
    main()
