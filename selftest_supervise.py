"""supervise.py 的自测脚本（独立运行，pytest 不会收集它）。

    E:\\Python\\python.exe D:\\window-mcp-v2\\selftest_supervise.py

覆盖：
 1. 日志按大小轮转（改名，不是删除）
 2. pid_alive 绝不误杀（Windows 上 os.kill(pid, 0) 会真的把进程杀掉）
 3. 对正在跑的服务/隧道，护栏必须命中（这就是「不产生重复进程」的证据）
 4. 退避序列 2,4,8… + 单实例锁
 5. 端口护栏
 6. --status / --stop
 7. 回归：子进程日志被独占占用时不许崩，服务照常启动

注意：第 3 项依赖 v2 服务（8770）与命名隧道正在运行 —— 它是「生产状态体检」，
不是隔离单元测试，所以名字不叫 test_*.py。
"""
import ctypes
import os
import subprocess
import sys
import tempfile
import time
from ctypes import wintypes
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SCRATCH = Path(tempfile.gettempdir()) / "window-mcp-v2-selftest"
SCRATCH.mkdir(parents=True, exist_ok=True)
PY = r"E:\Python\python.exe"

import supervise  # noqa: E402

ok = fail = 0


def check(label, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {label}")
    else:
        fail += 1
        print(f"  FAIL  {label} {extra}")


def run_sup(*extra, timeout=120):
    return subprocess.run(
        [PY, str(HERE / "supervise.py"), *extra],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, env={**os.environ, "NO_PROXY": "*"})


print("=== 1) 日志按大小轮转（不是删） ===")
lp = SCRATCH / "rot.log"
for f in SCRATCH.glob("rot.log*"):
    f.unlink()
lp.write_bytes(b"x" * 300)
supervise.MAX_LOG_BYTES = 100
supervise.KEEP_ROTATIONS = 3
for blob in (b"x" * 300, b"y" * 300, b"z" * 300, b"w" * 300):
    lp.write_bytes(blob)
    supervise.rotate_if_needed(lp)
check("轮转产生 .1/.2/.3", all((SCRATCH / f"rot.log.{i}").exists() for i in (1, 2, 3)))
check("只保留 3 份（没有 .4）", not (SCRATCH / "rot.log.4").exists())
check("轮转是改名不是删除（3 份内容都在）",
      sum((SCRATCH / f"rot.log.{i}").stat().st_size for i in (1, 2, 3)) == 900)
supervise.MAX_LOG_BYTES = 20 * 1024 * 1024

print("=== 2) pid_alive 绝不能误杀 ===")
victim = subprocess.Popen([PY, "-c", "import time;time.sleep(60)"])
time.sleep(1.0)
check("活着的进程报 alive", supervise.pid_alive(victim.pid) is True)
check("探活之后它还在跑（没被误杀）", victim.poll() is None)
victim.kill()
victim.wait()
time.sleep(0.5)
check("已死进程报 not alive", supervise.pid_alive(victim.pid) is False)
check("不存在的 pid 报 not alive", supervise.pid_alive(999999) is False)

print("=== 3) 护栏：对正在跑的 v2 服务/隧道应当命中 ===")
for name, port, match in (
    ("v2-server", 8770, ""),
    ("named-tunnel", 0, r"window-mcp-v2\tunnel\config.yml"),
):
    extra = ["--name", name, "--log", str(SCRATCH / f"{name}.log"), "--check-only"]
    if port:
        extra += ["--port", str(port)]
    if match:
        extra += ["--match", match]
    r = run_sup(*extra)
    line = (r.stdout or "").strip()
    print(f"    {line}")
    # 看门狗正在跑时，锁护栏会先命中；三种原因（锁 / 端口 / 命令行）都说明不会起重复进程
    check(f"{name} 护栏命中（锁 / 端口 / 命令行 任一）", "护栏命中" in line,
          f"rc={r.returncode} stderr={r.stderr[:200]}")

print("=== 4) 退避序列 + 单实例 ===")
dummy = SCRATCH / "dummy_exit.py"
dummy.write_text("import sys\nsys.exit(3)\n", encoding="utf-8")
dlog, wdlog = SCRATCH / "dummy.log", SCRATCH / "supervise-dummy.log"
for f in (dlog, wdlog):
    if f.exists():
        f.unlink()
sup = subprocess.Popen(
    [PY, str(HERE / "supervise.py"), "--name", "dummy", "--log", str(dlog),
     "--cwd", str(SCRATCH), "--healthy-s", "300", "--", PY, "-u", str(dummy)],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(9.0)
run_sup("--name", "dummy", "--log", str(dlog), "--cwd", str(SCRATCH),
        "--", PY, "-u", str(dummy))
sup.terminate()
try:
    sup.wait(timeout=15)
except subprocess.TimeoutExpired:
    sup.kill()
text = wdlog.read_text(encoding="utf-8", errors="replace")
delays = [l.split("→")[1].split("s")[0].strip() for l in text.splitlines() if "后重启" in l]
print(f"    退避序列: {delays}")
check("退避从 2s 起、递增", delays[:2] == ["2", "4"], f"实际={delays}")
check("子进程退出码被记录", "code=3" in text)
check("看门狗事件写在它自己的日志里（子进程日志里没有）",
      "不启动" not in dlog.read_text(encoding="utf-8", errors="replace"))
check("第二次启动被锁文件拦下", "锁文件被活着的看门狗占着" in text)

print("=== 5) 端口护栏 ===")
holder = SCRATCH / "holder.py"
holder.write_text(
    "import socket,time\n"
    "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
    "s.bind(('127.0.0.1',18770));s.listen(5)\n"
    "time.sleep(120)\n", encoding="utf-8")
hlog = SCRATCH / "holder.log"
subprocess.Popen([PY, str(HERE / "supervise.py"), "--name", "holder", "--log",
                  str(hlog), "--port", "18770", "--", PY, "-u", str(holder)],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(40):
    time.sleep(0.25)
    if supervise.port_in_use(18770):
        break
check("dummy 已在 18770 监听", supervise.port_in_use(18770))
r = run_sup("--name", "holder2", "--log", str(SCRATCH / "holder2.log"),
            "--port", "18770", "--check-only")
print(f"    {r.stdout.strip()}")
check("端口护栏命中", "护栏命中" in r.stdout and "18770" in r.stdout)

print("=== 6) --status / --stop ===")
r = run_sup("--name", "holder", "--log", str(hlog), "--port", "18770", "--status")
print(r.stdout.rstrip())
check("status 认出看门狗/端口占用者/两份日志",
      "在跑" in r.stdout and "18770" in r.stdout and "看门狗日志" in r.stdout)
r = run_sup("--name", "holder", "--log", str(hlog), "--port", "18770", "--stop")
print(r.stdout.rstrip())
time.sleep(1.0)
check("stop 之后端口空了", not supervise.port_in_use(18770))
check("stop 之后锁文件没了", not (HERE / "state" / "supervise-holder.lock").exists())

print("=== 7) 回归：子进程日志被独占占用时不许崩 ===")
locked = SCRATCH / "locked.log"
wd_locked = SCRATCH / "supervise-lockedtest.log"
for f in (locked, wd_locked):
    if f.exists():
        f.unlink()
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = wintypes.HANDLE
k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                            wintypes.HANDLE]
handle = k32.CreateFileW(str(locked), 0x40000000, 0, None, 2, 0, None)  # share=0
try:
    with open(locked, "ab", buffering=0):
        pass
    check("复现独占占用（应打不开）", False, "居然打开了")
except PermissionError as exc:
    check(f"复现独占占用：{exc.__class__.__name__}", True)

sleeper = SCRATCH / "sleeper.py"
sleeper.write_text("import time\ntime.sleep(120)\n", encoding="utf-8")
lsup = subprocess.Popen(
    [PY, str(HERE / "supervise.py"), "--name", "lockedtest", "--log", str(locked),
     "--watchdog-log", str(wd_locked), "--cwd", str(SCRATCH), "--", PY, "-u", str(sleeper)],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(4.0)
wtext = wd_locked.read_text(encoding="utf-8", errors="replace") if wd_locked.exists() else ""
check("看门狗没崩（进程还在）", lsup.poll() is None)
check("看门狗日志记录了「打不开 → devnull」", "打不开" in wtext and "devnull" in wtext)
child = supervise.read_child_pid(HERE / "state" / "supervise-lockedtest.child")
check("子进程确实起来了", child > 0 and supervise.pid_alive(child), f"child={child}")
r = run_sup("--name", "lockedtest", "--log", str(locked),
            "--watchdog-log", str(wd_locked), "--stop")
time.sleep(1.0)
check("stop 之后子进程没了", not supervise.pid_alive(child))
lsup.kill()
k32.CloseHandle(wintypes.HANDLE(handle))
for f in (HERE / "state" / "supervise-dummy.lock", HERE / "state" / "supervise-dummy.child"):
    try:
        f.unlink()
    except OSError:
        pass

print(f"\n===== supervise 自测: {ok} passed, {fail} failed =====")
sys.exit(1 if fail else 0)
