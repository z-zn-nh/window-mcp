"""后台任务管理：启动、等待、查看、终止。

对应文档 §5.2。要点：
* 命令按 ≤50 秒设计（Hark 单次调用默认 60 秒超时），跑不完就转后台并保留结果；
* 子进程用 psutil 递归终止 + taskkill /T /F 兜底，不能只杀直接子进程；
* PowerShell 输出 cp936 的坑用「脚本前置设置 UTF-8 输出编码」解决；
  wsl.exe 的输出是 UTF-16LE，读取时按 utf-16-le 解码。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import psutil

from .config import Config

CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000

PS_PROLOGUE = (
    "$ProgressPreference='SilentlyContinue';"
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
    "$OutputEncoding=[System.Text.Encoding]::UTF8;"
)

# 启动期崩溃码：进程还没真正跑起来就死了，命令没有执行过。
# 实测遇到过 0x800703E9（Win32 1001 堆栈溢出）——PowerShell 5.1 在密集启动时
# 偶发启动崩溃，属于环境抖动，不是命令本身的结果。
_STARTUP_FAILURE_CODES = {
    0xC00000FD: "STATUS_STACK_OVERFLOW：进程启动时栈溢出",
    0x800703E9: "HRESULT_FROM_WIN32(1001)：堆栈溢出",
    0xC0000142: "STATUS_DLL_INIT_FAILED：DLL 初始化失败",
    0xC0000135: "STATUS_DLL_NOT_FOUND：缺少依赖 DLL",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN：进程快速失败",
}
# 这个码表示进程被中断，命令可能已经部分执行，不能当作「没跑过」
_TERMINATED_CODES = {
    0xC000013A: "STATUS_CONTROL_C_EXIT：进程被中断（Ctrl+C 或被终止）",
}


def diagnose_exit(code: int | None, log_empty: bool) -> dict | None:
    """识别异常退出码，避免把「进程没起来」误报成「命令执行结果」。

    只有同时满足「是启动期崩溃码」且「日志为空」才认为可以安全重试——
    这是启发式判断，所以结果里把依据一并返回，由调用方决定。
    """
    if code is None:
        return None
    unsigned = code & 0xFFFFFFFF
    if unsigned in _TERMINATED_CODES:
        return {
            "code": code,
            "code_hex": hex(unsigned),
            "reason": _TERMINATED_CODES[unsigned],
            "log_empty": log_empty,
            "retry_safe": False,
            "hint": "进程被中断，命令可能已经部分执行，重试前请先确认当前状态。",
        }
    reason = _STARTUP_FAILURE_CODES.get(unsigned)
    if reason is None:
        return None
    retry_safe = log_empty
    return {
        "code": code,
        "code_hex": hex(unsigned),
        "reason": reason,
        "log_empty": log_empty,
        "retry_safe": retry_safe,
        "hint": (
            "进程在启动阶段就崩了，命令没有执行，可以重试。"
            if retry_safe else
            "进程异常退出但已有输出，命令可能已部分执行，重试前请先确认状态。"
        ),
    }


@dataclass
class Job:
    job_id: str
    command: str
    shell: str
    cwd: str
    name: str
    encoding: str
    dir: Path
    log_path: Path
    script_path: Path | None
    started_at: float
    request_id: str | None = None
    proc: subprocess.Popen | None = None
    exit_code: int | None = None
    finished_at: float | None = None
    timed_out: bool = False
    stopped: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def done(self) -> bool:
        return self.exit_code is not None

    def meta(self) -> dict:
        return {
            "job_id": self.job_id,
            "name": self.name,
            "command": self.command,
            "shell": self.shell,
            "cwd": self.cwd,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.started_at)),
            "exit_code": self.exit_code,
            "finished_at": (
                time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.finished_at))
                if self.finished_at else None
            ),
            "timed_out": self.timed_out,
            "stopped": self.stopped,
            "log": str(self.log_path),
        }


def _kill_tree(pid: int) -> None:
    """递归终止进程树。先 psutil，再用 taskkill /T /F 兜底。"""
    targets: list[psutil.Process] = []
    try:
        parent = psutil.Process(pid)
        targets = parent.children(recursive=True)
        targets.append(parent)
    except psutil.Error:
        targets = []

    for proc in targets:
        try:
            proc.terminate()
        except psutil.Error:
            pass
    _, alive = psutil.wait_procs(targets, timeout=3)
    for proc in alive:
        try:
            proc.kill()
        except psutil.Error:
            pass

    if psutil.pid_exists(pid):
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True, timeout=10,
                creationflags=CREATE_NO_WINDOW,
            )
        except Exception:
            pass


class JobManager:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._ps_exe: str | None = None

    # ------------------------------------------------------------------ 内部

    def _powershell_exe(self) -> str:
        if self._ps_exe is None:
            self._ps_exe = shutil.which("pwsh") or shutil.which("powershell") or "powershell"
        return self._ps_exe

    def _build(self, job: Job, command: str) -> list[str]:
        if job.shell == "powershell":
            script = job.dir / "job.ps1"
            # PowerShell 5.1 读取无 BOM 的 UTF-8 脚本会按 cp936 解释，必须带 BOM
            script.write_text(
                PS_PROLOGUE + "\n" + command + "\nexit $LASTEXITCODE\n",
                encoding="utf-8-sig",
            )
            job.script_path = script
            job.encoding = "utf-8"
            return [
                self._powershell_exe(),
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", str(script),
            ]
        if job.shell == "wsl":
            argv = ["wsl.exe"]
            if self.cfg.wsl_distro:
                argv += ["-d", self.cfg.wsl_distro]
            argv += ["--", "bash", "-lc", command]
            # wsl.exe 的输出是 UTF-16LE，按 UTF-8 解会得到交错空字符
            job.encoding = "utf-16-le"
            return argv
        raise ValueError(f"不支持的 shell：{job.shell}")

    # ------------------------------------------------------------------ 对外

    def start(self, command: str, shell: str = "powershell", cwd: str | None = None,
              name: str = "", request_id: str | None = None) -> Job:
        if shell not in {"powershell", "wsl"}:
            raise ValueError("shell 只能是 powershell 或 wsl")
        job_id = uuid.uuid4().hex[:12]
        job_dir = self.cfg.jobs_path / job_id
        job_dir.mkdir(parents=True, exist_ok=True)

        job = Job(
            job_id=job_id,
            command=command,
            shell=shell,
            cwd=str(cwd or self.cfg.work_dir),
            name=name or command[:60],
            encoding="utf-8",
            dir=job_dir,
            log_path=job_dir / "output.log",
            script_path=None,
            started_at=time.time(),
            request_id=request_id,
        )
        argv = self._build(job, command)

        log_fh = open(job.log_path, "wb")
        try:
            job.proc = subprocess.Popen(
                argv,
                cwd=job.cwd,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
            )
        except Exception:
            log_fh.close()
            raise
        finally:
            # Popen 已经拿到句柄，父进程这边可以关掉
            log_fh.close()

        (job_dir / "meta.json").write_text(
            json.dumps(job.meta(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        with self._lock:
            self.jobs[job_id] = job
        return job

    def _refresh(self, job: Job) -> None:
        if job.done or job.proc is None:
            return
        code = job.proc.poll()
        if code is not None:
            with job.lock:
                if job.exit_code is None:
                    job.exit_code = code
                    job.finished_at = time.time()
            self._write_meta(job)

    def _write_meta(self, job: Job) -> None:
        try:
            (job.dir / "meta.json").write_text(
                json.dumps(job.meta(), ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError:
            pass

    def wait(self, job_id: str, timeout: float) -> bool:
        """等到任务结束或超时。返回是否已结束。"""
        job = self.jobs.get(job_id)
        if job is None:
            raise KeyError(job_id)
        deadline = time.monotonic() + max(0.0, timeout)
        while time.monotonic() < deadline:
            self._refresh(job)
            if job.done:
                return True
            time.sleep(0.1)
        self._refresh(job)
        return job.done

    def tail(self, job: Job, tail_lines: int) -> str:
        return _read_tail(job.log_path, tail_lines, job.encoding)

    def status(self, job_id: str, tail_lines: int = 100) -> dict:
        job = self.jobs.get(job_id)
        if job is None:
            raise KeyError(job_id)
        self._refresh(job)
        return {
            "job_id": job.job_id,
            "name": job.name,
            "shell": job.shell,
            "cwd": job.cwd,
            "status": "finished" if job.done else "running",
            "exit_code": job.exit_code,
            "timed_out": job.timed_out,
            "stopped": job.stopped,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(job.started_at)),
            "duration_s": round((job.finished_at or time.time()) - job.started_at, 2),
            "output": self.tail(job, tail_lines),
            "log_file": str(job.log_path),
            "diagnosis": diagnose_exit(job.exit_code, _log_is_empty(job.log_path)),
        }

    def result(self, job_id: str, tail_lines: int = 200) -> dict:
        """任务结束后的返回体（run_command 用）。"""
        data = self.status(job_id, tail_lines)
        data["status"] = "finished" if data["exit_code"] is not None else "running"
        return data

    def stop(self, job_id: str) -> dict:
        job = self.jobs.get(job_id)
        if job is None:
            raise KeyError(job_id)
        if job.done:
            return self.status(job_id, 50)
        if job.proc is not None:
            _kill_tree(job.proc.pid)
        job.stopped = True
        self._refresh(job)
        if not job.done:
            with job.lock:
                job.exit_code = -1
                job.finished_at = time.time()
            self._write_meta(job)
        return self.status(job_id, 50)

    def run_and_wait(self, command: str, shell: str, cwd: str | None, timeout_s: int,
                     name: str = "", request_id: str | None = None) -> dict:
        """同步执行；超时不丢结果，转后台并返回 job_id。"""
        job = self.start(command, shell=shell, cwd=cwd, name=name, request_id=request_id)
        if self.wait(job.job_id, timeout_s):
            return self.result(job.job_id)
        # 超时：不杀进程，交给调用方轮询（Hark 侧也是这么建议的）
        return {
            "status": "running",
            "job_id": job.job_id,
            "timed_out_after_s": timeout_s,
            "note": "命令仍在后台执行，用 job_status 轮询；结果不会丢。",
            "output": self.tail(job, 100),
            "log_file": str(job.log_path),
        }

    def cleanup(self, max_age_s: int = 7 * 24 * 3600) -> int:
        """清理过期的任务目录。"""
        removed = 0
        now = time.time()
        for job_dir in self.cfg.jobs_path.glob("*"):
            if not job_dir.is_dir():
                continue
            try:
                if now - job_dir.stat().st_mtime > max_age_s:
                    shutil.rmtree(job_dir, ignore_errors=True)
                    removed += 1
            except OSError:
                continue
        return removed


def _log_is_empty(path: Path) -> bool:
    try:
        return path.stat().st_size == 0
    except OSError:
        return True


def _read_tail(path: Path, tail_lines: int, encoding: str, max_bytes: int = 256 * 1024) -> str:
    """读取日志尾部。UTF-16LE 需要按偶数偏移对齐，否则会解出乱码。"""
    try:
        size = path.stat().st_size
    except OSError:
        return ""
    if size == 0:
        return ""

    with open(path, "rb") as fh:
        if size > max_bytes:
            fh.seek(size - max_bytes)
            data = fh.read()
            if encoding == "utf-16-le" and len(data) % 2:
                data = data[1:]
        else:
            data = fh.read()

    text = data.decode(encoding, errors="replace")
    lines = text.splitlines()
    if tail_lines and len(lines) > tail_lines:
        lines = lines[-tail_lines:]
    return "\n".join(lines)


def truncate_output(text: str, max_bytes: int) -> tuple[str, bool]:
    """输出超限时保留末尾部分（日志文件里有完整内容）。"""
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= max_bytes:
        return text, False
    clipped = raw[-max_bytes:]
    return clipped.decode("utf-8", errors="replace"), True


def tail_file_bytes(path: Path, max_bytes: int) -> str:
    try:
        size = path.stat().st_size
    except OSError:
        return ""
    with open(path, "rb") as fh:
        if size > max_bytes:
            fh.seek(size - max_bytes)
        return fh.read().decode("utf-8", errors="replace")


def env_summary() -> dict:
    return {"pid": os.getpid(), "cwd": os.getcwd()}
