"""任务执行层测试：编码处理与超时转后台。"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from mcp_server.config import Config
from mcp_server.jobs import JobManager, _read_tail, diagnose_exit, truncate_output


@pytest.fixture
def manager(tmp_path):
    cfg = Config(
        tokens=["x"],
        work_dir=str(tmp_path / "work"),
        log_dir=str(tmp_path / "logs"),
        state_dir=str(tmp_path / "state"),
        read_roots=[str(tmp_path / "work")],
        write_roots=[str(tmp_path / "work")],
    )
    cfg.ensure_dirs()
    return JobManager(cfg), cfg


def test_powershell_output_is_utf8(manager):
    """本机 powershell.exe 默认 cp936，必须先置 UTF-8 输出编码。"""
    jobs, cfg = manager
    result = jobs.run_and_wait('Write-Output "中文测试 ok"', "powershell", cfg.work_dir, 40)
    assert result["status"] == "finished"
    assert result["exit_code"] == 0
    assert "中文测试 ok" in result["output"]
    assert "\x00" not in result["output"]


def test_powershell_exit_code_propagates(manager):
    jobs, cfg = manager
    result = jobs.run_and_wait("cmd /c exit 7", "powershell", cfg.work_dir, 40)
    assert result["exit_code"] == 7


def test_powershell_script_bom_for_non_ascii_source(manager):
    """脚本里带中文时，必须靠 BOM 让 PowerShell 5.1 正确解析。"""
    jobs, cfg = manager
    script = 'Write-Output "路径：C:\\工作\\项目"'
    result = jobs.run_and_wait(script, "powershell", cfg.work_dir, 40)
    assert "路径：C:\\工作\\项目" in result["output"]


def test_timeout_hands_off_to_background(manager):
    jobs, cfg = manager
    result = jobs.run_and_wait("Start-Sleep -Seconds 20", "powershell", cfg.work_dir, 2)
    assert result["status"] == "running"
    assert result["job_id"]
    jobs.stop(result["job_id"])
    status = jobs.status(result["job_id"], 10)
    assert status["stopped"] is True


def test_kill_tree_terminates_children(manager):
    jobs, cfg = manager
    result = jobs.run_and_wait("Start-Sleep -Seconds 60", "powershell", cfg.work_dir, 1)
    job_id = result["job_id"]
    jobs.stop(job_id)
    status = jobs.status(job_id, 10)
    assert status["exit_code"] is not None


def test_utf16le_tail_decoding(tmp_path):
    """wsl.exe 输出是 UTF-16LE，按 UTF-8 解会得到交错空字符。"""
    path = tmp_path / "out.log"
    path.write_bytes("Ubuntu\n中文\n".encode("utf-16-le"))
    text = _read_tail(path, 10, "utf-16-le")
    assert "Ubuntu" in text
    assert "中文" in text
    assert "\x00" not in text


def test_utf16le_tail_odd_offset_alignment(tmp_path):
    """截断到奇数偏移时必须对齐，否则解出乱码。"""
    path = tmp_path / "out.log"
    path.write_bytes(("X" * 5000 + "\n结束\n").encode("utf-16-le"))
    text = _read_tail(path, 5, "utf-16-le", max_bytes=101)
    assert "\x00" not in text


def test_truncate_output_keeps_tail():
    text = "A" * 100 + "TAIL"
    clipped, truncated = truncate_output(text, 10)
    assert truncated is True
    assert clipped.endswith("TAIL")


def test_diagnose_exit_flags_startup_crash():
    """PowerShell 启动期崩溃不能被当成命令执行结果。"""
    diag = diagnose_exit(0x800703E9, log_empty=True)
    assert diag["retry_safe"] is True
    assert diag["code_hex"] == "0x800703e9"
    assert "堆栈溢出" in diag["reason"]


def test_diagnose_exit_not_retry_safe_when_output_exists():
    diag = diagnose_exit(0xC00000FD, log_empty=False)
    assert diag["retry_safe"] is False
    assert "部分执行" in diag["hint"]


def test_diagnose_exit_terminated_is_never_retry_safe():
    diag = diagnose_exit(0xC000013A, log_empty=True)
    assert diag["retry_safe"] is False


def test_diagnose_exit_ignores_normal_codes():
    assert diagnose_exit(0, log_empty=True) is None
    assert diagnose_exit(1, log_empty=False) is None
    assert diagnose_exit(None, log_empty=True) is None


def test_status_includes_diagnosis_for_normal_run(manager):
    jobs, cfg = manager
    result = jobs.run_and_wait("dir", "powershell", cfg.work_dir, 40)
    assert result["diagnosis"] is None


def test_job_meta_written(manager):
    jobs, cfg = manager
    result = jobs.run_and_wait("dir", "powershell", cfg.work_dir, 40)
    log_file = Path(result["log_file"])
    assert log_file.exists()
    assert (log_file.parent / "meta.json").exists()
