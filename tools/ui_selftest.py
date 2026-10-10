r"""面板 UI 自查：真起面板 + 真起浏览器，在手机尺寸和桌面尺寸各截一张图。

用法：``python tools/ui_selftest.py <输出目录>``（用 E:\Python\python.exe 跑）。
需要 playwright；会用系统已装的 Edge（``channel="msedge"``）。

用的是一个**临时环境**（临时 state/logs 目录、临时口令、演示 bot 与演示审批单），
不会碰生产环境。跑完会把截图和 ``layout-report.txt`` 写到输出目录。
"""
from __future__ import annotations

import base64
import io
import pathlib
import socket
import sys
import threading
import time

import uvicorn

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from mcp_server.app import App                      # noqa: E402
from mcp_server.config import Config                # noqa: E402
from mcp_server.panel import PanelApp, PassphraseStore  # noqa: E402
from mcp_server.server import Server                # noqa: E402

OUT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
OUT.mkdir(parents=True, exist_ok=True)
PASSPHRASE = "correct-horse-battery-staple"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def fake_thumb() -> str:
    from PIL import Image, ImageDraw
    image = Image.new("RGB", (640, 360), (24, 28, 36))
    draw = ImageDraw.Draw(image)
    for i in range(0, 640, 40):
        draw.rectangle([i, 0, i + 20, 360], fill=(32, 40, 54))
    draw.rectangle([60, 60, 580, 110], fill=(58, 68, 88))
    draw.rectangle([60, 140, 420, 180], fill=(70, 82, 104))
    draw.rectangle([60, 210, 260, 300], fill=(79, 140, 255))
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=60)
    return "data:image/jpeg;base64," + base64.b64encode(buffer.getvalue()).decode()


def main() -> int:
    root = OUT / "ui-selftest-env"
    if root.exists():
        import shutil
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    work = root / "work"
    work.mkdir(exist_ok=True)
    passphrase = root / "panel.passphrase"
    PassphraseStore(passphrase).set(PASSPHRASE)

    port = free_port()
    cfg = Config(
        host="127.0.0.1", port=free_port(), path="/mcp", tool_prefix="wb_",
        tokens=["S" * 64], admin_token="admin-token-abcdefghijklmnopqrstuvwxyz",
        read_roots=[str(work)], write_roots=[str(work)], work_dir=str(work),
        log_dir=str(root / "logs"), state_dir=str(root / "state"),
        panel={"passphrase_file": str(passphrase), "port": port},
    )
    cfg.ensure_dirs()
    server = Server(cfg)
    app = App(server)
    tools = [(name, "演示工具") for name in (
        "system_info", "system_stats", "list_processes", "list_windows", "list_dir",
        "read_file", "screenshot", "job_status", "approval_status",
        "list_pending_approvals", "agent_status", "uia_snapshot", "uia_wait_for",
        "clipboard_get", "clipboard_set", "type_text", "click", "hotkey",
        "wake_screen", "uia_click", "uia_type", "write_file", "edit_file",
        "run_command", "start_job", "stop_job")]
    panel = PanelApp(cfg, server, tools, app.bots, None)

    # 演示数据：两个 bot + 三条待审批 + 一条已处理 + 一条旧的轮询式审批单
    app.bots.create("phone-claude", note="手机上用的助手",
                    policy={"system_info": "allow", "screenshot": "allow",
                            "click": "ask", "type_text": "ask", "hotkey": "ask",
                            "run_command": "ask", "write_file": "ask",
                            "clipboard_get": "allow"})
    app.bots.create("hark", note="桌面主力", protected=True,
                    policy={"system_info": "allow", "run_command": "ask",
                            "click": "ask"})
    server.runtime.update({"ntfy_topic": "wmcp-replace-with-your-own-topic"})
    server.remote.create(bot="phone-claude", bot_id="", tools=["click"],
                         summary="click: x=812 y=460 button=left clicks=1",
                         arg_keys=["button", "clicks", "x", "y"],
                         thumb=fake_thumb(), wait_s=120)
    server.remote.create(bot="hark", bot_id="", tools=["run_command"],
                         summary="run_command: command=Get-Process | Select-Object -First 5",
                         arg_keys=["command"], thumb=fake_thumb(), wait_s=120)
    server.remote.create(bot="phone-claude", bot_id="", tools=["type_text"],
                         summary="type_text: text=你好，帮我打开设置 interval_ms=0",
                         arg_keys=["interval_ms", "text"], wait_s=120)
    decided = server.remote.create(bot="hark", bot_id="", tools=["hotkey"],
                                   summary="hotkey: keys=win+r repeat=1",
                                   arg_keys=["keys", "repeat"], wait_s=120)
    server.remote.decide(decided.approval_id, True, actor="lanxinyao")
    ticket = server.tool_lock.request("hark", "uia_type")
    server.tool_lock.try_acquire(ticket)
    server.tool_lock.request("phone-claude", "click")
    server.approvals.create("run_command", {"command": "Remove-Item -Recurse x"},
                            "powershell: Remove-Item -Recurse x", level="H")
    server.audit.call("system_info", {}, "R", "allowed", 12, "ok")
    server.audit.call("run_command", {"command": "whoami"}, "H", "awaiting_approval", 0,
                      "等待批准")

    uv = uvicorn.Server(uvicorn.Config(panel, host="127.0.0.1", port=port,
                                       log_level="warning", access_log=False))
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    import httpx
    deadline = time.time() + 25
    while time.time() < deadline:
        try:
            if httpx.get(f"{base}/healthz", timeout=1).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.05)
    else:
        raise SystemExit("面板起不来")

    CHECK = """() => {
      const out = {hscroll: 0, overflow: [], smallTap: [], overlap: [], longToken: null,
                   title: document.title, view: location.hash};
      const de = document.documentElement;
      const vw = window.innerWidth;
      out.hscroll = de.scrollWidth - vw;
      document.querySelectorAll('body *').forEach((el) => {
        const r = el.getBoundingClientRect();
        if (r.width < 1 || r.height < 1) return;
        const cs = getComputedStyle(el);
        if (cs.position === 'fixed' || cs.visibility === 'hidden' || cs.display === 'none')
          return;
        if (r.right > vw + 1 || r.left < -1) {
          out.overflow.push(el.tagName + '.' + (typeof el.className === 'string'
            ? el.className : '') + ' x=' + Math.round(r.left) + '..' + Math.round(r.right));
        }
      });
      document.querySelectorAll('button').forEach((b) => {
        const r = b.getBoundingClientRect();
        if (r.height > 0 && r.height < 43) {
          out.smallTap.push((b.textContent || '').trim().slice(0, 10)
            + ' h=' + Math.round(r.height));
        }
      });
      document.querySelectorAll('.acts, .row, .seg, .rail').forEach((g) => {
        const kids = [...g.children].filter((k) => k.getBoundingClientRect().height > 0);
        for (let i = 1; i < kids.length; i++) {
          const a = kids[i - 1].getBoundingClientRect();
          const b = kids[i].getBoundingClientRect();
          if (b.left < a.right - 1 && b.top < a.bottom - 1 && b.bottom > a.top + 1) {
            out.overlap.push((kids[i - 1].textContent || '').trim().slice(0, 10)
              + ' / ' + (kids[i].textContent || '').trim().slice(0, 10));
          }
        }
      });
      const found = (document.body.innerText.match(/[A-Za-z0-9_\\-]{40,}/g) || []);
      out.longToken = found.slice(0, 3);
      return out;
    }"""

    from playwright.sync_api import sync_playwright

    reports: list[str] = []
    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(channel="msedge")
        except Exception:
            browser = pw.chromium.launch()
        for label, width, height, device_scale in (("mobile", 390, 844, 2),
                                                   ("desktop", 1280, 900, 1)):
            page = browser.new_page(viewport={"width": width, "height": height},
                                    device_scale_factor=device_scale)
            page.goto(base, wait_until="networkidle")
            page.fill("#pp", PASSPHRASE)
            page.click("#doLogin")
            page.wait_for_selector("#view-approvals:not(.hidden)", timeout=15000)
            page.wait_for_timeout(1200)
            page.screenshot(path=str(OUT / f"panel-{label}-approvals.png"),
                            full_page=True)
            reports.append(f"[{label} {width}x{height}] approvals -> "
                           + repr(page.evaluate(CHECK)))
            for view in ("bots", "audit", "settings"):
                page.click(f'.rail button.tab[data-view="{view}"]')
                page.wait_for_timeout(700)
                page.screenshot(path=str(OUT / f"panel-{label}-{view}.png"),
                                full_page=True)
                reports.append(f"[{label} {width}x{height}] {view} -> "
                               + repr(page.evaluate(CHECK)))
            if label == "mobile":
                page.click('.rail button.tab[data-view="bots"]')
                page.wait_for_timeout(400)
                page.click('button[data-bact="detail"]')
                page.wait_for_timeout(600)
                page.screenshot(path=str(OUT / "panel-mobile-bot-detail.png"))
                reports.append("[mobile] bot-detail -> " + repr(page.evaluate(CHECK)))
        # 额外两张：未登录的登录页，以及浅色主题下的审批页（含文本转储，便于逐字核对）
        page = browser.new_page(viewport={"width": 390, "height": 844},
                                device_scale_factor=2)
        page.goto(base, wait_until="networkidle")
        page.wait_for_timeout(400)
        page.screenshot(path=str(OUT / "panel-mobile-login.png"), full_page=True)
        page.fill("#pp", PASSPHRASE)
        page.click("#doLogin")
        page.wait_for_selector("#view-approvals:not(.hidden)", timeout=15000)
        page.click('.rail button.tab[data-view="settings"]')
        page.wait_for_timeout(400)
        page.click('#themeSeg button[data-th="light"]')
        page.click('.rail button.tab[data-view="approvals"]')
        page.wait_for_timeout(800)
        page.screenshot(path=str(OUT / "panel-mobile-light.png"), full_page=True)
        (OUT / "approvals-text.txt").write_text(page.inner_text("body"),
                                                encoding="utf-8")
        page.close()
        page.close()
        browser.close()

    (OUT / "layout-report.txt").write_text("\n".join(reports), encoding="utf-8")
    for line in reports:
        print(line)
    uv.should_exit = True
    thread.join(5)
    print("截图写到", OUT)
    return 0
    for line in reports:
        print(line)
    uv.should_exit = True
    thread.join(5)
    print("截图写到", OUT)
    return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
