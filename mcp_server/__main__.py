"""入口：python -m mcp_server

一个进程、两个监听：

* 主线程跑 MCP 本体（``cfg.host:cfg.port``，只监听 127.0.0.1）；
* 一个后台守护线程跑管理面板（``cfg.panel_settings.host:port``，同样只监听本机）。

为什么面板要挤在同一个进程里：现有的自启/看门狗（计划任务 + ``supervise.py``）
只盯这一个进程。面板另起一个进程就得再加一套守护，收益为零、故障面翻倍。
面板线程挂了不影响 MCP 本体，反之亦然。
"""

from __future__ import annotations

import sys
import threading
import time


def _set_dpi_awareness() -> str:
    """文档 §4.3：不声明 per-monitor DPI 感知，截图坐标与点击坐标会对不上。"""
    try:
        import ctypes

        # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 == -4
        if ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
            return "per-monitor-v2"
        if ctypes.windll.shcore.SetProcessDpiAwareness(2):
            return "per-monitor"
    except Exception:
        pass
    return "system-default"


def _collect_tools(server, cfg) -> tuple[str, list[tuple[str, str]]]:
    """工具数 + [(内部名, 说明)]。面板的白名单勾选框就用它，所以要用**内部名**。"""
    try:
        import asyncio

        listed = asyncio.run(server.mcp.list_tools())
    except Exception:
        return "未知", []
    prefix = cfg.tool_prefix or ""
    tools: list[tuple[str, str]] = []
    for tool in listed:
        name = str(getattr(tool, "name", "") or "")
        internal = name[len(prefix):] if prefix and name.startswith(prefix) else name
        tools.append((internal, str(getattr(tool, "description", "") or "")))
    return str(len(listed)), tools


def _panel_loop(panel, settings) -> None:
    """面板的 uvicorn。端口被占等错误重试几次后放弃——绝不带崩 MCP 本体。"""
    import uvicorn

    for attempt in range(1, 6):
        try:
            uvicorn.Server(uvicorn.Config(
                panel, host=settings.host, port=settings.port,
                log_level="warning", access_log=False,
            )).run()
            return
        except KeyboardInterrupt:
            return
        except BaseException as exc:  # uvicorn 绑定失败会 sys.exit(1)（SystemExit）
            print(f"[panel] 启动失败（第 {attempt}/5 次）：{type(exc).__name__}: {exc}")
            if attempt < 5:
                time.sleep(2)
    print("[panel] 连续 5 次失败，放弃启动面板；MCP 本体不受影响。")


def _start_panel(cfg, server, bots, tools) -> threading.Thread | None:
    from . import access as access_mod
    from .panel import PanelApp, PanelDisabled

    settings = cfg.panel_settings
    if not settings.enabled:
        print("  管理面板    : 已在配置里关闭（panel.enabled = false）")
        return None

    verifier = access_mod.AccessVerifier(
        team=settings.access_team,
        aud=settings.access_aud,
        emails=settings.access_emails,
        jwks_file=settings.access_jwks_file,
        cache_file=settings.access_cache_file,
    )
    try:
        panel = PanelApp(cfg, server, tools, bots, verifier)
    except PanelDisabled as exc:
        print(f"  管理面板    : 未启动 —— {exc}")
        return None

    thread = threading.Thread(target=_panel_loop, args=(panel, settings),
                              name="panel", daemon=True)
    thread.start()
    modes = {"both": "口令 + Access（经 Cloudflare 时）", "either": "口令或 Access",
             "passphrase": "只要口令", "access": "只要 Access"}
    print(f"  管理面板    : http://{settings.host}:{settings.port}/ "
          f"（{modes.get(settings.auth_mode, settings.auth_mode)}）")
    if settings.public_url:
        print(f"                公网入口：{settings.public_url}/")
    else:
        print("                公网入口：未配置（panel.public_url 为空）")
    print(f"                口令文件：{settings.passphrase_file}"
          f"（{'已配置' if panel.passphrase.configured() else '未配置'}）")
    access_state = "已启用" if verifier.configured() else "未启用（缺 access_aud）"
    print(f"                Cloudflare Access：{access_state}")
    return thread


def main() -> int:
    import uvicorn

    from . import config as config_module
    from . import desktop
    from .app import App
    from .server import Server

    dpi = _set_dpi_awareness()
    cfg = config_module.load()
    server = Server(cfg)
    app = App(server)

    removed = server.jobs.cleanup()
    tool_count, tools = _collect_tools(server, cfg)

    # 屏幕常亮必须挂在长期存活的线程上，这里是主线程，正好符合。
    display: dict = {}
    if cfg.keep_display_awake:
        display["keep_awake"] = desktop.keep_display_awake()
    if cfg.disable_screensaver:
        display["screensaver"] = desktop.disable_screensaver()
    if cfg.power_tweaks:
        display["power"] = desktop.apply_power_tweaks()
    if cfg.disable_dynamic_lock:
        display["dynamic_lock"] = desktop.disable_dynamic_lock()

    print("=" * 68)
    print("Windows MCP 服务器")
    print(f"  监听        : http://{cfg.host}:{cfg.port}{cfg.path}")
    print(f"  工具数      : {tool_count}")
    rows = app.registry.describe()
    static_names = [r["name"] for r in rows if r["source"] == "config"]
    bot_names = [r["name"] for r in rows if r["source"] == "bot"]
    print(f"  静态 token  : {len(static_names)} 个 -> {', '.join(static_names) or '（无）'}"
          "（全量权限，白名单不适用）")
    print(f"  bot token   : {len(bot_names)} 个 -> {', '.join(bot_names) or '（无）'}"
          "（带白名单，可在面板里改）")
    print("                （审计日志按这里的名字归属调用方；token 值永不落盘）")
    print(f"  DPI 感知    : {dpi}")
    print(f"  工作目录    : {cfg.work_dir}")
    print(f"  可读根目录  : {', '.join(cfg.read_roots)}")
    print(f"  可写根目录  : {', '.join(cfg.write_roots)}")
    print(f"  审批有效期  : {cfg.approval_ttl_s} 秒")
    print(f"  截屏级别    : {cfg.screenshot_level}")
    print(f"  GUI 级别    : {cfg.gui_level}（R=免审批）")
    print(f"  命令超时    : 默认 {cfg.default_timeout_s} 秒 / 上限 {cfg.max_timeout_s} 秒")
    print(f"  {server.notifier.dump_config_summary()}")

    if cfg.keep_display_awake:
        state = display.get("keep_awake", {})
        print("  屏幕常亮    : " + ("已开启，显示器不会自动熄灭"
                                    if state.get("ok") else "设置失败"))
    if cfg.disable_screensaver:
        before = display.get("screensaver", {}).get("before", {})
        print(f"  屏保        : 已关闭（改前 ScreenSaveActive={before.get('ScreenSaveActive')}）")
    if cfg.power_tweaks:
        power = display.get("power", {})
        if power.get("all_ok"):
            print("  电源方案    : 关显示器 / 睡眠 / 休眠 已全部设为「永不」")
        else:
            failed = [f"{k}({v})" for k, v in power.items()
                      if k != "all_ok" and v != "ok"]
            print("  电源方案    : 部分失败 -> " + "；".join(failed))
    if cfg.disable_dynamic_lock:
        lock = display.get("dynamic_lock", {})
        if lock.get("error"):
            print(f"  动态锁      : 关闭失败 -> {lock['error']}")
        else:
            print(f"  动态锁      : 已关闭（改前 EnableGoodbye={lock.get('before')}），"
                  "手机离开蓝牙范围不会再锁屏")

    # 合盖动作 / 唤醒是否需要密码：这两项要管理员才能改，所以服务器只读不改，
    # 只把当前值打出来，方便判断「为什么合盖还是会锁屏」。
    power_state = desktop.display_settings()
    lid = power_state.get("lid_close_action")
    if lid:
        names = {0: "不采取任何操作", 1: "睡眠", 2: "休眠", 3: "关机"}
        print(f"  合盖动作    : {names.get(lid['ac'], lid['ac'])}（交流） / "
              f"{names.get(lid['dc'], lid['dc'])}（电池）")
    console = power_state.get("require_password_on_wakeup")
    if console:
        print("  唤醒要密码  : "
              + ("是（唤醒后会停在锁屏界面）" if console["ac"] or console["dc"]
                 else "否（唤醒后直接回到桌面）"))

    if removed:
        print(f"  已清理过期任务目录：{removed} 个")
    for warning in cfg.load_warnings:
        print(f"  警告        : {warning}")
    for warning in app.bots.warnings:
        print(f"  警告        : {warning}")
    if not cfg.public_base_url:
        print("  提示        : 未配置 public_base_url，审批链接会是本机地址，手机点不开。")
    _start_panel(cfg, server, app.bots, tools)
    print("=" * 68)

    try:
        uvicorn.run(app, host=cfg.host, port=cfg.port, log_level="info", access_log=False)
    finally:
        # 使用计数是节流落盘的，退出前补一次
        try:
            app.bots.flush_touch()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
