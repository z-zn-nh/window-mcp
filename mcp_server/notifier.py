"""审批推送。

文档 §6.5：审批通道是安全设计的一环，不能是单点。
这里实现三条可选通道，全部失败也不影响审批单本身——审批单已经落盘，
还能通过 /admin/approve 端点或 CLI 处理。

通道配置（config.toml 的 [server.notifier]）：
    [server.notifier.ntfy]
    enabled = true
    server  = "https://ntfy.sh"
    topic   = "你的私有主题"
    token   = ""            # 可选

    [server.notifier.webhook]
    enabled = true
    url     = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..."
    format  = "wecom"       # generic / wecom / dingtalk / serverchan

    [server.notifier.telegram]
    enabled = true
    bot_token = "..."
    chat_id   = "..."
"""

from __future__ import annotations

import json
import urllib.parse

import httpx

from .approvals import Approval
from .config import Config

TIMEOUT = 10.0


class Notifier:
    def __init__(self, cfg: Config, audit) -> None:
        self.cfg = cfg
        self.audit = audit
        self.channels = cfg.notifier or {}

    # ------------------------------------------------------------------ 对外

    def configured(self) -> list[str]:
        return [name for name, conf in self.channels.items()
                if isinstance(conf, dict) and conf.get("enabled")]

    def send_approval(self, approval: Approval) -> dict:
        approve_url, reject_url = self.approval_urls(approval.approval_id)
        text = self._render(approval, approve_url, reject_url)
        results: dict[str, str] = {}
        for name in self.configured():
            conf = self.channels[name]
            try:
                sender = getattr(self, f"_send_{name}", None)
                if sender is None:
                    results[name] = "unknown_channel"
                    continue
                sender(conf, text, approval, approve_url, reject_url)
                results[name] = "sent"
            except Exception as exc:  # 通道失败不能影响审批流程
                results[name] = f"failed: {type(exc).__name__}: {exc}"
        self.audit.note("notify", approval_id=approval.approval_id, results=results)
        return results

    def approval_urls(self, approval_id: str) -> tuple[str, str]:
        base = self.cfg.public_base_url or f"http://{self.cfg.host}:{self.cfg.port}"
        token = urllib.parse.quote(self.cfg.admin_token, safe="")
        approve = f"{base}/admin/approve?id={approval_id}&token={token}"
        reject = f"{base}/admin/reject?id={approval_id}&token={token}"
        return approve, reject

    # ------------------------------------------------------------------ 内部

    @staticmethod
    def _render(approval: Approval, approve_url: str, reject_url: str) -> str:
        import time
        expires = time.strftime("%H:%M:%S", time.localtime(approval.expires_at))
        lines = [
            "【MCP 高危操作待批准】",
            f"工具：{approval.tool}",
            f"内容：{approval.summary}",
            f"审批号：{approval.approval_id}",
            f"有效期至：{expires}（超时自动拒绝）",
            f"批准：{approve_url}",
            f"拒绝：{reject_url}",
        ]
        return "\n".join(lines)

    def _send_ntfy(self, conf: dict, text: str, approval: Approval,
                   approve_url: str, reject_url: str) -> None:
        server = (conf.get("server") or "https://ntfy.sh").rstrip("/")
        topic = conf["topic"]
        headers = {"Title": "MCP 待批准", "Priority": "4", "Tags": "warning"}
        if conf.get("token"):
            headers["Authorization"] = f"Bearer {conf['token']}"
        body = {
            "topic": topic,
            "message": text,
            "actions": [
                {"action": "view", "label": "批准", "url": approve_url, "clear": True},
                {"action": "view", "label": "拒绝", "url": reject_url, "clear": True},
            ],
        }
        resp = httpx.post(f"{server}/", json=body, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()

    def _send_webhook(self, conf: dict, text: str, approval: Approval,
                      approve_url: str, reject_url: str) -> None:
        url = conf["url"]
        fmt = (conf.get("format") or "generic").lower()
        if fmt == "wecom":
            body = {"msgtype": "text", "text": {"content": text}}
        elif fmt == "dingtalk":
            body = {"msgtype": "text", "text": {"content": text}}
        elif fmt == "serverchan":
            body = {"title": "MCP 待批准", "desp": text.replace("\n", "\n\n")}
        else:
            body = {
                "title": "MCP 待批准",
                "text": text,
                "approval_id": approval.approval_id,
                "tool": approval.tool,
                "summary": approval.summary,
                "approve_url": approve_url,
                "reject_url": reject_url,
            }
        resp = httpx.post(url, json=body, timeout=TIMEOUT)
        resp.raise_for_status()

    def _send_telegram(self, conf: dict, text: str, approval: Approval,
                       approve_url: str, reject_url: str) -> None:
        api = f"https://api.telegram.org/bot{conf['bot_token']}/sendMessage"
        body = {
            "chat_id": conf["chat_id"],
            "text": text,
            "disable_web_page_preview": True,
            "reply_markup": {
                "inline_keyboard": [[
                    {"text": "批准", "url": approve_url},
                    {"text": "拒绝", "url": reject_url},
                ]]
            },
        }
        resp = httpx.post(api, json=body, timeout=TIMEOUT)
        resp.raise_for_status()

    def dump_config_summary(self) -> str:
        names = self.configured()
        if not names:
            return "未配置任何审批推送通道：审批单只会写审计日志，请用 /admin/pending 查看。"
        return "审批推送通道：" + ", ".join(names)
