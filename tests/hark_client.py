"""模拟 Hark 客户端的调用方式。

严格按照 Hark 实测行为（文档 §11 第 1 条）：
* 只走 Streamable HTTP，不开 GET 长连接；
* 每次调用都是全新会话：initialize → initialized → tools/call → DELETE；
* initialize 发 protocolVersion，之后每个请求带 Mcp-Protocol-Version；
* 每个 POST 都带 Accept: application/json, text/event-stream；
* 鉴权走单头 Authorization: Bearer <token>。

这个客户端既是测试工具，也是排查隧道问题时的探针：
    python -m tests.hark_client http://127.0.0.1:8765/mcp <token> system_stats
"""

from __future__ import annotations

import json
import sys

import httpx

PROTOCOL_VERSION = "2025-11-25"


class HarkError(RuntimeError):
    pass


class HarkClient:
    def __init__(self, url: str, token: str, protocol_version: str = PROTOCOL_VERSION,
                 timeout: float = 30.0) -> None:
        self.url = url
        self.token = token
        self.protocol_version = protocol_version
        self.timeout = timeout
        self._counter = 0
        self.last_session_id: str | None = None

    # ------------------------------------------------------------------ 内部

    def _next_id(self) -> int:
        self._counter += 1
        return self._counter

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Mcp-Protocol-Version": self.protocol_version,
        }

    def _parse(self, response: httpx.Response) -> dict:
        content_type = response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            payload = None
            for line in response.text.splitlines():
                if line.startswith("data:"):
                    payload = json.loads(line[5:].strip())
            if payload is None:
                raise HarkError(f"SSE 响应里没有 data 行：{response.text[:200]}")
            return payload
        try:
            return response.json()
        except ValueError as exc:
            raise HarkError(f"响应不是 JSON（{response.status_code}）：{response.text[:200]}") from exc

    def _post(self, payload: dict) -> dict:
        response = httpx.post(self.url, json=payload, headers=self._headers(),
                              timeout=self.timeout)
        if response.status_code >= 400:
            raise HarkError(f"HTTP {response.status_code}: {response.text[:300]}")
        if response.status_code == 202 or not response.content:
            return {}
        session = response.headers.get("mcp-session-id")
        if session:
            self.last_session_id = session
        return self._parse(response)

    def _delete(self) -> None:
        try:
            httpx.request("DELETE", self.url, headers=self._headers(), timeout=self.timeout)
        except Exception:
            pass

    # ------------------------------------------------------------------ 会话

    def initialize(self) -> dict:
        result = self._post({
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "initialize",
            "params": {
                "protocolVersion": self.protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "hark-agent", "version": "emulated"},
            },
        })
        # initialized 通知：无 id，服务器应返回 202
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return result.get("result", result)

    def request(self, method: str, params: dict | None = None, *, new_session: bool = True) -> dict:
        if new_session:
            self.initialize()
        response = self._post({
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
            "params": params or {},
        })
        if new_session:
            self._delete()
        if "error" in response:
            raise HarkError(f"{method} 返回错误：{response['error']}")
        return response.get("result", {})

    # ------------------------------------------------------------------ 工具

    def list_tools(self) -> list[dict]:
        return self.request("tools/list", {}).get("tools", [])

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        result = self.request("tools/call", {"name": name, "arguments": arguments or {}})
        return _unwrap(result)

    def call_raw(self, name: str, arguments: dict | None = None) -> dict:
        """返回原始 tools/call 结果（用于检查 isError 之类的传输层字段）。"""
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})


def _unwrap(result: dict) -> dict:
    """把 MCP 的 content 数组还原成工具返回的 JSON。"""
    if "structuredContent" in result and result["structuredContent"]:
        return result["structuredContent"]
    texts = [block.get("text", "") for block in result.get("content", [])
             if block.get("type") == "text"]
    if not texts:
        return {"raw": result}
    joined = "\n".join(texts)
    try:
        return json.loads(joined)
    except json.JSONDecodeError:
        return {"text": joined}


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print(__doc__)
        return 2
    url, token, tool = argv[1], argv[2], argv[3]
    arguments = json.loads(argv[4]) if len(argv) > 4 else {}
    client = HarkClient(url, token)
    init = client.initialize()
    print("initialize ->", json.dumps(init.get("serverInfo", init), ensure_ascii=False))
    print("tools/list ->", len(client.list_tools()), "个工具")
    print(f"tools/call {tool} ->")
    print(json.dumps(client.call_tool(tool, arguments), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
