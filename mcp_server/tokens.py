"""token 名册：把「config.toml 里的静态 token」和「面板管理的 bot token」合成一个入口。

为什么要合起来
--------------
鉴权只有一个地方做（``app.py`` 的 ASGI 外壳），但它现在要面对两类凭据：

* **静态 token**：``config.toml`` 的 ``tokens`` / ``named_tokens`` / ``token_files``。
  没有白名单限制（全量权限），行为与加面板之前完全一致。
* **bot token**：面板里建的，带白名单 / 过期 / 启用开关，改完**立即生效**（无需重启）。

``resolve()`` 是唯一的判定入口，返回 :class:`Identity`；调用方拿到后决定
「放行 / 401 / 403」。所有比较都遍历全部候选、不提前返回（时序一致性）。
"""

from dataclasses import dataclass, field

from dataclasses import dataclass
from .bots import ALL, Bot, BotStore
from .policy import level_for as _level_for
from .security import match_token_name

@dataclass(frozen=True)
class Identity:
    """一次成功辨认出的调用方。"""
@dataclass(frozen=True)
class Identity:
    """一次成功辨认出的调用方。"""

    name: str                      # 进审计日志的名字（不是 token 值）
    source: str                    # "config" | "bot"
    allow: tuple[str, ...] | None  # None = 全量权限；否则是内部工具名白名单
    policy: dict[str, str] = field(default_factory=dict)  # 逐工具三档策略
    bot_id: str | None = None
    status: str = "ok"             # ok / disabled / expired

    def allows(self, tool: str) -> bool:
        """``tool`` 是**不带前缀的内部名**。全量权限一律放行。"""
        if self.allow is None:
            return True
        return ALL in self.allow or tool in self.allow

    def level_for(self, tool: str) -> str:
        """这个工具对这个身份的实际档位：allow / ask / deny。

        静态 token（``allow is None``）永远是 ``allow``：它们没有「bot」这个身份，
        也就没有可以逐工具配置的策略，行为与加面板之前一致。
        """
        return _level_for(self.allow, self.policy, tool)

    @property
    def unrestricted(self) -> bool:
        """全量权限（静态 token，或 allow 里写了 "*"）。"""
        return self.allow is None or ALL in self.allow

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "source": self.source,
            "allow": None if self.allow is None else list(self.allow),
            "policy": dict(self.policy),
            "bot_id": self.bot_id,
            "status": self.status,
        }


class TokenRegistry:
    """静态名册 + bot 名册的统一视图。线程安全（内部只读快照 + store 自己加锁）。"""

    def __init__(self, static_entries: list[tuple[str, str]] | None = None,
                 store: BotStore | None = None) -> None:
        self._static: list[tuple[str, str]] = list(static_entries or [])
        self.store = store

    # ------------------------------------------------------------ 刷新

    def refresh_static(self, entries: list[tuple[str, str]] | None) -> None:
        """换掉静态名册（面板改不动它，只有配置重载会用到）。"""
        self._static = list(entries or [])

    def static_entries(self) -> list[tuple[str, str]]:
        return list(self._static)

    # ------------------------------------------------------------ 判定

    def resolve(self, presented: str) -> Identity | None:
        """命中就返回 Identity（可能 status != ok），完全没命中返回 None。"""
        if not presented:
            return None
        # 1) 静态 token（全量权限）
        name = match_token_name(presented, self._static)
        if name is not None:
            return Identity(name=name, source="config", allow=None)
        # 2) bot token（带白名单 / 过期 / 禁用）
        if self.store is not None:
            bot, status = self.store.verify(presented)
            if bot is not None:
                return Identity(name=bot.name, source="bot", allow=bot.allow,
                                policy=dict(bot.policy),
                                bot_id=bot.id, status=status)
        return None

    def usable(self) -> bool:
        """有没有至少一条能用的凭据？没有的话服务起来也没意义。"""
        if self._static:
            return True
        return self.store is not None and self.store.enabled_count() > 0

    def names(self) -> list[str]:
        out = [name for name, _ in self._static]
        if self.store is not None:
            for item in self.store.list_public():
                if item["name"] not in out:
                    out.append(item["name"])
        return out

    def describe(self) -> list[dict]:
        """给启动 banner 用：名字 + 来源 + 状态。"""
        rows: list[dict] = []
        for name, _ in self._static:
            rows.append({"name": name, "source": "config", "status": "ok",
                         "allow": None})
        if self.store is not None:
            for item in self.store.list_public():
                rows.append({"name": item["name"], "source": "bot",
                             "status": item["status"], "allow": item["allow"]})
        return rows


def bot_of(store: BotStore | None, bot_id: str | None) -> Bot | None:
    if store is None or not bot_id:
        return None
    return store.get(bot_id)
