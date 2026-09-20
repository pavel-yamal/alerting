"""Channel lookup and the default set for the prototype."""

from __future__ import annotations

from alerting.server.channels.base import Channel
from alerting.server.channels.push import PushChannel
from alerting.server.channels.siren import SirenChannel
from alerting.server.channels.sms import SmsChannel
from alerting.server.channels.voice import VoiceChannel
from alerting.server.channels.websocket import ConnectionRegistry, WebSocketChannel


class ChannelRegistry:
    def __init__(self, channels: dict[str, Channel]) -> None:
        self._channels = channels

    def get(self, name: str) -> Channel | None:
        return self._channels.get(name)

    def names(self) -> list[str]:
        return sorted(self._channels)

    def __getitem__(self, name: str) -> Channel:
        return self._channels[name]


def default_registry(connections: ConnectionRegistry, org_label: str = "ACME") -> ChannelRegistry:
    """WebSocket is real; the rest are stubs with a clear seam for a provider."""
    return ChannelRegistry(
        {
            "ws": WebSocketChannel(connections),
            "push": PushChannel(),
            "sms": SmsChannel(org_label),
            "voice": VoiceChannel(org_label),
            "siren": SirenChannel(),
        }
    )
