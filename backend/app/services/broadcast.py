"""Diffusion WebSocket : un hub par canal (packets, stats, alerts)."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class Broadcaster:
    """Gere les connexions WebSocket par canal et diffuse les messages JSON."""

    def __init__(self) -> None:
        """Initialise le registre des connexions, vide."""
        self._channels: dict[str, set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def connect(self, channel: str, websocket: WebSocket) -> None:
        """Accepte une connexion WebSocket et l'inscrit sur un canal."""
        await websocket.accept()
        async with self._lock:
            self._channels[channel].add(websocket)
        logger.debug("WS connecte sur %s (%d clients)", channel, len(self._channels[channel]))

    async def disconnect(self, channel: str, websocket: WebSocket) -> None:
        """Retire une connexion du canal."""
        async with self._lock:
            self._channels[channel].discard(websocket)

    def client_count(self, channel: str | None = None) -> int:
        """Nombre de clients connectes, sur un canal donne ou au total."""
        if channel:
            return len(self._channels.get(channel, ()))
        return sum(len(clients) for clients in self._channels.values())

    async def publish(self, channel: str, payload: dict[str, Any]) -> None:
        """Envoie a tous les clients du canal ; retire silencieusement les morts."""
        async with self._lock:
            clients = list(self._channels.get(channel, ()))
        if not clients:
            return

        dead: list[WebSocket] = []
        for client in clients:
            try:
                await client.send_json(payload)
            except Exception:  # noqa: BLE001 — connexion fermee cote client
                dead.append(client)

        if dead:
            async with self._lock:
                for client in dead:
                    self._channels[channel].discard(client)


broadcaster = Broadcaster()

CHANNEL_PACKETS = "packets"
CHANNEL_STATS = "stats"
CHANNEL_ALERTS = "alerts"
