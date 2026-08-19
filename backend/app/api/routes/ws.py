"""Canaux WebSocket temps reel.

Trois canaux :
  /ws/packets  — flux des paquets captures (page Flux Live)
  /ws/stats    — fin de chaque cycle d'analyse (rafraichissement du tableau de bord)
  /ws/alerts   — nouvelles attaques detectees (banniere d'alerte)

Le jeton JWT est passe en query string (`?token=...`), les WebSockets du
navigateur ne permettant pas d'en-tete Authorization.
"""

import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from app.core.security import decode_access_token
from app.services.broadcast import CHANNEL_ALERTS, CHANNEL_PACKETS, CHANNEL_STATS, broadcaster

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ws", tags=["Temps reel"])


async def _serve(channel: str, websocket: WebSocket, token: str | None) -> None:
    """Authentifie le client puis maintient la connexion ouverte sur un canal."""
    if not token or decode_access_token(token) is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await broadcaster.connect(channel, websocket)
    try:
        await websocket.send_json({"type": "connected", "channel": channel})
        while True:
            # Maintient la connexion ouverte ; sert aussi de ping cote client.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # noqa: BLE001
        logger.debug("WS %s ferme : %s", channel, exc)
    finally:
        await broadcaster.disconnect(channel, websocket)


@router.websocket("/packets")
async def ws_packets(websocket: WebSocket, token: str | None = Query(default=None)) -> None:
    """Canal temps reel des paquets captures."""
    await _serve(CHANNEL_PACKETS, websocket, token)


@router.websocket("/stats")
async def ws_stats(websocket: WebSocket, token: str | None = Query(default=None)) -> None:
    """Canal notifiant la fin de chaque cycle d'analyse."""
    await _serve(CHANNEL_STATS, websocket, token)


@router.websocket("/alerts")
async def ws_alerts(websocket: WebSocket, token: str | None = Query(default=None)) -> None:
    """Canal des nouvelles attaques detectees."""
    await _serve(CHANNEL_ALERTS, websocket, token)
