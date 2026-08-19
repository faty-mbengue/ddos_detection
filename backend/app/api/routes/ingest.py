"""Reception du trafic capture par un agent externe.

Pourquoi cette route existe
---------------------------
Sous macOS (et Windows), Docker Desktop execute les conteneurs dans une machine
virtuelle Linux. Un conteneur ne voit donc **jamais** les interfaces reseau de
la machine hote, meme avec `network_mode: host` : il n'observerait que le reseau
virtuel de la VM. La seule facon de capturer le trafic reel de la machine est de
lancer la capture *sur l'hote*, puis de la pousser vers l'API.

C'est le role de `tools/capture_agent.py` : il execute tshark localement, agrege
les paquets en flux CICFlowMeter, et poste le resultat ici toutes les N secondes.
Le backend applique ensuite exactement le meme traitement que pour sa capture
interne (classification, alertes, statistiques, diffusion WebSocket).
"""

from datetime import datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.api.deps import AnalystUser
from app.models import Flow
from app.services.analysis import pipeline

router = APIRouter(prefix="/ingest", tags=["Ingestion (agent de capture)"])

# Colonnes acceptees pour un flux : celles de la table `flows`, sans la cle primaire.
FLOW_COLUMNS = {column.name for column in Flow.__table__.columns} - {"id"}


class PacketIn(BaseModel):
    """Un paquet observe par l'agent."""

    packet_no: int = 0
    time: float = 0.0
    src_ip: str
    dst_ip: str
    protocol: str = ""
    length: int = 0
    info: str = ""
    timestamp: datetime | None = None


class IngestPayload(BaseModel):
    """Lot envoye par l'agent a la fin de chaque cycle de capture."""

    # Marge large : une rafale sur un lien charge depasse aisement quelques
    # milliers de paquets par cycle. L'agent plafonne de son cote.
    packets: list[PacketIn] = Field(default_factory=list, max_length=20000)
    flows: list[dict[str, Any]] = Field(default_factory=list, max_length=10000)
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    agent: str = Field(default="capture-agent", max_length=60)


def _sanitize_flow(payload: dict[str, Any]) -> dict[str, Any]:
    """Ne retient que les colonnes connues de `flows`.

    L'agent est un client comme un autre : on ne laisse jamais un champ arbitraire
    atteindre le constructeur du modele SQLAlchemy.
    """
    return {key: value for key, value in payload.items() if key in FLOW_COLUMNS}


@router.post("", summary="Recevoir un lot de paquets et de flux captures sur l'hote")
async def ingest(user: AnalystUser, payload: IngestPayload) -> dict[str, Any]:
    """Traite un lot de capture externe et retourne le resume du cycle."""
    packets = [
        {
            **packet.model_dump(exclude={"timestamp"}),
            "timestamp": (packet.timestamp or datetime.now()).isoformat(),
        }
        for packet in payload.packets
    ]
    flows = [_sanitize_flow(flow) for flow in payload.flows]

    resultat = await pipeline.ingest(
        packets=packets,
        raw_flows=flows,
        pps=payload.packets_per_second,
        bps=payload.bytes_per_second,
    )
    resultat["agent"] = payload.agent
    resultat["received_from"] = user.username
    return resultat
