"""Pipeline d'analyse periodique (cf. Description systeme, 4.2).

Toutes les ANALYSIS_INTERVAL_SECONDS secondes :
  1. les paquets du cycle sont persistes (table packets) et diffuses en WebSocket ;
  2. les flux du cycle sont construits (CICFlowMeter) et persistes (table flows) ;
  3. le modele Random Forest classe chaque flux (table predictions) ;
  4. les flux malveillants sont regroupes en alertes (table attacks) ;
  5. les statistiques agregees sont mises a jour (table statistics) ;
  6. l'interface est notifiee via les canaux WebSocket.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.ml.features import raw_vector_from_flow
from app.models import Attack, BlockedIP, Flow, Packet, Prediction, Statistic
from app.services.alerts import send_attack_alert
from app.services.broadcast import CHANNEL_ALERTS, CHANNEL_PACKETS, CHANNEL_STATS, broadcaster
from app.services.capture import current_backend, get_capture, reset_capture
from app.services.firewall import firewall
from app.services.ml import predictor
from app.services.settings_store import get_runtime_settings

logger = logging.getLogger(__name__)

# Paliers exprimes en flux malveillants recus par la cible durant un cycle
# d'analyse (15 s par defaut), toutes sources confondues.
# Duree pendant laquelle un nouvel assaut identique prolonge l'incident en
# cours plutot que d'en ouvrir un nouveau (evite les emails repetes).
FENETRE_CORRELATION_MINUTES = 5

# Du moins grave au plus grave : sert a detecter une aggravation.
ORDRE_CRITICITE = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

SEVERITY_THRESHOLDS = ((60, "CRITICAL"), (25, "HIGH"), (10, "MEDIUM"))


def _severity_for(flux_vers_la_cible: int, confidence: float) -> str:
    """Criticite deduite du volume subi par la cible et de la confiance du modele."""
    for threshold, level in SEVERITY_THRESHOLDS:
        if flux_vers_la_cible >= threshold:
            return level
    return "MEDIUM" if confidence >= 90 else "LOW"


class AnalysisPipeline:
    """Boucle d'analyse : capture -> extraction -> prediction -> alerte."""

    def __init__(self) -> None:
        """Initialise l'etat du pipeline (aucune tache n'est encore lancee)."""
        self._task: asyncio.Task | None = None
        self._running = False
        self._cycles = 0
        self._last_cycle_at: datetime | None = None
        self._last_error: str | None = None

    # ── Cycle de vie ──────────────────────────────────────────────────────────
    async def start(self) -> None:
        """Demarre la capture puis la boucle d'analyse periodique."""
        if self._running:
            return
        capture = get_capture()
        try:
            await capture.start()
        except Exception as exc:  # noqa: BLE001 — tshark indisponible, etc.
            self._last_error = str(exc)
            logger.error("Capture indisponible : %s", exc)
            return
        self._running = True
        self._task = asyncio.create_task(self._loop(), name="analysis-pipeline")
        logger.info(
            "Pipeline d'analyse demarre (backend=%s, intervalle=%ss)",
            capture.name,
            settings.ANALYSIS_INTERVAL_SECONDS,
        )

    async def stop(self) -> None:
        """Arrete la boucle d'analyse et la capture sous-jacente."""
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
        await get_capture().stop()

    async def switch_backend(self, backend: str) -> dict[str, Any]:
        """Change le moteur de capture sans redemarrer le backend.

        Arrete le moteur courant, oublie l'instance en cache pour qu'un nouveau
        soit construit, puis relance la boucle — sauf en mode `external`, ou
        c'est l'agent distant qui declenche les cycles.
        """
        await self.stop()
        reset_capture()
        if backend != "external":
            await self.start()
        logger.info("Moteur de capture bascule sur : %s", backend)
        return self.status()

    def is_active(self) -> bool:
        """Le systeme traite-t-il reellement des donnees ?

        En mode `external`, aucune boucle interne ne tourne : c'est l'agent de
        capture qui declenche les cycles. L'activite se mesure donc a la
        fraicheur du dernier cycle recu, et non a l'existence d'une tache locale.
        """
        if current_backend() != "external":
            return self._running
        if self._last_cycle_at is None:
            return False
        age = (datetime.now(UTC) - self._last_cycle_at).total_seconds()
        return age < max(get_runtime_settings().analysis_interval * 3, 60)

    def status(self) -> dict[str, Any]:
        """Etat complet du pipeline, expose par l'API et l'interface."""
        capture = get_capture()
        return {
            "pipeline_running": self.is_active(),
            "cycles": self._cycles,
            "last_cycle_at": self._last_cycle_at.isoformat() if self._last_cycle_at else None,
            "interval_seconds": get_runtime_settings().analysis_interval,
            "last_error": self._last_error,
            "capture": capture.status(),
            "model": predictor.info(),
            "firewall": firewall.status(),
            "ws_clients": broadcaster.client_count(),
        }

    # ── Boucle ────────────────────────────────────────────────────────────────
    async def _loop(self) -> None:
        """Boucle principale : pousse les paquets chaque seconde, analyse a chaque cycle."""
        capture = get_capture()
        try:
            while self._running:
                # Les paquets sont pousses plus souvent que les cycles d'analyse
                interval = get_runtime_settings().analysis_interval
                ticks = max(int(interval), 1)
                for _ in range(ticks):
                    if not self._running:
                        return
                    await asyncio.sleep(1)
                    await self._flush_packets()

                try:
                    await asyncio.to_thread(self._run_cycle_sync)
                except Exception as exc:  # noqa: BLE001 — un cycle en echec ne tue pas la boucle
                    self._last_error = str(exc)
                    logger.exception("Echec du cycle d'analyse : %s", exc)
                else:
                    self._last_error = None
                    await self._publish_cycle_results()

                _ = capture  # backend conserve entre les cycles
        except asyncio.CancelledError:
            pass

    # ── Etape 1 : paquets temps reel ──────────────────────────────────────────
    async def _flush_packets(self) -> None:
        """Diffuse et persiste les paquets accumules depuis le dernier passage."""
        capture = get_capture()
        packets = capture.drain_packets()
        if not packets:
            return

        payload = [p.to_dict() for p in packets[-120:]]
        await broadcaster.publish(CHANNEL_PACKETS, {"type": "packets", "data": payload})
        await asyncio.to_thread(self._persist_packets, packets)

    def _persist_packets(self, packets: list) -> None:
        """Enregistre en base les paquets issus de la capture interne."""
        with SessionLocal() as db:
            db.add_all(
                Packet(
                    timestamp=p.timestamp,
                    packet_no=p.packet_no,
                    time=p.time,
                    src_ip=p.src_ip,
                    dst_ip=p.dst_ip,
                    protocol=p.protocol,
                    length=p.length,
                    info=p.info,
                    source=current_backend(),
                )
                for p in packets
            )
            db.commit()
            self._prune_packets(db)

    def _prune_packets(self, db: Session) -> None:
        """Conserve uniquement les N derniers paquets (flux live, pas d'historique)."""
        keep = settings.LIVE_PACKET_RETENTION * 5
        total = db.scalar(select(func.count(Packet.id))) or 0
        if total <= keep:
            return
        cutoff = db.scalar(select(Packet.id).order_by(Packet.id.desc()).offset(keep).limit(1))
        if cutoff:
            db.execute(delete(Packet).where(Packet.id < cutoff))
            db.commit()

    # ── Etapes 2 a 5 : cycle d'analyse (synchrone, hors boucle asyncio) ───────
    def _run_cycle_sync(self) -> None:
        """Execute un cycle complet a partir du backend de capture interne."""
        capture = get_capture()
        raw_flows = capture.collect_flows()
        pps, bps = capture.throughput()
        self.process_cycle(raw_flows, pps, bps)

    def process_cycle(self, raw_flows: list[dict[str, Any]], pps: float, bps: float) -> list[dict[str, Any]]:
        """Classe un lot de flux, cree les alertes et met a jour les statistiques.

        Point d'entree commun a la capture interne et a l'agent de capture
        externe (`POST /api/ingest`). Retourne les alertes creees, deja
        serialisees pour la diffusion WebSocket.
        """
        self._cycles += 1
        self._last_cycle_at = datetime.now(UTC)

        with SessionLocal() as db:
            new_attacks: list[Attack] = []

            if raw_flows and predictor.is_ready:
                # Chaque enregistrement porte sa provenance : les analyses
                # peuvent ensuite isoler le trafic reel du trafic simule.
                origine = current_backend()
                flows = [Flow(**payload, source=origine) for payload in raw_flows]
                db.add_all(flows)
                db.flush()  # attribue les identifiants

                # Valeurs brutes : c'est le scaler du modele qui les met a l'echelle
                vectors = [raw_vector_from_flow(flow) for flow in flows]
                results = predictor.predict_batch(vectors)

                runtime = get_runtime_settings()
                predictions = [
                    Prediction(
                        flow_id=flow.id,
                        prediction=result.label,
                        confidence=result.confidence,
                        is_attack=result.is_attack
                        and result.confidence >= runtime.confidence_threshold * 100,
                        prediction_timestamp=self._last_cycle_at,
                    )
                    for flow, result in zip(flows, results, strict=True)
                ]
                db.add_all(predictions)
                db.flush()

                new_attacks = self._group_attacks(db, flows, predictions, runtime.flow_threshold)

            self._write_statistics(db, pps, bps)
            db.commit()

            alerts = [
                {
                    "id": attack.id,
                    "timestamp": attack.timestamp.isoformat(),
                    "attack_type": attack.attack_type,
                    "source_ip": attack.source_ip,
                    "destination_ip": attack.destination_ip,
                    "flows_count": attack.flows_count,
                    "severity": attack.severity,
                    "avg_confidence": round(attack.avg_confidence, 2),
                }
                for attack in new_attacks
            ]
            self._pending_alerts = alerts
            self._pending_alert_models = new_attacks
            return alerts

    # ── Ingestion depuis un agent de capture externe ──────────────────────────
    async def ingest(
        self,
        packets: list[dict[str, Any]],
        raw_flows: list[dict[str, Any]],
        pps: float,
        bps: float,
    ) -> dict[str, Any]:
        """Traite un lot envoye par l'agent de capture qui tourne sur l'hote.

        Sur macOS, un conteneur ne voit jamais les interfaces reseau de la
        machine : l'agent capture localement puis pousse ici ses paquets et ses
        flux. Le traitement est ensuite identique a celui de la capture interne.
        """
        if packets:
            await broadcaster.publish(CHANNEL_PACKETS, {"type": "packets", "data": packets[-120:]})
            await asyncio.to_thread(self._persist_packet_dicts, packets)

        alerts = await asyncio.to_thread(self.process_cycle, raw_flows, pps, bps)
        await self._publish_cycle_results()

        return {
            "packets": len(packets),
            "flows": len(raw_flows),
            "attacks": len(alerts),
            "cycle": self._cycles,
        }

    def _persist_packet_dicts(self, packets: list[dict[str, Any]]) -> None:
        """Enregistre des paquets recus au format JSON (agent externe)."""
        with SessionLocal() as db:
            db.add_all(
                Packet(
                    timestamp=datetime.fromisoformat(p["timestamp"])
                    if isinstance(p.get("timestamp"), str)
                    else datetime.now(UTC),
                    packet_no=int(p.get("packet_no", 0)),
                    time=float(p.get("time", 0.0)),
                    src_ip=str(p.get("src_ip", "")),
                    dst_ip=str(p.get("dst_ip", "")),
                    protocol=str(p.get("protocol", ""))[:10],
                    length=int(p.get("length", 0)),
                    info=str(p.get("info", ""))[:100],
                    source=current_backend(),
                )
                for p in packets
            )
            db.commit()
            self._prune_packets(db)

    def _group_attacks(
        self,
        db: Session,
        flows: list[Flow],
        predictions: list[Prediction],
        flow_threshold: int,
    ) -> list[Attack]:
        """Regroupe les flux malveillants par (type, source, cible) en une alerte.

        La criticite se mesure au volume subi par la **cible**, pas a la
        contribution d'une seule source : une attaque DDoS est distribuee, et
        chaque source n'envoie qu'une fraction du total. Juger source par source
        classerait une attaque massive comme une serie d'incidents benins.
        """
        groups: dict[tuple[str, str, str], list[tuple[Flow, Prediction]]] = defaultdict(list)
        # Volume total dirige contre chaque cible, toutes sources confondues.
        charge_par_cible: dict[str, int] = defaultdict(int)

        for flow, prediction in zip(flows, predictions, strict=True):
            if prediction.is_attack:
                groups[(prediction.prediction, flow.src_ip, flow.dst_ip)].append((flow, prediction))
                charge_par_cible[flow.dst_ip] += 1

        created: list[Attack] = []
        recent = datetime.now(UTC) - timedelta(minutes=FENETRE_CORRELATION_MINUTES)
        for (attack_type, source_ip, destination_ip), members in groups.items():
            if len(members) < flow_threshold:
                continue

            flows_count = len(members)
            avg_confidence = sum(p.confidence for _, p in members) / flows_count
            severite = _severity_for(charge_par_cible[destination_ip], avg_confidence)

            # Une rafale dure souvent plus longtemps qu'un cycle d'analyse. Sans
            # cette correlation, le meme assaut produirait une alerte -- et un
            # email -- a chaque cycle. On prolonge l'incident en cours au lieu
            # d'en ouvrir un nouveau ; seule une aggravation renotifie.
            en_cours = db.scalar(
                select(Attack)
                .where(
                    Attack.attack_type == attack_type,
                    Attack.source_ip == source_ip,
                    Attack.destination_ip == destination_ip,
                    Attack.status == "ACTIVE",
                    Attack.timestamp >= recent,
                )
                .order_by(Attack.timestamp.desc())
            )
            if en_cours is not None:
                total = en_cours.flows_count + flows_count
                en_cours.avg_confidence = round(
                    (en_cours.avg_confidence * en_cours.flows_count + avg_confidence * flows_count) / total,
                    2,
                )
                en_cours.flows_count = total
                en_cours.total_bytes += int(sum(f.totlen_fwd_pkts + f.totlen_bwd_pkts for f, _ in members))
                en_cours.total_packets += int(sum(f.tot_fwd_pkts + f.tot_bwd_pkts for f, _ in members))
                en_cours.duration = round(
                    en_cours.duration + sum(f.flow_duration for f, _ in members) / 1_000_000, 3
                )
                en_cours.timestamp = self._last_cycle_at or datetime.now(UTC)

                aggravee = ORDRE_CRITICITE.index(severite) > ORDRE_CRITICITE.index(en_cours.severity)
                if aggravee:
                    en_cours.severity = severite
                    created.append(en_cours)
                if get_runtime_settings().auto_block and severite in ("HIGH", "CRITICAL"):
                    self._auto_block(db, source_ip, attack_type)
                continue

            attack = Attack(
                timestamp=self._last_cycle_at or datetime.now(UTC),
                attack_type=attack_type,
                source_ip=source_ip,
                destination_ip=destination_ip,
                flows_count=flows_count,
                total_bytes=int(sum(f.totlen_fwd_pkts + f.totlen_bwd_pkts for f, _ in members)),
                total_packets=int(sum(f.tot_fwd_pkts + f.tot_bwd_pkts for f, _ in members)),
                duration=round(sum(f.flow_duration for f, _ in members) / 1_000_000, 3),
                avg_confidence=round(avg_confidence, 2),
                severity=severite,
                status="ACTIVE",
                source=current_backend(),
            )
            db.add(attack)
            created.append(attack)

            if get_runtime_settings().auto_block and attack.severity in ("HIGH", "CRITICAL"):
                self._auto_block(db, source_ip, attack_type)

        db.flush()
        return created

    def _auto_block(self, db: Session, ip_address: str, attack_type: str) -> None:
        """Inscrit l'IP source dans la liste de blocage et pose la regle de pare-feu.

        Appele uniquement si `auto_block` est active et que l'attaque est de
        criticite elevee ou critique.
        """
        exists = db.scalar(select(BlockedIP).where(BlockedIP.ip_address == ip_address))
        if exists:
            return

        db.add(
            BlockedIP(
                ip_address=ip_address,
                reason=f"Blocage automatique — attaque {attack_type}",
                blocked_by="system",
                is_automatic=True,
            )
        )
        # Une meme source alimente souvent plusieurs groupes d'attaque dans le
        # meme cycle (NTP et DNS par exemple). Sans ce flush, l'insertion reste
        # en attente dans la session : le SELECT du groupe suivant ne la voit
        # pas, les deux INSERT partent ensemble et violent l'unicite de l'IP.
        db.flush()
        resultat = firewall.block(ip_address)
        logger.warning(
            "IP bloquee automatiquement : %s (%s) — pare-feu : %s",
            ip_address,
            attack_type,
            "regle posee" if resultat.applied else resultat.detail,
        )

    def _write_statistics(self, db: Session, pps: float, bps: float) -> None:
        """Ecrit le releve de statistiques agregees du cycle courant."""
        total_flows = db.scalar(select(func.count(Flow.id))) or 0
        total_attacks = (
            db.scalar(select(func.count(Prediction.id)).where(Prediction.is_attack.is_(True))) or 0
        )
        benign_flows = (
            db.scalar(select(func.count(Prediction.id)).where(Prediction.is_attack.is_(False))) or 0
        )
        active_attacks = db.scalar(select(func.count(Attack.id)).where(Attack.status == "ACTIVE")) or 0
        db.add(
            Statistic(
                timestamp=self._last_cycle_at or datetime.now(UTC),
                total_flows=total_flows,
                total_attacks=total_attacks,
                benign_flows=benign_flows,
                packets_per_second=pps,
                bytes_per_second=bps,
                active_attacks=active_attacks,
                source=current_backend(),
            )
        )

    # ── Etape 6 : notification de l'interface ─────────────────────────────────
    async def _publish_cycle_results(self) -> None:
        """Notifie l'interface et envoie les alertes email du cycle."""
        alerts = getattr(self, "_pending_alerts", [])
        alert_models = getattr(self, "_pending_alert_models", [])
        self._pending_alerts, self._pending_alert_models = [], []

        await broadcaster.publish(
            CHANNEL_STATS,
            {
                "type": "cycle",
                "data": {
                    "cycle": self._cycles,
                    "timestamp": (self._last_cycle_at or datetime.now(UTC)).isoformat(),
                    "new_attacks": len(alerts),
                },
            },
        )

        for payload, model in zip(alerts, alert_models, strict=False):
            await broadcaster.publish(CHANNEL_ALERTS, {"type": "attack", "data": payload})
            await send_attack_alert(model)

    # ── Utilitaire : marquer les anciennes attaques comme mitigees ─────────────
    @staticmethod
    def auto_mitigate(db: Session, older_than_minutes: int = 10) -> int:
        """Passe en MITIGATED les alertes actives plus anciennes qu'un delai donne."""
        cutoff = datetime.now(UTC) - timedelta(minutes=older_than_minutes)
        rows = db.execute(
            select(Attack).where(Attack.status == "ACTIVE", Attack.timestamp < cutoff)
        ).scalars()
        count = 0
        for attack in rows:
            attack.status = "MITIGATED"
            count += 1
        if count:
            db.commit()
        return count


pipeline = AnalysisPipeline()
