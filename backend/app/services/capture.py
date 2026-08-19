"""Capture du trafic reseau.

Deux implementations interchangeables (variable CAPTURE_BACKEND) :

  - `tshark`    : capture reelle des paquets via tshark, puis agregation en flux
                  selon la nomenclature CICFlowMeter (CICFlowMeter simplifie).
                  Necessite tshark installe, la capability NET_ADMIN et un acces
                  a l'interface hote (`network_mode: host`).
  - `simulator` : generateur de trafic synthetique reproduisant les signatures
                  du dataset CICDDoS2019. Backend par defaut : il permet de faire
                  tourner la plateforme entiere dans un conteneur sans privileges.

Les deux backends exposent la meme interface : un flux de paquets temps reel
(`drain_packets`) et la construction de flux a analyser (`collect_flows`).
"""

from __future__ import annotations

import asyncio
import logging
import random
import shutil
import subprocess
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.config import settings
from app.ml.features import (
    ATTACK_CLASSES,
    BENIGN_CLASS,
    FEATURE_MAX,
    FEATURE_NAMES,
    FLOW_FIELD_BY_FEATURE,
)
from app.ml.train_demo_model import CLASS_PROFILES

logger = logging.getLogger(__name__)

PROTOCOL_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}

# Ports usuels des services reflecteurs, par classe d'attaque
ATTACK_PORTS: dict[str, int] = {
    "DNS": 53,
    "LDAP": 389,
    "MSSQL": 1434,
    "NTP": 123,
    "NetBIOS": 137,
    "SNMP": 161,
    "SSDP": 1900,
    "Syn": 80,
    "TFTP": 69,
    "UDP": 5353,
    "UDPLag": 5353,
}


@dataclass(slots=True)
class PacketRecord:
    """Un paquet observe en temps reel (table `packets`)."""

    packet_no: int
    time: float
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    info: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        """Serialise le paquet pour l'envoi WebSocket."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


class BaseCapture:
    """Interface commune aux backends de capture."""

    name = "base"

    def __init__(self) -> None:
        """Initialise le tampon de paquets et les compteurs de debit."""
        self._buffer: deque[PacketRecord] = deque(maxlen=settings.LIVE_PACKET_RETENTION)
        self._packet_no = 0
        self._started_at = time.monotonic()
        self._running = False
        self._bytes_window = 0
        self._packets_window = 0
        self._window_start = time.monotonic()

    # ── Cycle de vie ──────────────────────────────────────────────────────────
    async def start(self) -> None:
        """Demarre la capture. Surchargee par chaque backend."""
        self._running = True

    async def stop(self) -> None:
        """Arrete la capture."""
        self._running = False

    @property
    def is_running(self) -> bool:
        """Indique si la capture est active."""
        return self._running

    def status(self) -> dict[str, Any]:
        """Etat de la capture, expose par l'API."""
        return {
            "backend": self.name,
            "running": self._running,
            "interface": settings.CAPTURE_INTERFACE,
            "packets_captured": self._packet_no,
            "uptime_seconds": round(time.monotonic() - self._started_at, 1),
        }

    # ── Paquets temps reel ────────────────────────────────────────────────────
    def _record(self, src: str, dst: str, protocol: str, length: int, info: str) -> PacketRecord:
        """Enregistre un paquet dans le tampon et met a jour les compteurs de debit."""
        self._packet_no += 1
        self._bytes_window += length
        self._packets_window += 1
        packet = PacketRecord(
            packet_no=self._packet_no,
            time=round(time.monotonic() - self._started_at, 6),
            src_ip=src,
            dst_ip=dst,
            protocol=protocol,
            length=length,
            info=info,
        )
        self._buffer.append(packet)
        return packet

    def drain_packets(self) -> list[PacketRecord]:
        """Retire et retourne les paquets accumules depuis le dernier appel."""
        packets = list(self._buffer)
        self._buffer.clear()
        return packets

    def throughput(self) -> tuple[float, float]:
        """(paquets/s, octets/s) depuis le dernier appel."""
        now = time.monotonic()
        elapsed = max(now - self._window_start, 0.001)
        pps = self._packets_window / elapsed
        bps = self._bytes_window / elapsed
        self._packets_window = 0
        self._bytes_window = 0
        self._window_start = now
        return round(pps, 2), round(bps, 2)

    # ── Flux a analyser ───────────────────────────────────────────────────────
    def collect_flows(self) -> list[dict[str, Any]]:
        """Retourne les flux du cycle courant et vide le tampon (appel synchrone)."""
        raise NotImplementedError


# ══════════════════════════════════════════════════════════════════════════════
# Backend simulateur
# ══════════════════════════════════════════════════════════════════════════════

LOCAL_TARGETS = ["192.168.1.10", "192.168.1.20", "10.0.0.5"]
LEGIT_SOURCES = ["192.168.1.101", "192.168.1.102", "192.168.1.115", "10.0.0.42"]


def random_public_ip(rng: random.Random) -> str:
    """Tire une adresse IPv4 publique au hasard, pour le trafic simule."""
    return f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


class SimulatorCapture(BaseCapture):
    """Genere du trafic synthetique : trafic legitime + rafales d'attaque periodiques."""

    name = "simulator"

    def __init__(self) -> None:
        """Initialise le generateur aleatoire et l'etat de la rafale d'attaque."""
        super().__init__()
        self._rng = random.Random(1337)
        self._task: asyncio.Task | None = None
        self._attack_class: str | None = None
        self._attack_until = 0.0
        self._attack_source = ""
        self._attack_target = ""

    async def start(self) -> None:
        """Lance la tache d'emission de trafic synthetique."""
        await super().start()
        self._task = asyncio.create_task(self._loop(), name="simulator-capture")
        logger.info("Capture simulee demarree")

    async def stop(self) -> None:
        """Arrete la tache d'emission."""
        await super().stop()
        if self._task:
            self._task.cancel()
            self._task = None

    # ── Etat de l'attaque en cours ────────────────────────────────────────────
    def _refresh_attack_state(self) -> None:
        """Demarre ou termine une rafale d'attaque simulee."""
        now = time.monotonic()
        if self._attack_class and now < self._attack_until:
            return
        if self._attack_class:  # fin de la rafale
            self._attack_class = None
            return
        # ~1 chance sur 4 de declencher une rafale de 20 a 45 s
        if self._rng.random() < 0.25:
            self._attack_class = self._rng.choice(ATTACK_CLASSES)
            self._attack_until = now + self._rng.uniform(20, 45)
            self._attack_source = random_public_ip(self._rng)
            self._attack_target = self._rng.choice(LOCAL_TARGETS)
            logger.info("Rafale simulee : %s depuis %s", self._attack_class, self._attack_source)

    async def _loop(self) -> None:
        """Emet des paquets en continu (~35 a 220 paquets/s selon l'etat)."""
        try:
            while self._running:
                self._refresh_attack_state()
                under_attack = self._attack_class is not None
                burst = self._rng.randint(20, 45) if under_attack else self._rng.randint(4, 12)

                for _ in range(burst):
                    if under_attack and self._rng.random() < 0.8:
                        self._emit_attack_packet(self._attack_class or "UDP")
                    else:
                        self._emit_legit_packet()

                await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            pass

    def _emit_legit_packet(self) -> None:
        """Emet un paquet de trafic legitime."""
        rng = self._rng
        protocol = rng.choices(["TCP", "UDP", "ICMP"], weights=[72, 25, 3])[0]
        src = rng.choice(LEGIT_SOURCES)
        dst = rng.choice(LOCAL_TARGETS + [random_public_ip(rng)])
        if protocol == "TCP":
            port = rng.choice([80, 443, 22, 3306, 8080])
            info = f"{rng.randint(30000, 65000)} > {port} [ACK] Seq={rng.randint(1, 99999)} Win=64240"
            length = rng.randint(60, 1460)
        elif protocol == "UDP":
            info = f"{rng.randint(30000, 65000)} > 53 Len={rng.randint(20, 120)}"
            length = rng.randint(60, 512)
        else:
            info = "Echo (ping) request"
            length = rng.randint(56, 98)
        self._record(src, dst, protocol, length, info)

    def _emit_attack_packet(self, attack_class: str) -> None:
        """Emet un paquet correspondant a la classe d'attaque en cours."""
        rng = self._rng
        port = ATTACK_PORTS.get(attack_class, 5353)
        src = self._attack_source if rng.random() < 0.6 else random_public_ip(rng)
        if attack_class == "Syn":
            info = f"{rng.randint(1024, 65535)} > {port} [SYN] Seq=0 Win=1024 Len=0"
            self._record(src, self._attack_target, "TCP", rng.randint(54, 74), info)
        else:
            length = {"SNMP": rng.randint(800, 1450), "SSDP": rng.randint(300, 1000)}.get(
                attack_class, rng.randint(60, 600)
            )
            info = f"{rng.randint(1024, 65535)} > {port} Len={length - 42} [{attack_class}]"
            self._record(src, self._attack_target, "UDP", length, info)

    # ── Construction des flux du cycle ────────────────────────────────────────
    def collect_flows(self) -> list[dict[str, Any]]:
        """Construit les flux du cycle : trafic legitime et, le cas echeant, attaque."""
        rng = self._rng
        flows: list[dict[str, Any]] = []
        under_attack = self._attack_class is not None

        n_benign = rng.randint(4, 10)
        for _ in range(n_benign):
            flows.append(
                synthesize_flow(
                    BENIGN_CLASS,
                    rng,
                    src_ip=rng.choice(LEGIT_SOURCES),
                    dst_ip=rng.choice(LOCAL_TARGETS),
                )
            )

        if under_attack:
            # Une attaque DDoS reelle sature sa cible : plusieurs dizaines a
            # plusieurs centaines de flux par cycle d'analyse. Un volume trop
            # faible ne franchirait jamais les paliers de criticite, et le
            # simulateur ne representerait alors rien de realiste.
            attack_class = self._attack_class or "UDP"
            for _ in range(rng.randint(60, 180)):
                flows.append(
                    synthesize_flow(
                        attack_class,
                        rng,
                        src_ip=self._attack_source
                        if rng.random() < 0.55
                        else random_public_ip(rng),
                        dst_ip=self._attack_target,
                    )
                )

        rng.shuffle(flows)
        return flows


def _feature_scale() -> dict[str, float]:
    """Echelle brute a utiliser pour chaque caracteristique du simulateur.

    Si un scaler accompagne le modele charge, on reprend ses bornes reelles
    (`data_max_`) : le trafic simule tombe alors dans les memes plages que le jeu
    d'entrainement, et les predictions restent pertinentes. Sinon on retombe sur
    les bornes approximatives de `features.py`.
    """
    from app.services.ml import predictor

    bounds = predictor.raw_bounds()
    if bounds is None:
        return dict(FEATURE_MAX)

    _, data_max = bounds
    if len(data_max) != len(FEATURE_NAMES):
        return dict(FEATURE_MAX)
    return {name: data_max[i] or FEATURE_MAX[name] for i, name in enumerate(FEATURE_NAMES)}


def synthesize_flow(
    class_name: str, rng: random.Random, src_ip: str, dst_ip: str
) -> dict[str, Any]:
    """Produit un flux CICFlowMeter plausible pour une classe donnee.

    Le profil normalise de la classe est echantillonne puis converti vers les
    echelles brutes CICFlowMeter, de sorte que le flux stocke en base et le
    vecteur soumis au modele decrivent bien le meme trafic.
    """
    profile = CLASS_PROFILES[class_name]
    echelle = _feature_scale()
    protocol = 6 if class_name in ("BENIGN", "Syn") else 17
    port = ATTACK_PORTS.get(class_name, rng.choice([80, 443, 53]))

    flow: dict[str, Any] = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": rng.randint(1024, 65535),
        "dst_port": port,
        "protocol": protocol,
        "timestamp": datetime.now(UTC),
    }

    # Conversion profil normalise -> valeurs brutes
    for feature, (mean, std) in profile.items():
        normalized = max(0.0, min(1.0, rng.gauss(mean, std)))
        column = FLOW_FIELD_BY_FEATURE[feature]
        flow[column] = normalized * echelle[feature]
    flow["protocol"] = protocol  # la colonne protocol reste l'entier reel

    # Champs derives non couverts par les 31 caracteristiques du modele
    tot_fwd = max(int(flow.get("tot_fwd_pkts", 0)), 1)
    tot_bwd = max(int(flow.get("tot_bwd_pkts", 0)), 0)
    totlen_fwd = int(flow.get("totlen_fwd_pkts", 0))
    duration = float(flow.get("flow_duration", 1.0)) or 1.0

    flow["tot_fwd_pkts"] = tot_fwd
    flow["tot_bwd_pkts"] = tot_bwd
    flow["totlen_fwd_pkts"] = totlen_fwd
    flow["totlen_bwd_pkts"] = int(float(flow.get("bwd_pkt_len_mean", 0)) * tot_bwd)
    flow["flow_pkts_s"] = round((tot_fwd + tot_bwd) / (duration / 1_000_000), 2)
    flow["fwd_pkts_s"] = round(tot_fwd / (duration / 1_000_000), 2)
    flow["pkt_len_max"] = int(
        max(float(flow.get("fwd_pkt_len_max", 0)), float(flow.get("bwd_pkt_len_max", 0)))
    )
    flow["pkt_len_mean"] = round(totlen_fwd / tot_fwd, 2)
    flow["pkt_size_avg"] = flow["pkt_len_mean"]
    flow["fwd_pkt_len_mean"] = flow["pkt_len_mean"]
    flow["fwd_seg_size_avg"] = flow["pkt_len_mean"]
    flow["subflow_fwd_pkts"] = tot_fwd
    flow["subflow_bwd_pkts"] = tot_bwd
    flow["subflow_fwd_byts"] = totlen_fwd
    flow["psh_flag_cnt"] = int(flow.get("fwd_psh_flags", 0))

    # Les colonnes entieres de la table doivent recevoir des entiers
    for column in (
        "fwd_pkt_len_max",
        "bwd_pkt_len_max",
        "bwd_pkt_len_min",
        "fwd_header_len",
        "init_fwd_win_byts",
        "init_bwd_win_byts",
        "fwd_act_data_pkts",
        "fwd_seg_size_min",
        "syn_flag_cnt",
        "rst_flag_cnt",
        "ack_flag_cnt",
        "urg_flag_cnt",
        "cwr_flag_count",
        "fwd_psh_flags",
    ):
        if column in flow:
            flow[column] = int(round(float(flow[column])))

    return flow


# ══════════════════════════════════════════════════════════════════════════════
# Backend tshark (capture reelle)
# ══════════════════════════════════════════════════════════════════════════════

TSHARK_FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags",
    "tcp.hdr_len",
    "tcp.window_size_value",
    "_ws.col.Protocol",
    "_ws.col.Info",
]


@dataclass(slots=True)
class _RawPacket:
    ts: float
    length: int
    src_ip: str
    dst_ip: str
    proto: int
    src_port: int
    dst_port: int
    tcp_flags: int
    tcp_hdr_len: int
    win: int


class TsharkCapture(BaseCapture):
    """Capture reelle via tshark + agregation en flux (CICFlowMeter simplifie)."""

    name = "tshark"

    def __init__(self) -> None:
        """Prepare la capture tshark ; le processus n'est lance qu'au `start()`."""
        super().__init__()
        self._process: subprocess.Popen[str] | None = None
        self._task: asyncio.Task | None = None
        self._raw: list[_RawPacket] = []

    async def start(self) -> None:
        """Verifie la presence de tshark et demarre le processus de capture."""
        if shutil.which("tshark") is None:
            raise RuntimeError(
                "tshark introuvable : installez wireshark-common, "
                "ou basculez sur CAPTURE_BACKEND=simulator"
            )

        command = [
            "tshark",
            "-i", settings.CAPTURE_INTERFACE,
            "-l",                      # sortie non tamponnee
            "-n",                      # pas de resolution DNS
            "-T", "fields",
            "-E", "separator=\t",
        ]
        for field_name in TSHARK_FIELDS:
            command += ["-e", field_name]

        logger.info("Demarrage de tshark sur %s", settings.CAPTURE_INTERFACE)
        self._process = subprocess.Popen(  # noqa: S603
            command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1
        )
        await super().start()
        self._task = asyncio.create_task(self._reader(), name="tshark-reader")

    async def stop(self) -> None:
        """Arrete la lecture et termine le processus tshark."""
        await super().stop()
        if self._task:
            self._task.cancel()
            self._task = None
        if self._process:
            self._process.terminate()
            self._process = None

    async def _reader(self) -> None:
        """Lit stdout de tshark dans un thread pour ne pas bloquer la boucle asyncio."""
        loop = asyncio.get_running_loop()
        try:
            while self._running and self._process and self._process.stdout:
                line = await loop.run_in_executor(None, self._process.stdout.readline)
                if not line:
                    await asyncio.sleep(0.05)
                    continue
                self._ingest(line.rstrip("\n"))
        except asyncio.CancelledError:
            pass

    def _ingest(self, line: str) -> None:
        """Convertit une ligne de sortie tshark en paquet exploitable."""
        parts = line.split("\t")
        if len(parts) < len(TSHARK_FIELDS):
            parts += [""] * (len(TSHARK_FIELDS) - len(parts))

        def as_int(value: str, default: int = 0) -> int:
            """Convertit un champ tshark en entier, en tolerant l'hexadecimal et le vide."""
            try:
                return int(value.split(",")[0], 16) if value.startswith("0x") else int(float(value))
            except (ValueError, TypeError):
                return default

        src_ip, dst_ip = parts[2], parts[3]
        if not src_ip or not dst_ip:
            return

        proto = as_int(parts[4])
        length = as_int(parts[1])
        raw = _RawPacket(
            ts=float(parts[0] or 0.0),
            length=length,
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto=proto,
            src_port=as_int(parts[5]) or as_int(parts[7]),
            dst_port=as_int(parts[6]) or as_int(parts[8]),
            tcp_flags=as_int(parts[9]),
            tcp_hdr_len=as_int(parts[10]),
            win=as_int(parts[11]),
        )
        self._raw.append(raw)
        self._record(
            src_ip,
            dst_ip,
            parts[12] or PROTOCOL_NAMES.get(proto, str(proto)),
            length,
            (parts[13] or "")[:100],
        )

    def collect_flows(self) -> list[dict[str, Any]]:
        """Agrege les paquets bruts du cycle en flux bidirectionnels."""
        raw, self._raw = self._raw, []
        return _aggregate_flows(raw)


def _aggregate_flows(packets: list[_RawPacket]) -> list[dict[str, Any]]:
    """Agrege des paquets bruts en flux bidirectionnels (CICFlowMeter simplifie)."""
    if not packets:
        return []

    groups: dict[tuple, list[tuple[_RawPacket, bool]]] = {}
    for packet in packets:
        forward_key = (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.proto)
        backward_key = (packet.dst_ip, packet.src_ip, packet.dst_port, packet.src_port, packet.proto)
        if forward_key in groups:
            groups[forward_key].append((packet, True))
        elif backward_key in groups:
            groups[backward_key].append((packet, False))
        else:
            groups[forward_key] = [(packet, True)]

    def stats(values: list[float]) -> tuple[float, float, float, float]:
        """(max, min, mean, std) — 0 si la liste est vide."""
        if not values:
            return 0.0, 0.0, 0.0, 0.0
        n = len(values)
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        return max(values), min(values), mean, variance**0.5

    def iats(timestamps: list[float]) -> list[float]:
        """Calcule les intervalles entre arrivees successives, en microsecondes."""
        ts = sorted(timestamps)
        return [(b - a) * 1_000_000 for a, b in zip(ts, ts[1:], strict=False)]

    flows: list[dict[str, Any]] = []
    for (src_ip, dst_ip, src_port, dst_port, proto), members in groups.items():
        fwd = [p for p, is_fwd in members if is_fwd]
        bwd = [p for p, is_fwd in members if not is_fwd]
        all_ts = [p.ts for p, _ in members]
        duration = max((max(all_ts) - min(all_ts)) * 1_000_000, 1.0)  # microsecondes

        fwd_lengths = [float(p.length) for p in fwd]
        bwd_lengths = [float(p.length) for p in bwd]
        all_lengths = fwd_lengths + bwd_lengths

        fwd_max, fwd_min, fwd_mean, fwd_std = stats(fwd_lengths)
        bwd_max, bwd_min, bwd_mean, bwd_std = stats(bwd_lengths)
        all_max, all_min, all_mean, all_std = stats(all_lengths)

        flow_iat = iats(all_ts)
        _, flow_iat_min, flow_iat_mean, flow_iat_std = stats(flow_iat)
        flow_iat_max = max(flow_iat) if flow_iat else 0.0
        bwd_iat = iats([p.ts for p in bwd])
        bwd_iat_max, bwd_iat_min, bwd_iat_mean, bwd_iat_std = stats(bwd_iat)

        total_bytes = sum(all_lengths)
        seconds = duration / 1_000_000

        # Drapeaux TCP (bit a bit sur tcp.flags)
        def flag_count(mask: int, group: list = members) -> int:
            """Compte les paquets du flux portant un drapeau TCP donne."""
            return sum(1 for p, _ in group if p.tcp_flags & mask)

        flows.append(
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "timestamp": datetime.now(UTC),
                "flow_duration": duration,
                "flow_byts_s": round(total_bytes / seconds, 2),
                "flow_pkts_s": round(len(members) / seconds, 2),
                "fwd_pkts_s": round(len(fwd) / seconds, 2),
                "bwd_pkts_s": round(len(bwd) / seconds, 2),
                "tot_fwd_pkts": len(fwd),
                "tot_bwd_pkts": len(bwd),
                "totlen_fwd_pkts": int(sum(fwd_lengths)),
                "totlen_bwd_pkts": int(sum(bwd_lengths)),
                "fwd_pkt_len_max": int(fwd_max),
                "fwd_pkt_len_min": int(fwd_min),
                "fwd_pkt_len_mean": round(fwd_mean, 2),
                "fwd_pkt_len_std": round(fwd_std, 2),
                "bwd_pkt_len_max": int(bwd_max),
                "bwd_pkt_len_min": int(bwd_min),
                "bwd_pkt_len_mean": round(bwd_mean, 2),
                "bwd_pkt_len_std": round(bwd_std, 2),
                "pkt_len_max": int(all_max),
                "pkt_len_min": int(all_min),
                "pkt_len_mean": round(all_mean, 2),
                "pkt_len_std": round(all_std, 2),
                "pkt_len_var": round(all_std**2, 2),
                "pkt_size_avg": round(all_mean, 2),
                "fwd_header_len": sum(p.tcp_hdr_len for p in fwd),
                "bwd_header_len": sum(p.tcp_hdr_len for p in bwd),
                "fwd_seg_size_min": int(min((p.tcp_hdr_len for p in fwd), default=0)),
                "fwd_seg_size_avg": round(fwd_mean, 2),
                "bwd_seg_size_avg": round(bwd_mean, 2),
                "fwd_act_data_pkts": sum(1 for p in fwd if p.length > p.tcp_hdr_len),
                "flow_iat_mean": round(flow_iat_mean, 2),
                "flow_iat_max": round(flow_iat_max, 2),
                "flow_iat_min": round(flow_iat_min, 2),
                "flow_iat_std": round(flow_iat_std, 2),
                "bwd_iat_tot": round(sum(bwd_iat), 2),
                "bwd_iat_max": round(bwd_iat_max, 2),
                "bwd_iat_min": round(bwd_iat_min, 2),
                "bwd_iat_mean": round(bwd_iat_mean, 2),
                "bwd_iat_std": round(bwd_iat_std, 2),
                "fwd_psh_flags": sum(1 for p in fwd if p.tcp_flags & 0x08),
                "bwd_psh_flags": sum(1 for p in bwd if p.tcp_flags & 0x08),
                "fwd_urg_flags": sum(1 for p in fwd if p.tcp_flags & 0x20),
                "bwd_urg_flags": sum(1 for p in bwd if p.tcp_flags & 0x20),
                "fin_flag_cnt": flag_count(0x01),
                "syn_flag_cnt": flag_count(0x02),
                "rst_flag_cnt": flag_count(0x04),
                "psh_flag_cnt": flag_count(0x08),
                "ack_flag_cnt": flag_count(0x10),
                "urg_flag_cnt": flag_count(0x20),
                "ece_flag_cnt": flag_count(0x40),
                "cwr_flag_count": flag_count(0x80),
                "down_up_ratio": round(len(bwd) / len(fwd), 2) if fwd else 0.0,
                "init_fwd_win_byts": fwd[0].win if fwd else 0,
                "init_bwd_win_byts": bwd[0].win if bwd else 0,
                "active_mean": round(flow_iat_mean, 2),
                "active_std": round(flow_iat_std, 2),
                "active_max": round(flow_iat_max, 2),
                "active_min": round(flow_iat_min, 2),
                "subflow_fwd_pkts": len(fwd),
                "subflow_bwd_pkts": len(bwd),
                "subflow_fwd_byts": int(sum(fwd_lengths)),
                "subflow_bwd_byts": int(sum(bwd_lengths)),
            }
        )
    return flows


# ══════════════════════════════════════════════════════════════════════════════

class ExternalCapture(BaseCapture):
    """Aucune capture locale : les donnees arrivent par `POST /api/ingest`.

    Mode a utiliser avec `tools/capture_agent.py`, qui capture sur l'hote (seule
    facon d'observer le trafic reel d'un Mac, ou Docker tourne dans une VM).
    """

    name = "external"

    def collect_flows(self) -> list[dict[str, Any]]:
        """Ne produit rien : l'agent externe pousse directement ses flux."""
        return []


# Moteurs disponibles, exposes tels quels a l'interface d'administration.
CAPTURE_BACKENDS = ("simulator", "external", "tshark")

_capture: BaseCapture | None = None


def current_backend() -> str:
    """Backend de capture effectif : celui choisi dans l'interface, sinon l'environnement."""
    from app.services.settings_store import get_runtime_settings

    choisi = (get_runtime_settings().capture_backend or "").strip().lower()
    if choisi in CAPTURE_BACKENDS:
        return choisi
    return settings.CAPTURE_BACKEND


def get_capture() -> BaseCapture:
    """Retourne (et instancie au besoin) le backend de capture configure."""
    global _capture
    if _capture is None:
        backend = current_backend()
        if backend == "tshark":
            _capture = TsharkCapture()
        elif backend == "external":
            _capture = ExternalCapture()
        else:
            _capture = SimulatorCapture()
    return _capture


def reset_capture() -> None:
    """Oublie l'instance en cache, pour qu'un autre moteur soit construit ensuite.

    Appelee lors d'un changement de mode depuis l'administration : sans cela,
    l'ancien moteur resterait actif malgre la nouvelle configuration.
    """
    global _capture
    _capture = None
