#!/usr/bin/env python3
"""Agent de capture — capture le trafic reel de VOTRE machine et l'envoie a l'API.

Pourquoi un agent separe ?
--------------------------
Docker Desktop (macOS, Windows) execute les conteneurs dans une machine virtuelle
Linux. Un conteneur ne voit donc jamais les interfaces reseau de votre Mac : meme
avec `network_mode: host`, il n'observerait que le reseau interne de la VM.
Cet agent tourne **directement sur macOS**, capture avec tshark, agrege les
paquets en flux CICFlowMeter, puis pousse le tout vers `POST /api/ingest`.

Prerequis
---------
    brew install wireshark          # fournit tshark
    # Autoriser la capture sans mot de passe (une seule fois) :
    sudo chmod +r /dev/bpf*

Utilisation (depuis le dossier `backend/`, pour disposer de l'environnement uv)
------------------------------------------------------------------------------
    cd backend

    # Lister les interfaces disponibles
    uv run python ../tools/capture_agent.py --list-interfaces

    # Capturer sur le Wi-Fi (en0 sur la plupart des Mac)
    uv run python ../tools/capture_agent.py --interface en0

    # Vers une API distante, avec un cycle de 10 s
    uv run python ../tools/capture_agent.py -i en0 --api http://localhost:8000 --interval 10

Arreter avec Ctrl+C.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# Permet d'importer `app.*` en lancant le script depuis la racine du depot.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.capture import TSHARK_FIELDS, _aggregate_flows, _RawPacket  # noqa: E402

PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}

# Les paquets ne servent qu'a l'affichage temps reel, et la base n'en conserve
# qu'une fenetre glissante. En transmettre des milliers par cycle sature la
# requete sans rien apporter : on n'envoie que les plus recents.
# La detection, elle, s'appuie sur les FLUX, construits a partir de la totalite
# des paquets captures — aucune information n'est perdue pour l'analyse.
MAX_PAQUETS_TRANSMIS = 1000


def list_interfaces() -> int:
    """Affiche les interfaces reseau vues par tshark, puis retourne son code de sortie."""
    completed = subprocess.run(["tshark", "-D"], capture_output=True, text=True, check=False)
    print(completed.stdout or completed.stderr)
    print("Sur un Mac, en0 est generalement le Wi-Fi et en1/en2 l'Ethernet ou Thunderbolt.")
    return completed.returncode


def login(api: str, username: str, password: str) -> str:
    """Authentifie l'agent aupres de l'API et retourne son jeton JWT."""
    import httpx

    response = httpx.post(
        f"{api}/api/auth/login",
        data={"username": username, "password": password},
        timeout=15,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def build_tshark_command(interface: str, duration: int) -> list[str]:
    """Construit la commande tshark qui capture pendant `duration` secondes."""
    command = [
        "tshark",
        "-i", interface,
        "-a", f"duration:{duration}",  # s'arrete tout seul : un cycle = un appel
        "-n",                            # pas de resolution DNS
        "-T", "fields",
        "-E", "separator=\t",
    ]
    for field in TSHARK_FIELDS:
        command += ["-e", field]
    return command


def parse_line(line: str, index: int, started_at: float) -> tuple[_RawPacket, dict] | None:
    """Convertit une ligne de sortie tshark en (paquet brut, paquet affichable).

    Retourne None si la ligne ne porte pas d'adresses IP (trames ARP, etc.).
    """
    parts = line.split("\t")
    if len(parts) < len(TSHARK_FIELDS):
        parts += [""] * (len(TSHARK_FIELDS) - len(parts))

    def as_int(value: str, default: int = 0) -> int:
        try:
            return int(value.split(",")[0], 16) if value.startswith("0x") else int(float(value))
        except (ValueError, TypeError):
            return default

    # tshark renvoie plusieurs valeurs separees par des virgules quand un paquet
    # contient des en-tetes IP imbriques (erreur ICMP citant le paquet d'origine,
    # tunnel IP-dans-IP...). Seule la premiere decrit l'en-tete exterieur, donc le
    # veritable emetteur ; conserver la chaine entiere produirait une adresse
    # invalide, inutilisable pour l'agregation comme pour le blocage.
    src_ip = parts[2].split(",")[0].strip()
    dst_ip = parts[3].split(",")[0].strip()
    if not src_ip or not dst_ip:
        return None

    proto = as_int(parts[4])
    length = as_int(parts[1])
    horodatage = float(parts[0] or time.time())

    brut = _RawPacket(
        ts=horodatage,
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
    affichable = {
        "packet_no": index,
        "time": round(horodatage - started_at, 6),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": (parts[12] or PROTOCOL_NAMES.get(proto, str(proto)))[:10],
        "length": length,
        "info": (parts[13] or "")[:100],
    }
    return brut, affichable


def capture_cycle(interface: str, duration: int, first_index: int, started_at: float):
    """Capture pendant `duration` secondes et retourne (paquets bruts, paquets affichables)."""
    completed = subprocess.run(
        build_tshark_command(interface, duration),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0 and not completed.stdout:
        raise RuntimeError(completed.stderr.strip() or "tshark a echoue")

    bruts: list[_RawPacket] = []
    affichables: list[dict] = []
    for offset, line in enumerate(completed.stdout.splitlines()):
        resultat = parse_line(line, first_index + offset + 1, started_at)
        if resultat is None:
            continue
        brut, affichable = resultat
        bruts.append(brut)
        affichables.append(affichable)
    return bruts, affichables


def send(api: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Envoie un cycle a l'API et retourne son resume."""
    import httpx

    response = httpx.post(
        f"{api}/api/ingest",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=60,
    )
    if response.status_code >= 400:
        # Le corps de la reponse porte la raison exacte du refus (champ fautif,
        # valeur recue). La perdre rendrait tout diagnostic impossible.
        raise RuntimeError(f"HTTP {response.status_code} — {response.text[:600]}")
    return response.json()


def serialize_flow(flow: dict[str, Any]) -> dict[str, Any]:
    """Rend un flux transmissible en JSON (les datetime ne le sont pas nativement)."""
    return {
        key: (value.isoformat() if hasattr(value, "isoformat") else value)
        for key, value in flow.items()
    }


def main() -> int:
    """Boucle principale : capture, agrege, envoie, recommence."""
    parser = argparse.ArgumentParser(
        description="Capture le trafic reseau reel de la machine et l'envoie a DDoS Monitor.",
    )
    parser.add_argument("-i", "--interface", default="en0", help="Interface a ecouter (defaut : en0)")
    parser.add_argument("--api", default="http://localhost:8000", help="URL de l'API")
    parser.add_argument("--username", default="admin", help="Compte utilise pour l'ingestion")
    parser.add_argument("--password", default="admin123", help="Mot de passe du compte")
    parser.add_argument("--interval", type=int, default=15, help="Duree d'un cycle en secondes")
    parser.add_argument("--list-interfaces", action="store_true", help="Lister les interfaces")
    args = parser.parse_args()

    if args.list_interfaces:
        return list_interfaces()

    try:
        token = login(args.api, args.username, args.password)
    except Exception as exc:  # noqa: BLE001 — message lisible plutot qu'une trace
        print(f"Connexion a l'API impossible : {exc}", file=sys.stderr)
        return 1

    print(f"Agent connecte a {args.api}")
    print(f"Capture sur '{args.interface}', cycles de {args.interval} s. Ctrl+C pour arreter.\n", flush=True)

    started_at = time.time()
    total_packets = 0

    try:
        while True:
            debut = time.time()
            try:
                bruts, affichables = capture_cycle(
                    args.interface, args.interval, total_packets, started_at
                )
            except RuntimeError as exc:
                print(f"  capture en echec : {exc}", file=sys.stderr)
                print(
                    "  Verifiez le nom de l'interface (--list-interfaces) et les droits "
                    "de capture (sudo chmod +r /dev/bpf*).",
                    file=sys.stderr,
                )
                return 1

            total_packets += len(affichables)
            ecoule = max(time.time() - debut, 0.001)
            octets = sum(p["length"] for p in affichables)

            # Les flux sont agreges sur TOUS les paquets du cycle...
            flux = [serialize_flow(f) for f in _aggregate_flows(bruts)]
            # ...seul l'echantillon destine a l'affichage est plafonne.
            a_transmettre = affichables[-MAX_PAQUETS_TRANSMIS:]

            try:
                resume = send(
                    args.api,
                    token,
                    {
                        "packets": a_transmettre,
                        "flows": flux,
                        "packets_per_second": round(len(affichables) / ecoule, 2),
                        "bytes_per_second": round(octets / ecoule, 2),
                        "agent": f"macos:{args.interface}",
                    },
                )
            except Exception as exc:  # noqa: BLE001 — l'agent ne doit pas mourir sur un 5xx
                print(f"  envoi en echec : {exc}", file=sys.stderr)
                continue

            alertes = resume.get("attacks", 0)
            marqueur = f"  ⚠ {alertes} alerte(s)" if alertes else ""
            tronque = "" if len(a_transmettre) == len(affichables) else f" (dont {len(a_transmettre)} affiches)"
            print(
                f"cycle {resume.get('cycle', '?'):>4} | "
                f"{len(affichables):>5} paquets{tronque} | {len(flux):>4} flux | "
                f"{octets / 1024:>8.1f} Ko{marqueur}",
                flush=True,
            )
    except KeyboardInterrupt:
        print(f"\nArret de l'agent. {total_packets} paquets captures au total.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
