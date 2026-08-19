"""Inventaire des interfaces reseau reellement capturables par le backend.

Repond a une question concrete : quand on ecrit `CAPTURE_INTERFACE=eth0`, de
quelle interface parle-t-on exactement ?

Cela depend entierement du mode reseau du conteneur :

  - Reseau bridge (docker-compose.yml seul) : `eth0` est l'interface **virtuelle
    du conteneur**. On n'y voit que le trafic du conteneur lui-meme, pas celui du
    serveur. Sans les capabilities, dumpcap ne liste meme aucune interface reelle.

  - `network_mode: host` sur un serveur **Linux** (docker-compose.capture.yml) :
    le conteneur partage la pile reseau de l'hote. `eth0`, `ens33`, `enp0s3`…
    sont alors les vraies interfaces du serveur, et la capture voit son trafic.

  - `network_mode: host` sur **macOS ou Windows** : Docker tourne dans une VM
    Linux ; on capture le reseau de cette VM, pas celui de la machine. Utiliser
    `tools/capture_agent.py` a la place.

Ce module interroge dumpcap/tshark et renvoie ce qui est reellement disponible,
avec un diagnostic lisible affiche dans l'interface d'administration.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

from app.core.config import settings
from app.services.capture import current_backend

logger = logging.getLogger(__name__)

COMMAND_TIMEOUT = 10

# Pseudo-interfaces fournies par les greffons extcap de Wireshark : elles
# apparaissent dans `tshark -D` mais ne capturent aucun trafic local.
EXTCAP_PSEUDO = {
    "ciscodump",
    "dpauxmon",
    "randpkt",
    "sdjournal",
    "sshdump",
    "udpdump",
    "wifidump",
}

# Interfaces speciales de libpcap : utiles, mais ce ne sont pas des cartes reseau.
SPECIAL = {"any", "lo", "lo0"}

# Peripheriques crees d'office par le noyau Linux (tunnels inactifs) ou sources
# de capture non reseau. Les proposer comme interface a surveiller n'a pas de sens.
KERNEL_STUBS = {
    "tunl0",
    "gre0",
    "gretap0",
    "erspan0",
    "ip_vti0",
    "ip6_vti0",
    "sit0",
    "ip6tnl0",
    "ip6gre0",
    "bluetooth-monitor",
    "nflog",
    "nfqueue",
    "dbus-system",
    "dbus-session",
}


def _run(command: list[str]) -> tuple[int, str]:
    """Execute une commande sans shell et retourne (code de retour, sortie).

    Ne leve jamais : toute erreur systeme est convertie en code de retour, car
    l'appelant expose le resultat dans une reponse HTTP.
    """
    try:
        completed = subprocess.run(  # noqa: S603 — commande construite en dur
            command, capture_output=True, text=True, timeout=COMMAND_TIMEOUT, check=False
        )
    except FileNotFoundError:
        return 127, f"commande introuvable : {command[0]}"
    except subprocess.TimeoutExpired:
        return 124, "delai depasse"
    except PermissionError as exc:
        # EPERM typique : le binaire porte des file capabilities que le conteneur
        # n'a pas dans son bounding set, donc execve() est refuse.
        return 126, f"execution refusee ({exc.strerror}) : {command[0]}"
    except OSError as exc:  # noqa: BLE001 — remonte proprement au diagnostic
        return 125, f"{type(exc).__name__}: {exc}"
    return completed.returncode, completed.stdout + completed.stderr


def _in_container() -> bool:
    """Detecte si le processus tourne dans un conteneur (heuristique usuelle)."""
    return Path("/.dockerenv").exists()


def _default_route_interface() -> str | None:
    """Nom de l'interface portant la route par defaut, lu dans /proc/net/route."""
    try:
        lignes = Path("/proc/net/route").read_text().splitlines()[1:]
    except OSError:
        return None

    for ligne in lignes:
        colonnes = ligne.split()
        # Destination "00000000" = route par defaut
        if len(colonnes) > 1 and colonnes[1] == "00000000":
            return colonnes[0]
    return None


def _host_network() -> bool | None:
    """Determine si le conteneur partage la pile reseau de l'hote.

    Retourne None quand la question n'est pas tranchable (route par defaut
    absente, /sys illisible) : mieux vaut ne rien affirmer que d'induire en erreur.

    On teste uniquement l'interface qui porte la route par defaut. Sur un reseau
    bridge, Docker la relie par une paire veth : cote conteneur, `iflink`
    (index du pair) differe de `ifindex` (index local). En mode host, cette
    interface est une vraie carte reseau et les deux valeurs coincident.

    Tester toutes les interfaces serait trompeur : un serveur qui heberge Docker
    possede lui-meme des `veth*`, ce qui ferait conclure a tort au mode bridge.
    """
    if not _in_container():
        return False

    principale = _default_route_interface()
    if not principale:
        return None

    chemin = Path("/sys/class/net") / principale
    try:
        ifindex = (chemin / "ifindex").read_text().strip()
        iflink = (chemin / "iflink").read_text().strip()
    except OSError:
        return None
    return ifindex == iflink


def list_interfaces() -> dict[str, object]:
    """Liste les interfaces capturables et explique ce qui est reellement observe."""
    outil = shutil.which("dumpcap") or shutil.which("tshark")
    if outil is None:
        return {
            "available": False,
            "interfaces": [],
            "capture_possible": False,
            "explanation": (
                "Ni dumpcap ni tshark ne sont installes : la capture reelle est "
                "impossible depuis ce backend. Utilisez CAPTURE_BACKEND=simulator "
                "ou l'agent externe."
            ),
            "current": settings.CAPTURE_INTERFACE,
            "backend": current_backend(),
        }

    code, sortie = _run([outil, "-D"])

    # dumpcap peut etre inexecutable faute de capabilities : tshark, lui, n'en
    # porte pas et repond toujours, meme s'il ne listera que des pseudo-interfaces.
    if code in (125, 126) and outil.endswith("dumpcap"):
        secours = shutil.which("tshark")
        if secours:
            code, sortie = _run([secours, "-D"])

    interfaces: list[dict[str, object]] = []

    # Format attendu : "1. eth0" ou "2. en0 (Wi-Fi)"
    for ligne in sortie.splitlines():
        correspondance = re.match(r"^\s*\d+\.\s+(\S+)(?:\s+\((.*)\))?", ligne)
        if not correspondance:
            continue
        nom = correspondance.group(1)
        description = correspondance.group(2) or ""
        base = nom.split("/")[-1]
        interfaces.append(
            {
                "name": nom,
                "description": description,
                "pseudo": base in EXTCAP_PSEUDO or base in KERNEL_STUBS,
                "special": base in SPECIAL,
            }
        )

    reelles = [i for i in interfaces if not i["pseudo"] and not i["special"]]
    capture_possible = bool(reelles)

    return {
        "available": True,
        "interfaces": interfaces,
        "real_interfaces": [i["name"] for i in reelles],
        "capture_possible": capture_possible,
        "current": settings.CAPTURE_INTERFACE,
        "backend": current_backend(),
        "in_container": _in_container(),
        "host_network": _host_network(),
        "explanation": _explain(capture_possible, reelles, interfaces, code, sortie),
    }


def _explain(
    capture_possible: bool,
    reelles: list[dict],
    toutes: list[dict],
    code: int,
    sortie: str,
) -> str:
    """Redige le diagnostic affiche a l'administrateur.

    L'ordre des cas compte : le message le plus informatif est celui qui explique
    *pourquoi* rien n'est capturable, pas le code de retour brut de l'outil.
    """
    if not capture_possible:
        prive = code in (125, 126) or "permission" in sortie.lower() or "denied" in sortie.lower()
        if prive:
            return (
                "Aucune interface capturable : le conteneur n'a pas les privileges "
                "reseau (dumpcap ne peut meme pas demarrer). Lancez-le avec "
                "docker-compose.capture.yml, qui ajoute cap_add NET_ADMIN et NET_RAW."
            )
        if toutes:
            # Des pseudo-interfaces Wireshark sont listees, mais aucune carte reseau.
            return (
                "Aucune interface reseau reelle n'est visible : seules des "
                f"pseudo-interfaces Wireshark ({len(toutes)}) sont listees. Sans "
                "privileges reseau, le conteneur ne peut capturer aucun trafic. "
                "Utilisez docker-compose.capture.yml sur un serveur Linux, ou "
                "l'agent tools/capture_agent.py en local."
            )
        if code != 0:
            return f"La liste des interfaces a echoue (code {code}). Sortie : {sortie[:200]}"
        return "Aucune interface detectee sur ce systeme."

    noms = ", ".join(str(i["name"]) for i in reelles[:6])
    if len(reelles) > 6:
        noms += f" (+{len(reelles) - 6})"

    if not _in_container():
        return f"Capture possible sur les interfaces de cette machine : {noms}."

    mode = _host_network()
    if mode is True:
        return (
            f"Le conteneur partage la pile reseau de l'hote : {noms} sont les "
            "interfaces du serveur, leur trafic est donc bien observe."
        )
    if mode is False:
        return (
            f"Interface(s) disponible(s) : {noms}. Attention, le conteneur est sur "
            "un reseau bridge : eth0 est son interface virtuelle et ne voit que son "
            "propre trafic, pas celui du serveur. Pour surveiller le serveur, "
            "demarrez avec docker-compose.capture.yml (network_mode: host)."
        )
    return (
        f"Interface(s) disponible(s) : {noms}. Le mode reseau du conteneur n'a pas "
        "pu etre determine : verifiez que l'interface choisie est bien celle du "
        "serveur a surveiller, et non une interface virtuelle."
    )
