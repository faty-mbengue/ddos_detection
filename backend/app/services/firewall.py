"""Application effective du blocage d'adresses IP (mitigation).

Sans ce service, la table `blocked_ips` n'est qu'un inventaire : aucune regle
n'est posee et le trafic continue de passer. Trois backends sont disponibles :

  - `none`     : aucun effet reseau (defaut). La liste reste documentaire et
                 l'interface l'indique explicitement.
  - `iptables` : Linux. Insere `-A INPUT -s <ip> -j DROP` dans une chaine dediee.
  - `pfctl`    : macOS. Alimente la table `ddos_monitor_blocked` du pare-feu pf.

Le backend est choisi par `FIREWALL_BACKEND` et n'agit que si `FIREWALL_ENABLED`
vaut true. Toutes les commandes sont construites en interne (jamais de shell),
et l'adresse est validee avant usage : une valeur venant de la base ne peut donc
pas etre interpretee comme une option ou une commande.

Privileges requis :
  - Linux    : capability NET_ADMIN (voir docker-compose.capture.yml).
  - macOS    : droits root pour pfctl, donc backend lance hors conteneur en sudo.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import shutil
import subprocess
from dataclasses import dataclass

from app.core.config import settings

logger = logging.getLogger(__name__)

# Nom des objets crees dans le pare-feu, pour ne jamais toucher aux regles de l'hote.
IPTABLES_CHAIN = "DDOS_MONITOR"
PF_TABLE = "ddos_monitor_blocked"

COMMAND_TIMEOUT = 10


@dataclass(slots=True)
class FirewallResult:
    """Issue d'une operation de pare-feu, remontee telle quelle a l'interface."""

    applied: bool
    backend: str
    detail: str


def is_valid_ip(address: str) -> bool:
    """Verifie qu'une chaine est bien une adresse IPv4/IPv6 (et rien d'autre)."""
    try:
        ipaddress.ip_address(address)
    except ValueError:
        return False
    return True


def _run(command: list[str]) -> tuple[int, str]:
    """Execute une commande sans shell et retourne (code de retour, sortie)."""
    try:
        completed = subprocess.run(  # noqa: S603 — arguments construits en dur, IP validee
            command,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        return 127, f"commande introuvable : {command[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"delai depasse : {' '.join(command)}"

    sortie = (completed.stdout + completed.stderr).strip()
    return completed.returncode, sortie


class FirewallService:
    """Pose et retire les regles de blocage selon le backend configure."""

    def __init__(self) -> None:
        """Lit la configuration du pare-feu sans encore toucher au systeme."""
        self._backend = (settings.FIREWALL_BACKEND or "none").lower()
        self._enabled = settings.FIREWALL_ENABLED
        self._last_error: str | None = None
        self._ready = False

    # ── Etat ──────────────────────────────────────────────────────────────────
    @property
    def backend(self) -> str:
        """Backend effectivement utilise (`none` si desactive)."""
        return self._backend if self._enabled else "none"

    @property
    def is_active(self) -> bool:
        """True si les regles sont reellement posees sur le systeme."""
        return self._enabled and self._backend in ("iptables", "pfctl") and self._ready

    def status(self) -> dict[str, object]:
        """Etat du pare-feu, expose par l'API et affiche dans l'administration."""
        return {
            "enabled": self._enabled,
            "backend": self.backend,
            "active": self.is_active,
            "available": self._tool_available(),
            "last_error": self._last_error,
            "explanation": self._explanation(),
        }

    def _explanation(self) -> str:
        """Phrase affichee a l'utilisateur pour lever toute ambiguite."""
        if not self._enabled:
            return (
                "Blocage non applique : la liste sert d'inventaire de mitigation. "
                "Activez FIREWALL_ENABLED pour poser de vraies regles."
            )
        if not self._tool_available():
            return (
                f"{self._backend} est introuvable dans ce conteneur : "
                "aucune regle ne peut etre posee."
            )
        if not self._ready:
            return (
                f"{self._backend} est present mais l'initialisation a echoue "
                "(privileges insuffisants ?) : aucune regle n'est posee."
            )
        return f"Les regles sont appliquees via {self._backend}."

    def _tool_available(self) -> bool:
        """Verifie la presence de l'outil systeme correspondant au backend."""
        if self._backend == "iptables":
            return shutil.which("iptables") is not None
        if self._backend == "pfctl":
            return shutil.which("pfctl") is not None
        return False

    # ── Initialisation ────────────────────────────────────────────────────────
    def setup(self) -> None:
        """Prepare la chaine ou la table dediee. Sans effet si le backend est `none`."""
        if not self._enabled or self._backend == "none":
            logger.info("Pare-feu desactive : le blocage restera documentaire")
            return

        if not self._tool_available():
            self._last_error = f"{self._backend} introuvable"
            logger.warning("Pare-feu %s indisponible : blocage sans effet", self._backend)
            return

        if self._backend == "iptables":
            self._ready = self._setup_iptables()
        elif self._backend == "pfctl":
            self._ready = self._setup_pfctl()

        if self._ready:
            logger.info("Pare-feu %s pret : les blocages seront appliques", self._backend)

    def _setup_iptables(self) -> bool:
        """Cree la chaine DDOS_MONITOR et la branche sur INPUT (idempotent)."""
        code, sortie = _run(["iptables", "-N", IPTABLES_CHAIN])
        # Code 1 = la chaine existe deja, ce qui est le cas nominal au redemarrage.
        if code not in (0, 1):
            self._last_error = sortie
            return False

        # -C teste la presence de la regle avant de l'inserer, pour ne pas empiler.
        code, _ = _run(["iptables", "-C", "INPUT", "-j", IPTABLES_CHAIN])
        if code != 0:
            code, sortie = _run(["iptables", "-I", "INPUT", "-j", IPTABLES_CHAIN])
            if code != 0:
                self._last_error = sortie
                return False

        self._last_error = None
        return True

    def _setup_pfctl(self) -> bool:
        """Verifie que pf est joignable ; la table est creee au premier ajout."""
        code, sortie = _run(["pfctl", "-s", "info"])
        if code != 0:
            self._last_error = sortie or "pfctl inaccessible (root requis)"
            return False
        self._last_error = None
        return True

    # ── Operations ────────────────────────────────────────────────────────────
    def block(self, address: str) -> FirewallResult:
        """Bloque une adresse. Retourne si la regle a effectivement ete posee."""
        if not is_valid_ip(address):
            return FirewallResult(False, self.backend, f"adresse invalide : {address}")

        if not self.is_active:
            return FirewallResult(False, self.backend, self._explanation())

        if self._backend == "iptables":
            # -C evite les doublons si l'IP est bloquee deux fois.
            code, _ = _run(["iptables", "-C", IPTABLES_CHAIN, "-s", address, "-j", "DROP"])
            if code == 0:
                return FirewallResult(True, "iptables", "regle deja presente")
            code, sortie = _run(["iptables", "-A", IPTABLES_CHAIN, "-s", address, "-j", "DROP"])
        else:
            code, sortie = _run(["pfctl", "-t", PF_TABLE, "-T", "add", address])

        if code != 0:
            self._last_error = sortie
            logger.error("Blocage de %s echoue : %s", address, sortie)
            return FirewallResult(False, self.backend, sortie)

        logger.warning("IP bloquee au niveau reseau : %s (%s)", address, self._backend)
        return FirewallResult(True, self.backend, "regle posee")

    def unblock(self, address: str) -> FirewallResult:
        """Retire la regle de blocage d'une adresse."""
        if not is_valid_ip(address):
            return FirewallResult(False, self.backend, f"adresse invalide : {address}")

        if not self.is_active:
            return FirewallResult(False, self.backend, self._explanation())

        if self._backend == "iptables":
            code, sortie = _run(["iptables", "-D", IPTABLES_CHAIN, "-s", address, "-j", "DROP"])
        else:
            code, sortie = _run(["pfctl", "-t", PF_TABLE, "-T", "delete", address])

        if code != 0:
            # L'absence de regle n'est pas une erreur : l'etat vise est atteint.
            logger.info("Deblocage de %s sans regle correspondante : %s", address, sortie)
            return FirewallResult(True, self.backend, "aucune regle a retirer")

        logger.info("IP debloquee au niveau reseau : %s", address)
        return FirewallResult(True, self.backend, "regle retiree")

    def sync(self, addresses: list[str]) -> int:
        """Re-applique la liste complete au demarrage. Retourne le nombre de regles posees."""
        if not self.is_active:
            return 0
        return sum(1 for adresse in addresses if self.block(adresse).applied)

    # ── Variantes asynchrones (les commandes systeme sont bloquantes) ─────────
    async def block_async(self, address: str) -> FirewallResult:
        """Version non bloquante de `block`, pour la boucle d'analyse."""
        return await asyncio.to_thread(self.block, address)

    async def unblock_async(self, address: str) -> FirewallResult:
        """Version non bloquante de `unblock`."""
        return await asyncio.to_thread(self.unblock, address)


firewall = FirewallService()
