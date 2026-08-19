"""Configuration centralisee de l'application (12-factor : tout vient de l'environnement)."""

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── Application ───────────────────────────────────────────────────────────
    PROJECT_NAME: str = "DDoS Monitor"
    API_V1_PREFIX: str = "/api"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # ── Base de donnees ───────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+psycopg://ddos:ddos@localhost:5432/ddos_monitor"

    # ── Securite / JWT ────────────────────────────────────────────────────────
    SECRET_KEY: str = "change-me-in-production-please-use-a-long-random-value"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 12
    # NoDecode : pydantic-settings n'essaie pas de decoder du JSON, le validateur
    # ci-dessous accepte aussi bien "A,B,C" qu'une liste JSON.
    CORS_ORIGINS: Annotated[list[str], NoDecode] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost",
        "http://localhost:8080",
    ]

    # Compte administrateur cree au premier demarrage
    FIRST_ADMIN_USERNAME: str = "admin"
    FIRST_ADMIN_EMAIL: str = "admin@ddos-monitor.local"
    FIRST_ADMIN_PASSWORD: str = "admin123"

    # ── Capture du trafic ─────────────────────────────────────────────────────
    # "simulator" : generateur de trafic synthetique (defaut, aucun privilege requis)
    # "tshark"    : capture reelle depuis le backend (Linux : NET_ADMIN + network_mode host)
    # "external"  : aucune capture locale, les donnees arrivent par POST /api/ingest
    #               depuis tools/capture_agent.py (seule option sur macOS)
    CAPTURE_BACKEND: str = "simulator"
    CAPTURE_INTERFACE: str = "eth0"
    CAPTURE_ENABLED: bool = True
    ANALYSIS_INTERVAL_SECONDS: int = 15
    LIVE_PACKET_RETENTION: int = 2000

    # ── Pare-feu (mitigation reelle) ──────────────────────────────────────────
    # false : la liste d'IP bloquees reste un inventaire, aucune regle n'est posee.
    # true  : les regles sont reellement appliquees (privileges requis).
    FIREWALL_ENABLED: bool = False
    FIREWALL_BACKEND: str = "none"  # none | iptables (Linux) | pfctl (macOS)

    # ── Detection ─────────────────────────────────────────────────────────────
    MODEL_DIR: Path = BASE_DIR / "app" / "ml" / "artifacts"
    ATTACK_CONFIDENCE_THRESHOLD: float = 0.70
    ATTACK_FLOW_THRESHOLD: int = 3

    # ── Alertes email ─────────────────────────────────────────────────────────
    # Configure pour Gmail : port 587 avec STARTTLS. SMTP_PASSWORD doit etre un
    # mot de passe d'application Google (16 caracteres, genere avec la
    # verification en deux etapes) — le mot de passe du compte est refuse.
    SMTP_HOST: str | None = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_STARTTLS: bool = True
    SMTP_USER: str | None = None
    SMTP_PASSWORD: str | None = None
    SMTP_FROM: str = "alerts@ddos-monitor.local"
    ALERT_EMAIL_ENABLED: bool = False
    ALERT_RECIPIENTS: Annotated[list[str], NoDecode] = []

    @field_validator("CORS_ORIGINS", "ALERT_RECIPIENTS", mode="before")
    @classmethod
    def _split_csv(cls, v: object) -> object:
        """Accepte `A,B,C` comme une liste JSON en variable d'environnement."""
        if isinstance(v, str):
            text = v.strip()
            if text.startswith("["):
                import json

                return json.loads(text)
            return [item.strip() for item in text.split(",") if item.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    """Retourne la configuration, mise en cache pour tout le processus."""
    return Settings()


settings = get_settings()
