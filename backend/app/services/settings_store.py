"""Configuration modifiable a chaud depuis l'interface d'administration.

Regle de priorite entre `.env` et l'interface
---------------------------------------------
Une meme valeur peut venir de deux endroits, d'ou une regle explicite :

  1. au demarrage, toute variable **presente dans l'environnement** ecrase la
     valeur stockee en base : le fichier `.env` decrit le deploiement et fait foi ;
  2. ensuite, l'interface d'administration peut l'ajuster a chaud, et cet
     ajustement s'applique jusqu'au prochain redemarrage.

Sans cette regle, modifier `.env` resterait sans effet une fois la ligne creee en
base, et le champ correspondant de l'interface n'aurait aucun effet sur l'envoi.

Les valeurs sont persistees dans la table `settings` et mises en cache en memoire
pour que la boucle d'analyse n'interroge pas la base a chaque tick.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, replace

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings as env_settings
from app.models import Setting

# Cles exposees a l'administration : (cle, type, valeur par defaut)
EDITABLE_KEYS: dict[str, tuple[type, object]] = {
    "capture_backend": (str, env_settings.CAPTURE_BACKEND),
    "capture_interface": (str, env_settings.CAPTURE_INTERFACE),
    "analysis_interval": (int, env_settings.ANALYSIS_INTERVAL_SECONDS),
    "confidence_threshold": (float, env_settings.ATTACK_CONFIDENCE_THRESHOLD),
    "flow_threshold": (int, env_settings.ATTACK_FLOW_THRESHOLD),
    "auto_block": (bool, False),
    "email_alerts": (bool, env_settings.ALERT_EMAIL_ENABLED),
    "alert_recipients": (str, ",".join(env_settings.ALERT_RECIPIENTS)),
}

# Variable d'environnement correspondant a chaque cle : si elle est definie au
# demarrage, elle a la priorite sur ce qui est deja enregistre en base.
ENV_VAR_BY_KEY: dict[str, str] = {
    "capture_backend": "CAPTURE_BACKEND",
    "capture_interface": "CAPTURE_INTERFACE",
    "analysis_interval": "ANALYSIS_INTERVAL_SECONDS",
    "confidence_threshold": "ATTACK_CONFIDENCE_THRESHOLD",
    "flow_threshold": "ATTACK_FLOW_THRESHOLD",
    "email_alerts": "ALERT_EMAIL_ENABLED",
    "alert_recipients": "ALERT_RECIPIENTS",
}


@dataclass(frozen=True, slots=True)
class RuntimeSettings:
    capture_backend: str
    capture_interface: str
    analysis_interval: int
    confidence_threshold: float
    flow_threshold: int
    auto_block: bool
    email_alerts: bool
    alert_recipients: str

    def as_dict(self) -> dict[str, object]:
        """Serialise la configuration pour l'API."""
        return {
            "capture_backend": self.capture_backend,
            "capture_interface": self.capture_interface,
            "analysis_interval": self.analysis_interval,
            "confidence_threshold": self.confidence_threshold,
            "flow_threshold": self.flow_threshold,
            "auto_block": self.auto_block,
            "email_alerts": self.email_alerts,
            "alert_recipients": self.alert_recipients,
        }


def _defaults() -> RuntimeSettings:
    """Construit la configuration par defaut a partir des variables d'environnement."""
    return RuntimeSettings(**{key: value for key, (_, value) in EDITABLE_KEYS.items()})  # type: ignore[arg-type]


_lock = threading.Lock()
_cache: RuntimeSettings = _defaults()


def _coerce(key: str, raw: str) -> object:
    """Convertit une valeur stockee en base vers le type attendu par la cle."""
    kind, default = EDITABLE_KEYS[key]
    try:
        if kind is bool:
            return raw.lower() in ("1", "true", "yes", "on")
        return kind(raw)
    except (TypeError, ValueError):
        return default


def load_from_db(db: Session) -> RuntimeSettings:
    """Recharge le cache au demarrage, l'environnement ayant la priorite.

    Pour chaque cle : si sa variable d'environnement est definie, elle ecrase la
    valeur en base (le deploiement fait foi) ; sinon la valeur enregistree est
    conservee. Les cles absentes sont creees avec leur valeur par defaut.
    """
    global _cache
    stored = {row.key: row.value for row in db.execute(select(Setting)).scalars()}
    defaults = _defaults().as_dict()
    values = dict(defaults)

    a_ecrire: list[Setting] = []
    for key in EDITABLE_KEYS:
        env_var = ENV_VAR_BY_KEY.get(key)
        force_env = env_var is not None and env_var in os.environ

        if force_env:
            values[key] = defaults[key]  # deja lue depuis l'environnement
        elif key in stored:
            values[key] = _coerce(key, stored[key])

        # Synchronise la ligne si elle manque ou ne correspond plus
        attendu = str(values[key])
        if stored.get(key) != attendu:
            ligne = db.get(Setting, key)
            if ligne is None:
                a_ecrire.append(Setting(key=key, value=attendu))
            else:
                ligne.value = attendu

    if a_ecrire:
        db.add_all(a_ecrire)
    db.commit()

    with _lock:
        _cache = RuntimeSettings(**values)  # type: ignore[arg-type]
    return _cache


def get_runtime_settings() -> RuntimeSettings:
    """Retourne la configuration courante depuis le cache memoire."""
    return _cache


def update(db: Session, changes: dict[str, object]) -> RuntimeSettings:
    """Applique une mise a jour partielle, la persiste et rafraichit le cache."""
    global _cache
    applied: dict[str, object] = {}

    for key, value in changes.items():
        if key not in EDITABLE_KEYS or value is None:
            continue
        row = db.get(Setting, key)
        if row is None:
            row = Setting(key=key, value=str(value))
            db.add(row)
        else:
            row.value = str(value)
        applied[key] = _coerce(key, str(value))

    db.commit()
    with _lock:
        _cache = replace(_cache, **applied)  # type: ignore[arg-type]
    return _cache
