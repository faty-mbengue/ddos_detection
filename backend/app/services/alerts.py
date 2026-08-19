"""Notifications par email lors de la detection d'une attaque.

Configuration Gmail
-------------------
    SMTP_HOST=smtp.gmail.com
    SMTP_PORT=587
    SMTP_STARTTLS=true
    SMTP_USER=votre.compte@gmail.com
    SMTP_PASSWORD=<mot de passe d'application, 16 caracteres>

Google refuse depuis 2022 le mot de passe du compte : il faut activer la
verification en deux etapes puis generer un « mot de passe d'application »
(https://myaccount.google.com/apppasswords). Il se renseigne dans `.env`, jamais
dans le depot.

A savoir sur l'expediteur : Gmail reecrit l'en-tete `From` avec l'adresse du
compte authentifie, sauf si l'adresse voulue a ete declaree comme alias verifie
dans Gmail (Parametres > Comptes > « Envoyer des e-mails en tant que »). Un
`SMTP_FROM` different de `SMTP_USER` sera donc probablement remplace.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage

from app.core.config import settings
from app.models import Attack

logger = logging.getLogger(__name__)

# Delai maximal accorde a Gmail avant d'abandonner l'envoi.
SMTP_TIMEOUT = 20


def sender_address() -> str:
    """Adresse d'expedition effective.

    A defaut de `SMTP_FROM`, on utilise le compte authentifie : c'est de toute
    facon l'adresse que Gmail imposera.
    """
    return settings.SMTP_FROM or settings.SMTP_USER or "alerts@ddos-monitor.local"


def sender_will_be_rewritten() -> bool:
    """Indique si le fournisseur remplacera l'expediteur declare.

    Gmail (comme la plupart des messageries grand public) impose l'adresse du
    compte authentifie dans l'en-tete `From`, sauf si l'adresse voulue a ete
    declaree comme alias verifie. Dans ce cas, `SMTP_FROM` n'a aucun effet.
    """
    hote = (settings.SMTP_HOST or "").lower()
    fournisseur_grand_public = any(
        domaine in hote for domaine in ("gmail.com", "googlemail.com", "outlook.com", "office365")
    )
    return bool(
        fournisseur_grand_public
        and settings.SMTP_USER
        and settings.SMTP_FROM
        and settings.SMTP_FROM.strip().lower() != settings.SMTP_USER.strip().lower()
    )


def recipients() -> list[str]:
    """Destinataires effectifs des alertes.

    La valeur modifiable depuis l'administration a la priorite ; a defaut on
    retombe sur `ALERT_RECIPIENTS` de l'environnement.
    """
    from app.services.settings_store import get_runtime_settings

    brut = get_runtime_settings().alert_recipients or ""
    liste = [adresse.strip() for adresse in brut.split(",") if adresse.strip()]
    return liste or list(settings.ALERT_RECIPIENTS)


def alerts_enabled() -> bool:
    """Indique si les notifications sont activees (interrupteur de l'administration)."""
    from app.services.settings_store import get_runtime_settings

    return bool(get_runtime_settings().email_alerts)


def is_configured() -> bool:
    """Indique si l'envoi d'emails est active et suffisamment configure."""
    return bool(
        alerts_enabled()
        and settings.SMTP_HOST
        and settings.SMTP_USER
        and settings.SMTP_PASSWORD
        and recipients()
    )


def configuration_status() -> dict[str, object]:
    """Diagnostic de la configuration email, affiche dans l'administration."""
    destinataires = recipients()
    manquants = []
    if not settings.SMTP_HOST:
        manquants.append("SMTP_HOST")
    if not settings.SMTP_USER:
        manquants.append("SMTP_USER")
    if not settings.SMTP_PASSWORD:
        manquants.append("SMTP_PASSWORD")
    if not destinataires:
        manquants.append("ALERT_RECIPIENTS")

    if not alerts_enabled():
        explication = (
            "Notifications desactivees. Activez l'interrupteur ci-dessus, "
            "ou ALERT_EMAIL_ENABLED dans .env."
        )
    elif manquants:
        explication = f"Configuration incomplete, il manque : {', '.join(manquants)}."
    else:
        explication = (
            f"Pret a envoyer via {settings.SMTP_HOST}:{settings.SMTP_PORT} "
            f"vers {len(destinataires)} destinataire(s)."
        )

    reecrit = sender_will_be_rewritten()
    return {
        "enabled": alerts_enabled(),
        "configured": is_configured(),
        "host": settings.SMTP_HOST,
        "port": settings.SMTP_PORT,
        "starttls": settings.SMTP_STARTTLS,
        "user": settings.SMTP_USER,
        # `sender` est l'adresse declaree, `effective_sender` celle qui arrivera
        # reellement chez le destinataire.
        "sender": sender_address(),
        "effective_sender": settings.SMTP_USER if reecrit else sender_address(),
        "sender_rewritten": reecrit,
        "sender_warning": (
            f"SMTP_FROM ({settings.SMTP_FROM}) sera ignore : le fournisseur imposera "
            f"{settings.SMTP_USER}. Declarez l'adresse comme alias verifie, ou "
            "supprimez SMTP_FROM."
            if reecrit
            else None
        ),
        "recipients": destinataires,
        "missing": manquants,
        "explanation": explication,
    }


def _build_message(attack: Attack, recipients: list[str]) -> EmailMessage:
    """Compose l'email d'alerte decrivant l'attaque detectee."""
    message = EmailMessage()
    message["Subject"] = f"[DDoS Monitor] Attaque {attack.attack_type} detectee ({attack.severity})"
    message["From"] = sender_address()
    message["To"] = ", ".join(recipients)
    message.set_content(
        f"""Une attaque DDoS a ete detectee par le systeme de surveillance.

Type d'attaque   : {attack.attack_type}
Criticite        : {attack.severity}
IP source        : {attack.source_ip}
IP destination   : {attack.destination_ip}
Flux concernes   : {attack.flows_count}
Paquets          : {attack.total_packets}
Volume           : {attack.total_bytes} octets
Confiance moyenne: {attack.avg_confidence:.2f} %
Horodatage       : {attack.timestamp:%Y-%m-%d %H:%M:%S}

-- DDoS Monitor (detection Random Forest / CICDDoS2019)
"""
    )
    return message


def _build_test_message(recipients: list[str]) -> EmailMessage:
    """Compose l'email de test envoye depuis l'administration."""
    message = EmailMessage()
    message["Subject"] = "[DDoS Monitor] Test de configuration des alertes"
    message["From"] = sender_address()
    message["To"] = ", ".join(recipients)
    message.set_content(
        f"""Ceci est un email de test envoye depuis DDoS Monitor.

Si vous le recevez, les alertes d'attaque parviendront a cette adresse.

Serveur SMTP : {settings.SMTP_HOST}:{settings.SMTP_PORT}
Compte       : {settings.SMTP_USER}
Expediteur   : {sender_address()}

-- DDoS Monitor
"""
    )
    return message


def _send_sync(message: EmailMessage) -> None:
    """Ouvre la session SMTP et envoie le message (appel bloquant)."""
    with smtplib.SMTP(settings.SMTP_HOST or "", settings.SMTP_PORT, timeout=SMTP_TIMEOUT) as server:
        server.ehlo()
        if settings.SMTP_STARTTLS:
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.send_message(message)


def _readable_error(exc: Exception) -> str:
    """Traduit une erreur SMTP en message actionnable, sans divulguer le secret."""
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return (
            "Authentification refusee par le serveur. Avec Gmail, activez la "
            "verification en deux etapes puis utilisez un mot de passe "
            "d'application (16 caracteres) comme SMTP_PASSWORD."
        )
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "Destinataire refuse : verifiez ALERT_RECIPIENTS."
    if isinstance(exc, smtplib.SMTPConnectError | TimeoutError | OSError):
        return (
            f"Connexion impossible a {settings.SMTP_HOST}:{settings.SMTP_PORT}. "
            "Verifiez le reseau du conteneur et que le port sortant est autorise."
        )
    return f"{type(exc).__name__}: {exc}"


async def send_attack_alert(attack: Attack) -> bool:
    """Envoie l'alerte email si la configuration SMTP est complete."""
    if not is_configured():
        return False
    try:
        await asyncio.to_thread(_send_sync, _build_message(attack, recipients()))
    except Exception as exc:  # noqa: BLE001 — une panne SMTP ne doit pas casser le pipeline
        logger.error("Echec de l'alerte email : %s", _readable_error(exc))
        return False
    logger.info("Alerte email envoyee pour l'attaque %s", attack.id)
    return True


async def send_test_email(destinataires: list[str] | None = None) -> dict[str, object]:
    """Envoie un email de test et retourne le resultat, erreur comprise.

    Ignore volontairement l'interrupteur d'activation : le test doit rester
    possible avant d'allumer les notifications.
    """
    destinataires = destinataires or recipients()
    if not destinataires:
        return {"sent": False, "detail": "Aucun destinataire : renseignez ALERT_RECIPIENTS."}
    if not (settings.SMTP_HOST and settings.SMTP_USER and settings.SMTP_PASSWORD):
        return {"sent": False, "detail": "Configuration SMTP incomplete (hote, compte ou mot de passe)."}

    try:
        await asyncio.to_thread(_send_sync, _build_test_message(destinataires))
    except Exception as exc:  # noqa: BLE001 — on remonte l'erreur a l'administrateur
        detail = _readable_error(exc)
        logger.error("Email de test en echec : %s", detail)
        return {"sent": False, "detail": detail}

    return {"sent": True, "detail": f"Email de test envoye a {', '.join(destinataires)}."}
