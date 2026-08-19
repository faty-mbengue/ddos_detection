"""Analyse hors ligne d'un fichier de capture deposé par l'utilisateur.

Deux formats sont acceptes, qui correspondent aux deux etapes du flux decrit
dans le memoire :

  - **PCAP / PCAPNG** : capture brute. Le fichier est relu par `tshark`, les
    paquets sont agreges en flux (CICFlowMeter simplifie), puis classes.
  - **CSV CICFlowMeter** : sortie du vrai CICFlowMeter. C'est la voie la plus
    fidele, puisque les 31 caracteristiques sont alors calculees par l'outil de
    reference et non par notre agregation simplifiee.

Aucune donnee n'est enregistree par defaut : l'analyse est retournee telle
quelle. L'appelant peut demander la persistance, auquel cas les flux sont
marques `source="upload"` pour ne jamais se melanger au trafic surveille.
"""

from __future__ import annotations

import logging
import re
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from app.ml.features import CLASS_NAMES, FEATURE_NAMES, raw_vector_from_flow
from app.models import Flow
from app.services.capture import TSHARK_FIELDS, _aggregate_flows, _RawPacket
from app.services.ml import predictor
from app.services.settings_store import get_runtime_settings

logger = logging.getLogger(__name__)

# Au-dela, la lecture bloquerait trop longtemps une requete HTTP.
TAILLE_MAX_OCTETS = 200 * 1024 * 1024
TSHARK_TIMEOUT = 300

EXTENSIONS_PCAP = {".pcap", ".pcapng", ".cap", ".dmp"}
EXTENSIONS_CSV = {".csv", ".txt"}


class AnalyseError(Exception):
    """Erreur fonctionnelle, destinee a etre affichee telle quelle a l'utilisateur."""


def _normaliser(nom: str) -> str:
    """Reduit un nom de colonne a sa forme comparable (casse et separateurs ignores)."""
    return "".join(c for c in nom.lower() if c.isalnum())


# Equivalences entre les noms du modele et ceux des differentes versions de
# CICFlowMeter (la nomenclature a change entre les versions Java et Python).
ALIAS_COLONNES: dict[str, tuple[str, ...]] = {
    "Total Fwd Packets": ("Tot Fwd Pkts", "Total Fwd Packet"),
    "Total Backward Packets": ("Tot Bwd Pkts", "Total Bwd packets", "Total Backward Packets"),
    # CICDDoS2019 emploie le pluriel « Packets » ; CICFlowMeter V4 le singulier.
    "Fwd Packets Length Total": (
        "TotLen Fwd Pkts",
        "Total Length of Fwd Packets",
        "Total Length of Fwd Packet",
    ),
    "Fwd Packet Length Max": ("Fwd Pkt Len Max",),
    "Fwd Packet Length Std": ("Fwd Pkt Len Std",),
    "Bwd Packet Length Max": ("Bwd Pkt Len Max",),
    "Bwd Packet Length Min": ("Bwd Pkt Len Min",),
    "Bwd Packet Length Mean": ("Bwd Pkt Len Mean",),
    "Flow Bytes/s": ("Flow Byts/s",),
    "Flow IAT Min": ("Flow IAT Min",),
    "Bwd IAT Total": ("Bwd IAT Tot",),
    "Fwd PSH Flags": ("Fwd PSH Flags",),
    "Fwd Header Length": ("Fwd Header Len",),
    "Bwd Packets/s": ("Bwd Pkts/s",),
    "Packet Length Variance": ("Pkt Len Var",),
    "SYN Flag Count": ("SYN Flag Cnt",),
    "RST Flag Count": ("RST Flag Cnt",),
    "ACK Flag Count": ("ACK Flag Cnt",),
    "URG Flag Count": ("URG Flag Cnt",),
    "CWE Flag Count": ("CWE Flag Count", "CWR Flag Count", "CWR Flag Cnt"),
    "Down/Up Ratio": ("Down/Up Ratio",),
    "Init Fwd Win Bytes": ("Init Fwd Win Byts", "Init_Win_bytes_forward"),
    "Init Bwd Win Bytes": ("Init Bwd Win Byts", "Init_Win_bytes_backward"),
    "Fwd Act Data Packets": ("Fwd Act Data Pkts", "act_data_pkt_fwd"),
    "Fwd Seg Size Min": ("Fwd Seg Size Min", "min_seg_size_forward"),
    "Active Mean": ("Active Mean",),
    "Active Std": ("Active Std",),
}


def _colonne_pour(feature: str, colonnes: dict[str, str]) -> str | None:
    """Retrouve la colonne du CSV correspondant a une caracteristique du modele."""
    for candidat in (feature, *ALIAS_COLONNES.get(feature, ())):
        trouve = colonnes.get(_normaliser(candidat))
        if trouve:
            return trouve
    return None


# ── Lecture d'un PCAP ─────────────────────────────────────────────────────────


def _lire_pcap(chemin: Path) -> tuple[list[dict[str, Any]], int]:
    """Relit un PCAP avec tshark et retourne (flux agreges, nombre de paquets)."""
    commande = ["tshark", "-r", str(chemin), "-n", "-T", "fields", "-E", "separator=\t"]
    for champ in TSHARK_FIELDS:
        commande += ["-e", champ]

    try:
        resultat = subprocess.run(  # noqa: S603 — commande construite en dur
            commande, capture_output=True, text=True, timeout=TSHARK_TIMEOUT, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise AnalyseError("Fichier trop volumineux : la lecture a depasse 5 minutes.") from exc
    except FileNotFoundError as exc:
        raise AnalyseError("tshark n'est pas disponible dans ce conteneur.") from exc

    if resultat.returncode != 0 and not resultat.stdout:
        detail = (resultat.stderr or "").strip()[:200]
        raise AnalyseError(f"Fichier illisible par tshark : {detail or 'format non reconnu'}")

    def entier(valeur: str, defaut: int = 0) -> int:
        try:
            return int(valeur.split(",")[0], 16) if valeur.startswith("0x") else int(float(valeur))
        except (ValueError, TypeError):
            return defaut

    paquets: list[_RawPacket] = []
    total_lignes = 0
    for ligne in resultat.stdout.splitlines():
        total_lignes += 1
        parts = ligne.split("\t")
        if len(parts) < len(TSHARK_FIELDS):
            parts += [""] * (len(TSHARK_FIELDS) - len(parts))

        # Comme pour l'agent : tshark peut renvoyer plusieurs adresses quand un
        # paquet contient des en-tetes imbriques ; seule la premiere compte.
        src = parts[2].split(",")[0].strip()
        dst = parts[3].split(",")[0].strip()
        if not src or not dst:
            continue

        paquets.append(
            _RawPacket(
                ts=float(parts[0] or 0.0),
                length=entier(parts[1]),
                src_ip=src,
                dst_ip=dst,
                proto=entier(parts[4]),
                src_port=entier(parts[5]) or entier(parts[7]),
                dst_port=entier(parts[6]) or entier(parts[8]),
                tcp_flags=entier(parts[9]),
                tcp_hdr_len=entier(parts[10]),
                win=entier(parts[11]),
            )
        )

    if not paquets:
        raise AnalyseError("Aucun paquet IP exploitable dans ce fichier.")

    return _aggregate_flows(paquets), total_lignes


# ── Lecture d'un CSV CICFlowMeter ─────────────────────────────────────────────


def _lire_csv(chemin: Path) -> tuple[list[list[float]], list[dict[str, Any]], list[str]]:
    """Lit un CSV CICFlowMeter et retourne (vecteurs, metadonnees, colonnes manquantes)."""
    import pandas as pd

    try:
        tableau = pd.read_csv(chemin, low_memory=False)
    except Exception as exc:  # noqa: BLE001 — message lisible pour l'utilisateur
        raise AnalyseError(f"CSV illisible : {exc}") from exc

    if tableau.empty:
        raise AnalyseError("Le fichier CSV ne contient aucune ligne.")

    # Index insensible a la casse et aux separateurs
    colonnes = {_normaliser(str(c)): str(c) for c in tableau.columns}

    correspondances: dict[str, str] = {}
    manquantes: list[str] = []
    for feature in FEATURE_NAMES:
        colonne = _colonne_pour(feature, colonnes)
        if colonne:
            correspondances[feature] = colonne
        else:
            manquantes.append(feature)

    if len(manquantes) == len(FEATURE_NAMES):
        # Aucune colonne reconnue : le fichier n'est probablement pas un tableau
        # de flux (rapport texte, journal, notes...). Le dire explicitement evite
        # de laisser croire a un CSV mal forme.
        raise AnalyseError(
            "Aucune caracteristique CICFlowMeter n'a ete trouvee. Ce fichier ne "
            "semble pas etre un tableau de flux : attendez-vous a un CSV produit "
            "par CICFlowMeter (une ligne par flux), ou deposez directement le PCAP."
        )

    if len(manquantes) > len(FEATURE_NAMES) // 2:
        raise AnalyseError(
            f"Ce CSV ne ressemble pas a une sortie CICFlowMeter : "
            f"{len(manquantes)} des {len(FEATURE_NAMES)} caracteristiques sont absentes."
        )

    # Les caracteristiques absentes sont mises a zero, comme le ferait
    # CICFlowMeter pour un compteur jamais incremente.
    donnees = pd.DataFrame(index=tableau.index)
    for feature in FEATURE_NAMES:
        colonne = correspondances.get(feature)
        serie = tableau[colonne] if colonne else 0
        donnees[feature] = pd.to_numeric(serie, errors="coerce")

    donnees = donnees.replace([float("inf"), float("-inf")], 0.0).fillna(0.0)
    vecteurs = donnees.to_numpy(dtype=float).tolist()

    # Colonnes d'identification, si le CSV les fournit
    def valeur(ligne_index: int, *noms: str) -> Any:
        """Lit une colonne optionnelle et la ramene a un type JSON serialisable.

        pandas renvoie des scalaires numpy (`int64`, `float64`) que FastAPI ne
        sait pas encoder : on les convertit systematiquement.
        """
        for nom in noms:
            colonne = colonnes.get(_normaliser(nom))
            if not colonne:
                continue
            brut = tableau.iloc[ligne_index][colonne]
            if brut is None or (isinstance(brut, float) and brut != brut):  # NaN
                return None
            if hasattr(brut, "item"):  # scalaire numpy
                return brut.item()
            return brut
        return None

    metadonnees = [
        {
            "src_ip": str(valeur(i, "Src IP", "Source IP", "src_ip") or ""),
            "dst_ip": str(valeur(i, "Dst IP", "Destination IP", "dst_ip") or ""),
            "dst_port": valeur(i, "Dst Port", "Destination Port", "dst_port"),
            "label": valeur(i, "Label"),
        }
        for i in range(len(tableau))
    ]
    return vecteurs, metadonnees, manquantes


# ── Point d'entree ────────────────────────────────────────────────────────────


# Le dataset CICDDoS2019 etiquette ses classes « DrDoS_DNS », « UDP-lag »,
# « DrDoS_NTP »… alors que l'encodeur du modele apprend « DNS », « UDPLag »,
# « NTP ». Sans cette normalisation, une prediction correcte serait comptee
# comme fausse et l'exactitude rapportee s'effondrerait a tort.
PREFIXES_ETIQUETTE = ("DRDOS_", "DRDOS-", "DRDOS")


def _cle_classe(etiquette: str) -> str:
    """Ramene une etiquette a une forme comparable (casse, prefixe, separateurs)."""
    cle = re.sub(r"[^A-Za-z0-9]", "", str(etiquette)).upper()
    for prefixe in PREFIXES_ETIQUETTE:
        sans_separateur = prefixe.replace("_", "").replace("-", "")
        if cle.startswith(sans_separateur) and cle != sans_separateur:
            return cle[len(sans_separateur) :]
    return cle


def _meme_classe(reelle: str, predite: str) -> bool:
    """Vrai si l'etiquette du fichier et la prediction designent la meme classe."""
    return _cle_classe(reelle) == _cle_classe(predite)


def analyser_fichier(nom: str, contenu: bytes) -> dict[str, Any]:
    """Analyse un fichier deposé et retourne la synthese des predictions."""
    if not predictor.is_ready:
        raise AnalyseError("Aucun modele n'est charge : analyse impossible.")

    if len(contenu) > TAILLE_MAX_OCTETS:
        raise AnalyseError(
            f"Fichier trop volumineux ({len(contenu) / 1024 / 1024:.0f} Mo). "
            f"Limite : {TAILLE_MAX_OCTETS // 1024 // 1024} Mo."
        )

    extension = Path(nom).suffix.lower()
    if extension not in EXTENSIONS_PCAP | EXTENSIONS_CSV:
        raise AnalyseError(
            f"Extension « {extension or 'inconnue'} » non geree. "
            f"Formats acceptes : {', '.join(sorted(EXTENSIONS_PCAP | EXTENSIONS_CSV))}"
        )

    with tempfile.NamedTemporaryFile(suffix=extension, delete=True) as fichier:
        fichier.write(contenu)
        fichier.flush()
        chemin = Path(fichier.name)

        manquantes: list[str] = []
        if extension in EXTENSIONS_PCAP:
            flux_bruts, nb_paquets = _lire_pcap(chemin)
            vecteurs = [raw_vector_from_flow(Flow(**f)) for f in flux_bruts]
            metadonnees = [
                {
                    "src_ip": f["src_ip"],
                    "dst_ip": f["dst_ip"],
                    "dst_port": f.get("dst_port"),
                    "label": None,
                }
                for f in flux_bruts
            ]
            format_detecte = "pcap"
        else:
            vecteurs, metadonnees, manquantes = _lire_csv(chemin)
            nb_paquets = 0
            format_detecte = "csv"

    if not vecteurs:
        raise AnalyseError("Aucun flux exploitable n'a pu etre extrait.")

    resultats = predictor.predict_batch(vecteurs)

    # ── Synthese ──────────────────────────────────────────────────────────────
    par_classe = Counter(r.label for r in resultats)
    confiance_par_classe: dict[str, list[float]] = {}
    for r in resultats:
        confiance_par_classe.setdefault(r.label, []).append(r.confidence)

    # Le pipeline temps reel ne retient une attaque que si la confiance depasse
    # le seuil configure. L'analyse de fichier doit appliquer le meme critere,
    # sinon un meme trafic afficherait ici des attaques que la surveillance
    # ignore. On expose aussi le comptage sans seuil, pour ne rien masquer.
    seuil = get_runtime_settings().confidence_threshold * 100
    attaques = [r for r in resultats if r.is_attack and r.confidence >= seuil]
    attaques_sans_seuil = [r for r in resultats if r.is_attack]
    sources_malveillantes = Counter(
        m["src_ip"] for m, r in zip(metadonnees, resultats, strict=True) if r.is_attack and m["src_ip"]
    )
    cibles = Counter(
        m["dst_ip"] for m, r in zip(metadonnees, resultats, strict=True) if r.is_attack and m["dst_ip"]
    )

    # Si le fichier porte une colonne Label, on peut confronter la verite terrain
    verite_terrain = None
    if any(m.get("label") for m in metadonnees):
        # Comptage par classe reelle : le pourcentage global seul est trompeur
        # des que les classes sont desequilibrees, ce qui est la norme ici.
        total_par_classe: Counter[str] = Counter()
        justes_par_classe: Counter[str] = Counter()
        for m, r in zip(metadonnees, resultats, strict=True):
            reelle = str(m["label"]).strip()
            total_par_classe[reelle] += 1
            if _meme_classe(reelle, r.label):
                justes_par_classe[reelle] += 1

        justes = sum(justes_par_classe.values())
        verite_terrain = {
            "disponible": True,
            "exactitude": round(justes / len(resultats) * 100, 2),
            "corrects": justes,
            "total": len(resultats),
            "par_classe": [
                {
                    "label": nom,
                    "total": nombre,
                    "corrects": justes_par_classe[nom],
                    "exactitude": round(justes_par_classe[nom] / nombre * 100, 2),
                }
                for nom, nombre in total_par_classe.most_common()
            ],
        }

    echantillon = [
        {
            "src_ip": m["src_ip"],
            "dst_ip": m["dst_ip"],
            "dst_port": m["dst_port"],
            "prediction": r.label,
            "confidence": r.confidence,
            "is_attack": r.is_attack,
            "label": str(m["label"]) if m.get("label") is not None else None,
        }
        for m, r in list(zip(metadonnees, resultats, strict=True))[:100]
    ]

    return {
        "filename": nom,
        "format": format_detecte,
        "packets_read": nb_paquets,
        "flows_analyzed": len(resultats),
        "attacks_detected": len(attaques),
        "attack_ratio": round(len(attaques) / len(resultats) * 100, 2),
        "confidence_threshold": round(seuil, 2),
        "attacks_below_threshold": len(attaques_sans_seuil) - len(attaques),
        "missing_features": manquantes,
        "distribution": [
            {
                "name": nom_classe,
                "count": nombre,
                "share": round(nombre / len(resultats) * 100, 2),
                "avg_confidence": round(
                    sum(confiance_par_classe[nom_classe]) / len(confiance_par_classe[nom_classe]), 2
                ),
                "is_attack": nom_classe != "BENIGN",
            }
            for nom_classe, nombre in par_classe.most_common()
            if nom_classe in CLASS_NAMES or True
        ],
        "top_sources": [{"ip": ip, "flows": n} for ip, n in sources_malveillantes.most_common(10)],
        "top_targets": [{"ip": ip, "flows": n} for ip, n in cibles.most_common(10)],
        "ground_truth": verite_terrain,
        "sample": echantillon,
    }
