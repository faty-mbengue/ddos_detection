"""Tests du moteur de detection (vecteur d'entree, modele, agregation des flux).

Ces tests ne touchent pas a la base de donnees : ils couvrent la partie du
systeme qui doit rester juste independamment de l'infrastructure.

    uv run pytest
"""

from __future__ import annotations

import random

import pytest

from app.ml.features import (
    ATTACK_CLASSES,
    CLASS_NAMES,
    FEATURE_NAMES,
    FLOW_FIELD_BY_FEATURE,
    N_FEATURES,
    normalize_raw,
    raw_vector_from_flow,
)
from app.models import Flow
from app.services.capture import synthesize_flow
from app.services.ml import predictor

# ── Definition du vecteur d'entree ───────────────────────────────────────────


def test_le_vecteur_compte_31_caracteristiques():
    assert N_FEATURES == 31
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES)), "noms dupliques"


def test_les_12_classes_du_dataset():
    assert len(CLASS_NAMES) == 12
    assert CLASS_NAMES[0] == "BENIGN"
    assert len(ATTACK_CLASSES) == 11
    assert "BENIGN" not in ATTACK_CLASSES


def test_chaque_caracteristique_est_reliee_a_une_colonne_de_flows():
    colonnes = {c.name for c in Flow.__table__.columns}
    for feature in FEATURE_NAMES:
        colonne = FLOW_FIELD_BY_FEATURE.get(feature)
        assert colonne is not None, f"{feature} n'est pas mappee"
        assert colonne in colonnes, f"{colonne} absente de la table flows"


@pytest.mark.parametrize(
    ("valeur", "attendu"),
    [(-5.0, 0.0), (0.0, 0.0), (17.0, 1.0), (1_000.0, 1.0)],
)
def test_la_normalisation_reste_dans_zero_un(valeur: float, attendu: float):
    assert normalize_raw("Protocol", valeur) == attendu


def test_le_vecteur_issu_d_un_flux_est_brut_et_complet():
    """Le vecteur transmis au modele porte les valeurs brutes, pas normalisees."""
    flow = Flow(**synthesize_flow("Syn", random.Random(1), "1.2.3.4", "10.0.0.1"))
    vecteur = raw_vector_from_flow(flow)

    assert len(vecteur) == N_FEATURES
    assert all(v >= 0.0 for v in vecteur)
    # Protocol vaut 6 (TCP) en brut : une valeur normalisee serait <= 1
    assert vecteur[FEATURE_NAMES.index("Protocol")] == 6.0


# ── Inference ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def modele():
    """Charge le modele, en l'entrainant si aucun artefact n'est present."""
    from app.services.ml import load_or_bootstrap

    load_or_bootstrap()
    assert predictor.is_ready
    return predictor


def test_la_10eme_ligne_du_notebook_est_classee_tftp(modele):
    """Vecteur de reference du notebook (deja normalise, reel : TFTP).

    Ces valeurs sortent du notebook *apres* passage du MinMaxScaler : on les
    soumet donc avec `already_scaled=True` pour court-circuiter le scaler.
    """
    vecteur = [0.0] * N_FEATURES
    valeurs = {
        "Protocol": 1.0,
        "Flow Duration": 0.07498149,
        "Total Fwd Packets": 0.00006990,
        "Fwd Packets Length Total": 0.00039151,
        "Fwd Packet Length Max": 0.02073969,
        "Flow Bytes/s": 0.00000016,
        "Flow IAT Min": 0.00000002,
        "Fwd Header Length": 0.00136364,
        "Fwd Act Data Packets": 0.00170316,
    }
    for nom, valeur in valeurs.items():
        vecteur[FEATURE_NAMES.index(nom)] = valeur

    resultat = modele.predict_one(vecteur, already_scaled=True)
    assert resultat.label == "TFTP"
    assert resultat.is_attack is True
    assert 0.0 <= resultat.confidence <= 100.0


def test_un_flux_benin_synthetique_est_classe_benign(modele):
    rng = random.Random(99)
    flows = [
        Flow(**synthesize_flow("BENIGN", rng, "192.168.1.50", "192.168.1.10")) for _ in range(20)
    ]
    resultats = modele.predict_batch([raw_vector_from_flow(f) for f in flows])

    benins = sum(1 for r in resultats if not r.is_attack)
    assert benins >= 16, f"seulement {benins}/20 flux benins reconnus"


def test_une_rafale_syn_est_classee_comme_attaque(modele):
    rng = random.Random(7)
    flows = [Flow(**synthesize_flow("Syn", rng, "203.0.113.9", "192.168.1.10")) for _ in range(20)]
    resultats = modele.predict_batch([raw_vector_from_flow(f) for f in flows])

    attaques = sum(1 for r in resultats if r.is_attack)
    assert attaques >= 18, f"seulement {attaques}/20 flux detectes comme attaque"


def test_un_vecteur_de_mauvaise_taille_est_rejete(modele):
    with pytest.raises(ValueError, match="caracteristiques attendues"):
        modele.predict_one([0.5] * 10)


def test_les_probabilites_couvrent_les_classes_du_modele(modele):
    """Les probabilites couvrent toutes les classes et somment a 1.

    Tolerance a 1e-5 : chaque probabilite est arrondie a 6 decimales avant d'etre
    renvoyee, ce qui fait deriver la somme de quelques 1e-7 par classe.
    """
    resultat = modele.predict_one([0.1] * N_FEATURES, already_scaled=True)
    assert resultat.label in CLASS_NAMES
    assert set(resultat.probabilities) <= set(CLASS_NAMES)
    assert pytest.approx(sum(resultat.probabilities.values()), abs=1e-5) == 1.0


# ── Agregation des paquets en flux (CICFlowMeter simplifie) ───────────────────


def test_l_agregation_regroupe_les_paquets_bidirectionnels():
    from app.services.capture import _aggregate_flows, _RawPacket

    def paquet(ts: float, src: str, dst: str, sport: int, dport: int, longueur: int):
        return _RawPacket(
            ts=ts,
            length=longueur,
            src_ip=src,
            dst_ip=dst,
            proto=6,
            src_port=sport,
            dst_port=dport,
            tcp_flags=0x02,  # SYN
            tcp_hdr_len=20,
            win=1024,
        )

    paquets = [
        paquet(1000.0, "10.0.0.1", "10.0.0.2", 5000, 80, 74),
        paquet(1000.5, "10.0.0.2", "10.0.0.1", 80, 5000, 60),  # retour du meme flux
        paquet(1001.0, "10.0.0.1", "10.0.0.2", 5000, 80, 80),
    ]

    flux = _aggregate_flows(paquets)

    assert len(flux) == 1, "les deux sens doivent former un seul flux"
    (f,) = flux
    assert (f["src_ip"], f["dst_ip"]) == ("10.0.0.1", "10.0.0.2")
    assert f["tot_fwd_pkts"] == 2
    assert f["tot_bwd_pkts"] == 1
    assert f["totlen_fwd_pkts"] == 154
    assert f["totlen_bwd_pkts"] == 60
    assert f["syn_flag_cnt"] == 3
    assert f["flow_duration"] == pytest.approx(1_000_000.0)  # 1 s en microsecondes


def test_l_agregation_d_une_liste_vide_ne_produit_rien():
    from app.services.capture import _aggregate_flows

    assert _aggregate_flows([]) == []


# ── Criticite des alertes ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("flux_vers_la_cible", "confiance", "attendu"),
    [
        (150, 95.0, "CRITICAL"),  # bien au-dela du palier critique
        (60, 95.0, "CRITICAL"),   # palier critique exact
        (30, 95.0, "HIGH"),
        (12, 95.0, "MEDIUM"),
        (5, 95.0, "MEDIUM"),      # volume faible mais modele tres sur
        (5, 80.0, "LOW"),
    ],
)
def test_la_criticite_suit_le_volume_subi_par_la_cible(
    flux_vers_la_cible: int, confiance: float, attendu: str
):
    """Le volume compte est celui recu par la cible, toutes sources confondues.

    Une attaque DDoS etant distribuee, juger source par source sous-estimerait
    systematiquement sa gravite.
    """
    from app.services.analysis import _severity_for

    assert _severity_for(flux_vers_la_cible, confiance) == attendu


# ── Regression : blocage automatique et unicite de l'IP ──────────────────────
def test_une_meme_source_bloquee_deux_fois_dans_un_cycle_ne_duplique_pas():
    """Une source alimentant deux groupes d'attaque ne doit etre inscrite qu'une fois.

    Sans le `db.flush()` de `_auto_block`, la premiere insertion restait en
    attente dans la session : le SELECT du second groupe ne la voyait pas et
    PostgreSQL rejetait le cycle entier (UniqueViolation sur ix_blocked_ips_ip_address).
    """
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker

    from app.core.database import Base
    from app.models import BlockedIP
    from app.services.analysis import AnalysisPipeline

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    # Meme configuration qu'en production : sans autoflush, une insertion en
    # attente reste invisible aux SELECT suivants de la meme session.
    db = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()

    pipeline = AnalysisPipeline()
    pipeline._auto_block(db, "203.0.113.9", "NTP")
    pipeline._auto_block(db, "203.0.113.9", "DNS")
    db.commit()

    lignes = db.scalars(select(BlockedIP).where(BlockedIP.ip_address == "203.0.113.9")).all()
    assert len(lignes) == 1
    # Le motif conserve la premiere attaque ayant declenche le blocage.
    assert "NTP" in lignes[0].reason
    db.close()
