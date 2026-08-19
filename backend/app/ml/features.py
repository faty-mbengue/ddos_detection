"""Definition du vecteur d'entree du modele de detection.

Les noms et l'ordre des caracteristiques reprennent exactement ceux du notebook
d'entrainement (CICDDoS2019, `train_df.drop('Label', axis=1).columns`).

IMPORTANT — ou se fait la normalisation
---------------------------------------
Le vecteur transmis au modele contient les valeurs **brutes** de CICFlowMeter
(microsecondes, octets, compteurs de paquets…). C'est le `MinMaxScaler`
sauvegarde a l'entrainement qui les ramene dans [0, 1], car lui seul connait les
bornes reelles du jeu d'entrainement (par exemple `Protocol` va de 6 a 17, et
non de 0 a 17). Normaliser en amont produirait une double mise a l'echelle et
donc des predictions fausses.

`FEATURE_MAX` ci-dessous ne sert donc qu'a deux choses :
  - de repli lorsque aucun scaler n'accompagne le modele ;
  - au simulateur de trafic, pour convertir un profil normalise en valeurs brutes.

Le mapping `FLOW_FIELD_BY_FEATURE` relie chaque caracteristique du modele a la
colonne correspondante de la table `flows` (nomenclature CICFlowMeter), ce qui
permet de construire le vecteur d'entree directement depuis un flux stocke.
"""

# ── Les 12 classes du dataset CICDDoS2019 (indices 0 a 11) ───────────────────
CLASS_NAMES: list[str] = [
    "BENIGN",
    "DNS",
    "LDAP",
    "MSSQL",
    "NTP",
    "NetBIOS",
    "SNMP",
    "SSDP",
    "Syn",
    "TFTP",
    "UDP",
    "UDPLag",
]

BENIGN_CLASS = "BENIGN"
ATTACK_CLASSES: list[str] = [c for c in CLASS_NAMES if c != BENIGN_CLASS]

# ── Caracteristiques retenues par la selection (Random Forest / SelectKBest) ──
FEATURE_NAMES: list[str] = [
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packets Length Total",
    "Fwd Packet Length Max",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Fwd Header Length",
    "Bwd Packets/s",
    "Packet Length Variance",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "Down/Up Ratio",
    "Init Fwd Win Bytes",
    "Init Bwd Win Bytes",
    "Fwd Act Data Packets",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
]

N_FEATURES = len(FEATURE_NAMES)

# ── Correspondance modele -> colonne de la table flows (CICFlowMeter) ─────────
FLOW_FIELD_BY_FEATURE: dict[str, str] = {
    "Protocol": "protocol",
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "tot_fwd_pkts",
    "Total Backward Packets": "tot_bwd_pkts",
    "Fwd Packets Length Total": "totlen_fwd_pkts",
    "Fwd Packet Length Max": "fwd_pkt_len_max",
    "Fwd Packet Length Std": "fwd_pkt_len_std",
    "Bwd Packet Length Max": "bwd_pkt_len_max",
    "Bwd Packet Length Min": "bwd_pkt_len_min",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Flow Bytes/s": "flow_byts_s",
    "Flow IAT Min": "flow_iat_min",
    "Bwd IAT Total": "bwd_iat_tot",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Min": "bwd_iat_min",
    "Fwd PSH Flags": "fwd_psh_flags",
    "Fwd Header Length": "fwd_header_len",
    "Bwd Packets/s": "bwd_pkts_s",
    "Packet Length Variance": "pkt_len_var",
    "SYN Flag Count": "syn_flag_cnt",
    "RST Flag Count": "rst_flag_cnt",
    "ACK Flag Count": "ack_flag_cnt",
    "URG Flag Count": "urg_flag_cnt",
    "CWE Flag Count": "cwr_flag_count",
    "Down/Up Ratio": "down_up_ratio",
    "Init Fwd Win Bytes": "init_fwd_win_byts",
    "Init Bwd Win Bytes": "init_bwd_win_byts",
    "Fwd Act Data Packets": "fwd_act_data_pkts",
    "Fwd Seg Size Min": "fwd_seg_size_min",
    "Active Mean": "active_mean",
    "Active Std": "active_std",
}

# Bornes approximatives des valeurs brutes CICFlowMeter, utilisees uniquement
# comme repli (aucun scaler fourni) et par le simulateur de trafic.
# Le scaler du modele, lorsqu'il existe, remplace ces bornes par les vraies.
FEATURE_MAX: dict[str, float] = {
    "Protocol": 17.0,
    "Flow Duration": 120_000_000.0,
    "Total Fwd Packets": 10_000.0,
    "Total Backward Packets": 10_000.0,
    "Fwd Packets Length Total": 5_000_000.0,
    "Fwd Packet Length Max": 65_535.0,
    "Fwd Packet Length Std": 5_000.0,
    "Bwd Packet Length Max": 65_535.0,
    "Bwd Packet Length Min": 65_535.0,
    "Bwd Packet Length Mean": 65_535.0,
    "Flow Bytes/s": 1_000_000_000.0,
    "Flow IAT Min": 120_000_000.0,
    "Bwd IAT Total": 120_000_000.0,
    "Bwd IAT Mean": 120_000_000.0,
    "Bwd IAT Min": 120_000_000.0,
    "Fwd PSH Flags": 1.0,
    "Fwd Header Length": 100_000.0,
    "Bwd Packets/s": 1_000_000.0,
    "Packet Length Variance": 100_000_000.0,
    "SYN Flag Count": 1.0,
    "RST Flag Count": 1.0,
    "ACK Flag Count": 1.0,
    "URG Flag Count": 1.0,
    "CWE Flag Count": 1.0,
    "Down/Up Ratio": 100.0,
    "Init Fwd Win Bytes": 65_535.0,
    "Init Bwd Win Bytes": 65_535.0,
    "Fwd Act Data Packets": 10_000.0,
    "Fwd Seg Size Min": 60.0,
    "Active Mean": 120_000_000.0,
    "Active Std": 120_000_000.0,
}


def normalize_raw(feature: str, value: float) -> float:
    """Ramene une valeur brute CICFlowMeter dans [0, 1] avec les bornes de repli.

    N'est appele que si le modele charge n'a pas de scaler associe.
    """
    upper = FEATURE_MAX.get(feature, 1.0) or 1.0
    if value <= 0:
        return 0.0
    return min(value / upper, 1.0)


def raw_vector_from_flow(flow: object) -> list[float]:
    """Extrait les 31 caracteristiques **brutes** d'un objet Flow, dans l'ordre du modele.

    Aucune normalisation n'est appliquee ici : c'est le scaler du modele qui s'en
    charge (voir le module `app.services.ml`).
    """
    vector: list[float] = []
    for feature in FEATURE_NAMES:
        raw = getattr(flow, FLOW_FIELD_BY_FEATURE[feature], 0) or 0
        vector.append(float(raw))
    return vector


def normalized_vector_from_flow(flow: object) -> list[float]:
    """Variante normalisee avec les bornes de repli, pour inspection ou debogage.

    Utilisee par l'endpoint de detail d'un flux afin de montrer a quoi ressemble
    le vecteur une fois mis a l'echelle, sans dependre du scaler charge.
    """
    return [
        normalize_raw(feature, float(getattr(flow, FLOW_FIELD_BY_FEATURE[feature], 0) or 0))
        for feature in FEATURE_NAMES
    ]
