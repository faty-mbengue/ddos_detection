"""Generation d'un modele Random Forest de demonstration.

Ce script n'est PAS le modele du memoire : il sert de repli pour que la
plateforme soit fonctionnelle de bout en bout lorsque les artefacts issus du
notebook CICDDoS2019 ne sont pas fournis.

Pour deployer le vrai modele, deposer dans `app/ml/artifacts/` :
    model.joblib, scaler.joblib (optionnel), metadata.json
puis redemarrer le backend (ou appeler POST /api/model/reload).

Les donnees synthetiques reproduisent les signatures caracteristiques de chaque
classe dans l'espace normalise [0, 1] des 31 caracteristiques selectionnees.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

from app.ml.features import CLASS_NAMES, FEATURE_MAX, FEATURE_NAMES, N_FEATURES

TCP = 6 / 17.0  # protocole normalise (Protocol / 17)
UDP = 17 / 17.0

# Profil par classe : {caracteristique: (moyenne, ecart-type)} en espace normalise.
# Les caracteristiques non citees suivent un bruit faible autour de 0.
CLASS_PROFILES: dict[str, dict[str, tuple[float, float]]] = {
    "BENIGN": {
        "Protocol": (TCP, 0.10),
        "Flow Duration": (0.35, 0.20),
        "Total Fwd Packets": (0.004, 0.003),
        "Total Backward Packets": (0.003, 0.002),
        "Fwd Packets Length Total": (0.010, 0.008),
        "Fwd Packet Length Max": (0.020, 0.010),
        "Fwd Packet Length Std": (0.060, 0.030),
        "Bwd Packet Length Max": (0.022, 0.012),
        "Bwd Packet Length Mean": (0.010, 0.006),
        "Flow Bytes/s": (0.0004, 0.0003),
        "Bwd Packets/s": (0.002, 0.002),
        "Packet Length Variance": (0.004, 0.003),
        "ACK Flag Count": (0.90, 0.15),
        "Fwd PSH Flags": (0.55, 0.30),
        "Down/Up Ratio": (0.012, 0.008),
        "Init Fwd Win Bytes": (0.45, 0.20),
        "Init Bwd Win Bytes": (0.35, 0.20),
        "Fwd Header Length": (0.010, 0.006),
        "Fwd Act Data Packets": (0.003, 0.002),
        "Fwd Seg Size Min": (0.55, 0.10),
        "Active Mean": (0.20, 0.15),
        "Active Std": (0.10, 0.08),
        "Bwd IAT Total": (0.15, 0.12),
        "Bwd IAT Mean": (0.05, 0.04),
        "Flow IAT Min": (0.010, 0.008),
    },
    # ── Attaques par reflexion / amplification UDP ────────────────────────────
    "DNS": {
        "Protocol": (UDP, 0.02),
        "Flow Duration": (0.006, 0.005),
        "Total Fwd Packets": (0.0009, 0.0004),
        "Fwd Packets Length Total": (0.0006, 0.0004),
        "Fwd Packet Length Max": (0.008, 0.003),
        "Flow Bytes/s": (0.0090, 0.0040),
        "Fwd Header Length": (0.0004, 0.0002),
        "Fwd Act Data Packets": (0.0008, 0.0004),
        "Fwd Seg Size Min": (0.13, 0.02),
        "Packet Length Variance": (0.0004, 0.0003),
    },
    "LDAP": {
        "Protocol": (UDP, 0.02),
        "Flow Duration": (0.004, 0.003),
        "Total Fwd Packets": (0.0007, 0.0004),
        "Fwd Packets Length Total": (0.0022, 0.0010),
        "Fwd Packet Length Max": (0.030, 0.008),
        "Flow Bytes/s": (0.0300, 0.0120),
        "Fwd Header Length": (0.0003, 0.0002),
        "Fwd Act Data Packets": (0.0007, 0.0004),
        "Fwd Seg Size Min": (0.13, 0.02),
        "Packet Length Variance": (0.0020, 0.0010),
    },
    "MSSQL": {
        "Protocol": (UDP, 0.02),
        "Flow Duration": (0.009, 0.006),
        "Total Fwd Packets": (0.0012, 0.0006),
        "Fwd Packets Length Total": (0.0016, 0.0008),
        "Fwd Packet Length Max": (0.016, 0.005),
        "Flow Bytes/s": (0.0140, 0.0060),
        "Fwd Header Length": (0.0006, 0.0003),
        "Fwd Act Data Packets": (0.0012, 0.0006),
        "Fwd Seg Size Min": (0.13, 0.02),
        "Down/Up Ratio": (0.004, 0.003),
    },
    "NTP": {
        "Protocol": (UDP, 0.02),
        "Flow Duration": (0.120, 0.070),
        "Total Fwd Packets": (0.0040, 0.0020),
        "Total Backward Packets": (0.0010, 0.0008),
        "Fwd Packets Length Total": (0.0030, 0.0015),
        "Fwd Packet Length Max": (0.007, 0.002),
        "Flow Bytes/s": (0.0020, 0.0010),
        "Bwd IAT Total": (0.090, 0.050),
        "Bwd IAT Mean": (0.030, 0.020),
        "Bwd Packets/s": (0.0008, 0.0005),
        "Fwd Seg Size Min": (0.13, 0.02),
        "Active Mean": (0.060, 0.040),
    },
    "NetBIOS": {
        "Protocol": (UDP, 0.02),
        "Flow Duration": (0.003, 0.002),
        "Total Fwd Packets": (0.0006, 0.0003),
        "Fwd Packets Length Total": (0.0005, 0.0003),
        "Fwd Packet Length Max": (0.007, 0.002),
        "Flow Bytes/s": (0.0180, 0.0080),
        "Fwd Header Length": (0.0003, 0.0002),
        "Fwd Act Data Packets": (0.0006, 0.0003),
        "Fwd Seg Size Min": (0.13, 0.02),
    },
    "SNMP": {
        "Protocol": (UDP, 0.02),
        "Flow Duration": (0.005, 0.004),
        "Total Fwd Packets": (0.0009, 0.0005),
        "Fwd Packets Length Total": (0.0040, 0.0020),
        "Fwd Packet Length Max": (0.045, 0.012),
        "Flow Bytes/s": (0.0420, 0.0180),
        "Fwd Header Length": (0.0004, 0.0002),
        "Fwd Act Data Packets": (0.0009, 0.0005),
        "Fwd Seg Size Min": (0.13, 0.02),
        "Packet Length Variance": (0.0035, 0.0018),
    },
    "SSDP": {
        "Protocol": (UDP, 0.02),
        "Flow Duration": (0.030, 0.020),
        "Total Fwd Packets": (0.0022, 0.0012),
        "Fwd Packets Length Total": (0.0060, 0.0030),
        "Fwd Packet Length Max": (0.035, 0.010),
        "Flow Bytes/s": (0.0090, 0.0045),
        "Fwd Header Length": (0.0011, 0.0006),
        "Fwd Act Data Packets": (0.0022, 0.0012),
        "Fwd Seg Size Min": (0.13, 0.02),
        "Active Mean": (0.020, 0.015),
    },
    "TFTP": {
        "Protocol": (UDP, 0.02),
        "Flow Duration": (0.075, 0.045),
        "Total Fwd Packets": (0.00007, 0.00004),
        "Fwd Packets Length Total": (0.00040, 0.00025),
        "Fwd Packet Length Max": (0.021, 0.006),
        "Flow Bytes/s": (0.00016, 0.00010),
        "Fwd Header Length": (0.00140, 0.00080),
        "Fwd Act Data Packets": (0.00170, 0.00090),
        "Fwd Seg Size Min": (0.00, 0.01),
        "Flow IAT Min": (0.00002, 0.00002),
    },
    "UDP": {
        "Protocol": (UDP, 0.02),
        "Flow Duration": (0.002, 0.002),
        "Total Fwd Packets": (0.0005, 0.0003),
        "Fwd Packets Length Total": (0.0026, 0.0013),
        "Fwd Packet Length Max": (0.055, 0.015),
        "Flow Bytes/s": (0.0600, 0.0250),
        "Fwd Header Length": (0.0002, 0.0001),
        "Fwd Act Data Packets": (0.0005, 0.0003),
        "Fwd Seg Size Min": (0.13, 0.02),
        "Packet Length Variance": (0.0050, 0.0025),
    },
    "UDPLag": {
        "Protocol": (UDP, 0.15),
        "Flow Duration": (0.045, 0.030),
        "Total Fwd Packets": (0.0016, 0.0009),
        "Total Backward Packets": (0.0004, 0.0003),
        "Fwd Packets Length Total": (0.0013, 0.0007),
        "Fwd Packet Length Max": (0.012, 0.004),
        "Flow Bytes/s": (0.0016, 0.0009),
        "Bwd Packets/s": (0.0004, 0.0003),
        "Fwd Seg Size Min": (0.13, 0.03),
        "Down/Up Ratio": (0.003, 0.002),
        "Active Mean": (0.030, 0.020),
    },
    # ── Attaque TCP ───────────────────────────────────────────────────────────
    "Syn": {
        "Protocol": (TCP, 0.02),
        "Flow Duration": (0.0009, 0.0007),
        "Total Fwd Packets": (0.0003, 0.0002),
        "Fwd Packets Length Total": (0.0, 0.0001),
        "Fwd Packet Length Max": (0.0, 0.0001),
        "SYN Flag Count": (0.97, 0.05),
        "ACK Flag Count": (0.03, 0.05),
        "RST Flag Count": (0.10, 0.12),
        "Init Fwd Win Bytes": (0.13, 0.06),
        "Init Bwd Win Bytes": (0.0, 0.002),
        "Fwd Header Length": (0.0006, 0.0003),
        "Fwd Seg Size Min": (0.33, 0.02),
        "Flow Bytes/s": (0.0, 0.0002),
    },
}


def _generate(n_per_class: int, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Genere un jeu synthetique de valeurs **brutes** CICFlowMeter et ses etiquettes.

    Les profils de classe sont definis dans l'espace normalise (plus lisible),
    puis convertis a l'echelle brute via `FEATURE_MAX` : le modele de
    demonstration suit ainsi exactement la meme chaine que le modele reel
    (valeurs brutes -> MinMaxScaler -> foret aleatoire).
    """
    rng = np.random.default_rng(seed)
    features_index = {name: i for i, name in enumerate(FEATURE_NAMES)}
    echelle = np.array([FEATURE_MAX[name] for name in FEATURE_NAMES], dtype=np.float64)

    x_parts: list[np.ndarray] = []
    y_parts: list[np.ndarray] = []

    for class_index, class_name in enumerate(CLASS_NAMES):
        profile = CLASS_PROFILES[class_name]
        block = np.abs(rng.normal(0.0, 0.0025, size=(n_per_class, N_FEATURES)))
        for feature, (mean, std) in profile.items():
            col = features_index[feature]
            block[:, col] = rng.normal(mean, std, size=n_per_class)
        x_parts.append(np.clip(block, 0.0, 1.0) * echelle)  # -> valeurs brutes
        y_parts.append(np.full(n_per_class, class_index, dtype=np.int64))

    return np.vstack(x_parts), np.concatenate(y_parts)


def bootstrap_demo_model(model_dir: Path, n_per_class: int = 1200, seed: int = 42) -> dict:
    """Entraine et sauvegarde le modele de demonstration. Retourne ses metriques.

    Produit trois artefacts dans `model_dir` :
      - `model.joblib`   : la foret aleatoire ;
      - `scaler.joblib`  : le MinMaxScaler ajuste sur les valeurs brutes ;
      - `metadata.json`  : metriques d'evaluation et provenance.
    """
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import (
        accuracy_score,
        classification_report,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
    )
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import MinMaxScaler

    model_dir = Path(model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)

    x_brut, y = _generate(n_per_class, seed)

    # Le scaler fait partie du modele : ajuste ici, applique a l'inference.
    scaler = MinMaxScaler().fit(x_brut)
    x = scaler.transform(x_brut)

    # Decoupage 70 / 10 / 20 (entrainement / validation / test), comme dans le memoire
    x_train, x_tmp, y_train, y_tmp = train_test_split(
        x, y, test_size=0.30, random_state=seed, stratify=y
    )
    x_val, x_test, y_val, y_test = train_test_split(
        x_tmp, y_tmp, test_size=2 / 3, random_state=seed, stratify=y_tmp
    )

    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=22,
        min_samples_leaf=1,
        n_jobs=-1,
        random_state=seed,
        class_weight="balanced",
    )
    model.fit(x_train, y_train)

    y_pred = model.predict(x_test)
    report = classification_report(
        y_test, y_pred, target_names=CLASS_NAMES, output_dict=True, zero_division=0
    )

    importances = dict(
        sorted(
            zip(FEATURE_NAMES, (float(v) for v in model.feature_importances_), strict=True),
            key=lambda kv: kv[1],
            reverse=True,
        )
    )

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision_macro": float(precision_score(y_test, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "val_accuracy": float(model.score(x_val, y_val)),
        "per_class": {
            name: {
                "precision": float(report[name]["precision"]),
                "recall": float(report[name]["recall"]),
                "f1": float(report[name]["f1-score"]),
                "support": int(report[name]["support"]),
            }
            for name in CLASS_NAMES
        },
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "feature_importances": importances,
        "n_train": int(len(y_train)),
        "n_val": int(len(y_val)),
        "n_test": int(len(y_test)),
    }

    metadata = {
        # `model_file` lie ces metriques a un artefact precis : le backend refuse
        # d'afficher les metriques du modele de demonstration a cote d'un autre modele.
        "model_file": "model.joblib",
        "classes": CLASS_NAMES,
        "features": FEATURE_NAMES,
        "dataset": "Synthetique (signatures CICDDoS2019)",
        "algorithm": "RandomForestClassifier",
        "hyperparameters": {"n_estimators": 150, "max_depth": 22, "class_weight": "balanced"},
        "trained_at": datetime.now(UTC).isoformat(),
        "is_demo": True,
        "metrics": metrics,
    }

    joblib.dump(model, model_dir / "model.joblib", compress=3)
    joblib.dump(scaler, model_dir / "scaler.joblib")
    (model_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return metrics


if __name__ == "__main__":
    from app.core.config import settings

    result = bootstrap_demo_model(settings.MODEL_DIR)
    print(f"Modele de demonstration entraine — accuracy {result['accuracy']:.4f}")
    print(f"  F1-macro   : {result['f1_macro']:.4f}")
    print(f"  Artefacts  : {settings.MODEL_DIR}")
