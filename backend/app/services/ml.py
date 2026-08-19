"""Moteur de detection : chargement du modele Random Forest et inference.

Chaine d'inference complete, telle que produite par le notebook d'entrainement :

    valeurs brutes CICFlowMeter (31)
        -> MinMaxScaler        (scaler_ddos.pkl)     -> valeurs dans [0, 1]
        -> RandomForestClassifier (meilleur_modele.pkl) -> indice de classe 0-11
        -> LabelEncoder        (label_encoder_ddos.pkl) -> nom de classe

Les artefacts sont cherches dans `MODEL_DIR` sous plusieurs noms possibles, afin
d'accepter aussi bien les fichiers du notebook (`meilleur_modele.pkl`,
`scaler_ddos.pkl`, `label_encoder_ddos.pkl`) que ceux du modele de demonstration
(`model.joblib`, `scaler.joblib`). Si rien n'est trouve,
`load_or_bootstrap()` entraine un modele de demonstration afin que la plateforme
reste fonctionnelle de bout en bout.
"""

from __future__ import annotations

import json
import logging
import threading
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from app.core.config import settings
from app.ml.features import CLASS_NAMES, FEATURE_NAMES, N_FEATURES, normalize_raw

logger = logging.getLogger(__name__)

# Noms de fichiers acceptes pour chaque artefact, par ordre de priorite.
# Les noms du notebook passent avant ceux du modele de demonstration
# (`model.joblib`, `scaler.joblib`) : deposer les vrais artefacts suffit a les
# faire prendre le dessus, sans supprimer le modele de repli.
MODEL_FILENAMES = (
    "meilleur_modele.pkl",
    "best_model.pkl",
    "random_forest.pkl",
    "model.pkl",
    "model.joblib",  # modele de demonstration
)
SCALER_FILENAMES = ("scaler_ddos.pkl", "minmax_scaler.pkl", "scaler.pkl", "scaler.joblib")
ENCODER_FILENAMES = (
    "label_encoder_ddos.pkl",
    "label_encoder.pkl",
    "encoder.pkl",
    "label_encoder.joblib",
)


@dataclass(slots=True)
class PredictionResult:
    """Resultat de classification d'un seul flux."""

    label: str
    confidence: float
    is_attack: bool
    probabilities: dict[str, float]


def _first_existing(directory: Path, filenames: tuple[str, ...]) -> Path | None:
    """Retourne le premier fichier de `filenames` present dans `directory`."""
    for name in filenames:
        candidate = directory / name
        if candidate.exists():
            return candidate
    return None


def _discover_model(directory: Path) -> Path | None:
    """Localise le fichier du modele.

    Cherche d'abord les noms connus, puis, a defaut, tout `.pkl`/`.joblib` du
    dossier qui ne soit ni un scaler ni un encodeur — ce qui permet de deposer un
    modele au nom libre sans toucher a la configuration.
    """
    known = _first_existing(directory, MODEL_FILENAMES)
    if known:
        return known

    exclus = set(SCALER_FILENAMES) | set(ENCODER_FILENAMES)
    candidats = [
        p
        for p in sorted(directory.glob("*"))
        if p.suffix in (".pkl", ".joblib") and p.name not in exclus
    ]
    if not candidats:
        return None

    # Le modele est de loin le plus gros artefact : on prend le fichier le plus lourd.
    choisi = max(candidats, key=lambda p: p.stat().st_size)
    logger.info("Modele detecte automatiquement : %s", choisi.name)
    return choisi


class DDoSPredictor:
    """Enveloppe thread-safe autour du modele de classification et de ses artefacts."""

    def __init__(self, model_dir: Path | None = None) -> None:
        """Prepare le predicteur ; aucun artefact n'est charge avant `load()`."""
        self._dir = Path(model_dir or settings.MODEL_DIR)
        self._lock = threading.Lock()
        self._model: Any = None
        self._scaler: Any = None
        self._encoder: Any = None
        self._classes: list[str] = list(CLASS_NAMES)
        self._features: list[str] = list(FEATURE_NAMES)
        self._metadata: dict[str, Any] = {}
        self._files: dict[str, str | None] = {"model": None, "scaler": None, "encoder": None}

    # ── Chargement ────────────────────────────────────────────────────────────
    def load(self) -> bool:
        """Charge les artefacts depuis le disque. Retourne True si un modele est pret."""
        import joblib

        model_path = _discover_model(self._dir)
        if model_path is None:
            logger.warning("Aucun modele trouve dans %s", self._dir)
            return False

        scaler_path = _first_existing(self._dir, SCALER_FILENAMES)
        encoder_path = _first_existing(self._dir, ENCODER_FILENAMES)

        with self._lock:
            # Les artefacts sont souvent produits par une autre version de
            # scikit-learn : l'avertissement est attendu et sans consequence ici.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                self._model = joblib.load(model_path)
                self._scaler = joblib.load(scaler_path) if scaler_path else None
                self._encoder = joblib.load(encoder_path) if encoder_path else None

            self._files = {
                "model": model_path.name,
                "scaler": scaler_path.name if scaler_path else None,
                "encoder": encoder_path.name if encoder_path else None,
            }

            self._load_classes()
            self._load_metadata(model_path)

        logger.info(
            "Modele charge : %s (%s) | scaler : %s | encodeur : %s | %d classes, %d caracteristiques",
            type(self._model).__name__,
            model_path.name,
            self._files["scaler"] or "aucun (repli sur les bornes internes)",
            self._files["encoder"] or "aucun",
            len(self._classes),
            len(self._features),
        )
        if self._scaler is None:
            logger.warning(
                "Aucun scaler trouve : les valeurs brutes seront normalisees avec les "
                "bornes approximatives de features.py, ce qui degrade la precision."
            )
        return True

    def _load_classes(self) -> None:
        """Determine les noms de classes, en privilegiant le LabelEncoder."""
        if self._encoder is not None and hasattr(self._encoder, "classes_"):
            self._classes = [str(c) for c in self._encoder.classes_]
            return

        classes = getattr(self._model, "classes_", None)
        if classes is not None and len(classes) and isinstance(classes[0], str):
            self._classes = [str(c) for c in classes]
        else:
            # Modele entraine sur des labels encodes sans encodeur fourni :
            # on retombe sur l'ordre alphabetique du dataset CICDDoS2019.
            self._classes = list(CLASS_NAMES)

    def _load_metadata(self, model_path: Path) -> None:
        """Charge metadata.json, mais seulement s'il decrit bien le modele charge.

        Sans cette verification, les metriques du modele de demonstration
        seraient affichees a cote d'un modele reel — donc trompeuses.
        """
        self._metadata = {}
        meta_path = self._dir / "metadata.json"
        if not meta_path.exists():
            return

        try:
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("metadata.json illisible : %s", exc)
            return

        declared = metadata.get("model_file")
        if declared != model_path.name:
            # Un metadata.json sans `model_file` provient forcement d'une version
            # anterieure du modele de demonstration : on ne l'associe qu'a lui.
            logger.warning(
                "metadata.json decrit '%s' alors que '%s' est charge : metriques ignorees. "
                "Ajoutez \"model_file\": \"%s\" a metadata.json pour publier vos propres metriques.",
                declared or "(non precise)",
                model_path.name,
                model_path.name,
            )
            return

        self._metadata = metadata
        if metadata.get("features"):
            self._features = list(metadata["features"])
        # Les classes du metadata ne prennent le dessus que sans LabelEncoder.
        if metadata.get("classes") and self._encoder is None:
            self._classes = list(metadata["classes"])

    @property
    def is_ready(self) -> bool:
        """Indique si un modele est charge et pret a predire."""
        return self._model is not None

    @property
    def classes(self) -> list[str]:
        """Noms des classes, dans l'ordre attendu par le modele."""
        return list(self._classes)

    @property
    def features(self) -> list[str]:
        """Noms des caracteristiques attendues en entree, dans l'ordre."""
        return list(self._features)

    def raw_bounds(self) -> tuple[list[float], list[float]] | None:
        """Bornes min/max apprises par le scaler, ou None si absent.

        Le simulateur s'en sert pour produire des valeurs brutes dans les memes
        plages que le jeu d'entrainement.
        """
        scaler = self._scaler
        if scaler is None or not hasattr(scaler, "data_min_"):
            return None
        return [float(v) for v in scaler.data_min_], [float(v) for v in scaler.data_max_]

    def feature_importances(self, limit: int = 15) -> list[dict[str, float | str]]:
        """Importance des caracteristiques, lue directement dans le modele charge.

        Permet a la page Metriques d'afficher quelque chose d'utile meme lorsque
        aucun `metadata.json` n'accompagne le modele.
        """
        importances = getattr(self._model, "feature_importances_", None)
        if importances is None or len(importances) != len(self._features):
            return []

        classees = sorted(
            zip(self._features, (float(v) for v in importances), strict=True),
            key=lambda kv: kv[1],
            reverse=True,
        )
        return [{"feature": nom, "importance": round(val, 5)} for nom, val in classees[:limit]]

    def info(self) -> dict[str, Any]:
        """Etat du modele, tel qu'expose par l'API et affiche dans l'interface."""
        return {
            "ready": self.is_ready,
            "model_type": type(self._model).__name__ if self._model is not None else None,
            "n_features": len(self._features),
            "n_classes": len(self._classes),
            "classes": self._classes,
            "features": self._features,
            "scaler": type(self._scaler).__name__ if self._scaler is not None else None,
            "encoder": type(self._encoder).__name__ if self._encoder is not None else None,
            "files": self._files,
            "expects_raw_features": True,
            "n_estimators": getattr(self._model, "n_estimators", None),
            "max_depth": getattr(self._model, "max_depth", None),
            "dataset": self._metadata.get("dataset", "CICDDoS2019"),
            "trained_at": self._metadata.get("trained_at"),
            "is_demo": bool(self._metadata.get("is_demo", False)),
            "has_training_metrics": bool(self._metadata.get("metrics")),
            "metrics": self._metadata.get("metrics", {}),
        }

    # ── Inference ─────────────────────────────────────────────────────────────
    def _prepare(self, vectors: list[list[float]], already_scaled: bool) -> np.ndarray:
        """Valide la forme du lot et applique la mise a l'echelle attendue par le modele.

        `already_scaled=True` signifie que l'appelant fournit un vecteur deja
        normalise (cas d'une ligne recopiee depuis le notebook) : le scaler est
        alors court-circuite.
        """
        matrix = np.asarray(vectors, dtype=np.float64)
        if matrix.ndim == 1:
            matrix = matrix.reshape(1, -1)

        expected = len(self._features) or N_FEATURES
        if matrix.shape[1] != expected:
            raise ValueError(
                f"{expected} caracteristiques attendues, {matrix.shape[1]} recues "
                f"(ordre attendu : {', '.join(self._features[:3])}, ...)"
            )

        # CICFlowMeter produit des inf/NaN sur les flux d'un seul paquet.
        matrix = np.nan_to_num(matrix, nan=0.0, posinf=0.0, neginf=0.0)

        if already_scaled:
            return matrix

        if self._scaler is not None:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                return self._scaler.transform(matrix)

        # Repli : normalisation avec les bornes approximatives de features.py
        return np.array(
            [
                [normalize_raw(self._features[i], row[i]) for i in range(expected)]
                for row in matrix
            ],
            dtype=np.float64,
        )

    def _label_for(self, raw_label: object) -> str:
        """Traduit la sortie du modele (indice encode ou chaine) en nom de classe."""
        if isinstance(raw_label, str):
            return raw_label

        index = int(raw_label)
        if self._encoder is not None:
            try:
                return str(self._encoder.inverse_transform([index])[0])
            except (ValueError, IndexError):
                pass
        if 0 <= index < len(self._classes):
            return self._classes[index]
        return str(raw_label)

    def predict_batch(
        self, vectors: list[list[float]], already_scaled: bool = False
    ) -> list[PredictionResult]:
        """Classe un lot de flux et retourne un resultat par ligne."""
        if not self.is_ready:
            raise RuntimeError("Modele non charge : impossible de predire")

        matrix = self._prepare(vectors, already_scaled)
        with self._lock:
            labels = self._model.predict(matrix)
            probabilities = (
                self._model.predict_proba(matrix)
                if hasattr(self._model, "predict_proba")
                else None
            )
            model_classes = [self._label_for(c) for c in getattr(self._model, "classes_", [])]

        results: list[PredictionResult] = []
        for i, raw_label in enumerate(labels):
            label = self._label_for(raw_label)
            probs: dict[str, float] = {}
            confidence = 1.0
            if probabilities is not None:
                row = probabilities[i]
                probs = {model_classes[j]: float(row[j]) for j in range(len(model_classes))}
                confidence = float(row.max())
            results.append(
                PredictionResult(
                    label=label,
                    confidence=round(confidence * 100, 2),
                    is_attack=label != "BENIGN",
                    probabilities={k: round(v, 6) for k, v in probs.items()},
                )
            )
        return results

    def predict_one(self, vector: list[float], already_scaled: bool = False) -> PredictionResult:
        """Classe un flux unique. Raccourci sur `predict_batch`."""
        return self.predict_batch([vector], already_scaled)[0]


predictor = DDoSPredictor()


def load_or_bootstrap() -> None:
    """Charge le modele ; a defaut, entraine un modele de demonstration."""
    if predictor.load():
        return

    from app.ml.train_demo_model import bootstrap_demo_model

    logger.warning("Entrainement d'un modele de demonstration (aucun artefact fourni)")
    bootstrap_demo_model(settings.MODEL_DIR)
    predictor.load()
