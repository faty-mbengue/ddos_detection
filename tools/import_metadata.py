#!/usr/bin/env python3
"""Convertit le certificat de modele du notebook en `metadata.json` exploitable.

Le notebook d'entrainement produit un « certificat » JSON lisible par un humain
(`metadate1.txt`). Le backend, lui, attend un `metadata.json` au format decrit
dans le README. Ce script fait la traduction, en corrigeant trois pieges :

  1. `model_file` est ajoute pour lier les metriques a un artefact precis ;
     sans lui le backend refuse de les afficher, afin de ne jamais montrer les
     chiffres d'un modele a cote d'un autre.
  2. les importances du certificat sont en pourcentages (somme = 100), alors
     que le backend attend des fractions ;
  3. le certificat ne fournit que les moyennes ponderees ; les moyennes macro
     sont recalculees ici a partir des scores par classe.

Utilisation (depuis le dossier backend/) :

    uv run python ../tools/import_metadata.py
    uv run python ../tools/import_metadata.py --source chemin/vers/certificat.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ARTIFACTS = Path(__file__).resolve().parents[1] / "backend" / "app" / "ml" / "artifacts"


def macro_average(per_class: dict[str, dict[str, float]], metric: str) -> float:
    """Moyenne non ponderee d'une metrique sur toutes les classes."""
    valeurs = [classe[metric] for classe in per_class.values()]
    return round(sum(valeurs) / len(valeurs), 6)


def convert(certificat: dict[str, Any], model_file: str) -> dict[str, Any]:
    """Traduit le certificat du notebook vers le format attendu par le backend."""
    classes_par_indice = certificat["classes"]
    classes = [classes_par_indice[str(i)] for i in range(len(classes_par_indice))]

    # Les scores par classe sont deja des fractions (0-1) dans le certificat.
    per_class = {
        nom: {
            "precision": float(valeurs["precision"]),
            "recall": float(valeurs["recall"]),
            "f1": float(valeurs["f1"]),
            "support": int(valeurs["support"]),
        }
        for nom, valeurs in certificat["performances_par_classe"].items()
    }

    test = certificat["performances_globales"]["test"]
    dimensions = certificat.get("dimensions_donnees", {})

    # Importances : le certificat les exprime en pourcentages.
    importances = {
        entree["feature"]: round(float(entree["importance"]) / 100, 6)
        for entree in certificat.get("feature_importances", [])
    }

    metrics: dict[str, Any] = {
        "accuracy": round(float(test["accuracy"]) / 100, 6),
        # Recalculees depuis les scores par classe : le certificat ne donne que
        # les moyennes ponderees, or l'interface annonce des moyennes macro.
        "precision_macro": macro_average(per_class, "precision"),
        "recall_macro": macro_average(per_class, "recall"),
        "f1_macro": macro_average(per_class, "f1"),
        # Moyennes ponderees telles que fournies par le notebook.
        "precision_weighted": round(float(test["precision_weighted"]) / 100, 6),
        "recall_weighted": round(float(test["recall_weighted"]) / 100, 6),
        "f1_weighted": round(float(test["f1_weighted"]) / 100, 6),
        "per_class": per_class,
        # Le certificat ne contient pas la matrice (exportee en PNG) : l'onglet
        # correspondant restera vide tant qu'elle n'est pas fournie.
        "confusion_matrix": None,
        "feature_importances": importances,
        "n_train": dimensions.get("entrainement", {}).get("lignes"),
        "n_val": dimensions.get("validation", {}).get("lignes"),
        "n_test": dimensions.get("test", {}).get("lignes"),
    }

    infos = certificat.get("informations_generales", {})
    jeu = certificat.get("dataset", {})

    return {
        "model_file": model_file,
        "classes": classes,
        "features": certificat["features"],
        "dataset": jeu.get("nom", "CIC-DDoS2019"),
        "dataset_source": jeu.get("source"),
        "algorithm": infos.get("algorithme", "RandomForestClassifier"),
        "hyperparameters": certificat.get("hyperparametres", {}),
        "trained_at": certificat.get("certificat", {}).get("date_creation"),
        "author": certificat.get("certificat", {}).get("auteur"),
        "is_demo": False,
        "metrics": metrics,
    }


def check_consistency(certificat: dict[str, Any]) -> list[str]:
    """Releve les incoherences du certificat, sans bloquer la conversion."""
    alertes: list[str] = []

    supports = sum(v["support"] for v in certificat["performances_par_classe"].values())
    dimensions = certificat.get("dimensions_donnees", {})
    n_test = dimensions.get("test", {}).get("lignes")
    if n_test and supports != n_test:
        alertes.append(
            f"la somme des supports ({supports:,}) differe de la taille du jeu de test "
            f"({n_test:,})"
        )

    total = dimensions.get("total", {}).get("lignes")
    if total:
        for nom in ("entrainement", "validation", "test"):
            bloc = dimensions.get(nom, {})
            reel = bloc.get("lignes", 0) / total * 100
            annonce = bloc.get("pourcentage")
            if annonce and abs(reel - annonce) > 2:
                alertes.append(
                    f"{nom} : {annonce} % annonces, {reel:.1f} % reels "
                    f"({bloc.get('lignes'):,} sur {total:,})"
                )
    return alertes


def main() -> int:
    """Convertit le certificat et ecrit metadata.json a cote des artefacts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        default=str(ARTIFACTS / "metadate1.txt"),
        help="Certificat JSON produit par le notebook",
    )
    parser.add_argument(
        "--model-file",
        default="meilleur_modele.pkl",
        help="Nom du fichier de modele auquel ces metriques se rapportent",
    )
    parser.add_argument(
        "--output",
        default=str(ARTIFACTS / "metadata.json"),
        help="Destination du metadata.json",
    )
    args = parser.parse_args()

    source = Path(args.source)
    if not source.exists():
        print(f"Certificat introuvable : {source}", file=sys.stderr)
        return 1

    certificat = json.loads(source.read_text(encoding="utf-8"))

    for alerte in check_consistency(certificat):
        print(f"  attention : {alerte}", file=sys.stderr)

    metadata = convert(certificat, args.model_file)
    Path(args.output).write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    m = metadata["metrics"]
    print(f"metadata.json ecrit pour {args.model_file}")
    print(f"  accuracy      : {m['accuracy'] * 100:.2f} %")
    print(f"  F1 macro      : {m['f1_macro'] * 100:.2f} %  (ponderee {m['f1_weighted'] * 100:.2f} %)")
    print(f"  classes       : {len(metadata['classes'])} | caracteristiques : {len(metadata['features'])}")
    print(f"  jeu de test   : {m['n_test']:,} echantillons")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
