# Backend — DDoS Monitor

API FastAPI : capture du trafic, détection par Random Forest (CICDDoS2019),
historisation et diffusion temps réel. Dépendances gérées par **uv**.

## Lancer en local

```bash
uv sync
cp .env.example .env                 # ajuster DATABASE_URL et SECRET_KEY
uv run python -m app.scripts.seed    # comptes initiaux + historique de démonstration
uv run uvicorn app.main:app --reload
```

Documentation interactive : http://localhost:8000/docs

## Entraîner le modèle de démonstration

```bash
uv run python -m app.ml.train_demo_model
```

Écrit `model.joblib` et `metadata.json` dans `app/ml/artifacts/`. Ce modèle n'est
qu'un repli : déposez les artefacts du notebook CICDDoS2019 dans le même dossier
pour le remplacer, puis `POST /api/model/reload`.

## Vecteur d'entrée

31 caractéristiques normalisées dans `[0, 1]`, dans l'ordre défini par
`FEATURE_NAMES` (`app/ml/features.py`) — l'ordre du notebook d'entraînement.
`GET /api/model/features` renvoie la liste exacte attendue.

```bash
curl -X POST http://localhost:8000/api/predict \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"features": [1.0, 0.07498149, 0.0000699, 0.0, 0.00039151, 0.02073969,
       0.0, 0.0, 0.0, 0.0, 0.00000016, 0.00000002, 0.0, 0.0, 0.0, 0.0,
       0.00136364, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
       0.00170316, 0.0, 0.0, 0.0]}'
# → {"prediction": "TFTP", "class_index": 9, "confidence": 90.0, "is_attack": true, ...}
```

`app/ml/features.py` fournit aussi `vector_from_flow()`, qui construit ce vecteur
directement depuis une ligne de la table `flows` (colonnes CICFlowMeter).

## Endpoints principaux

| Méthode | Route | Rôle |
|---|---|---|
| `POST` | `/api/auth/login` | Jeton JWT (formulaire OAuth2) |
| `GET` | `/api/auth/me` | Profil courant |
| `GET` | `/api/packets` | Derniers paquets capturés |
| `GET` | `/api/flows` · `/api/flows/{id}` | Flux analysés, détail 80 colonnes |
| `GET` | `/api/predictions` · `/predictions/distribution` | Classifications |
| `POST` | `/api/predict` · `/api/predict/batch` | Prédiction à la demande |
| `GET` | `/api/dashboard` | Données agrégées du tableau de bord |
| `GET` | `/api/stats/live` · `/api/stats/history` | Statistiques instantanées et débit |
| `GET` | `/api/attacks` · `/attacks/summary` · `/attacks/types` | Historique des alertes |
| `PATCH` | `/api/attacks/{id}/mitigate` | Marquer une alerte comme mitigée |
| `GET` | `/api/attacks/export/csv` · `/api/predictions/export` | Exports CSV |
| `GET` | `/api/model/metrics` · `/model/info` · `/model/features` | Métriques du modèle |
| `POST` | `/api/model/reload` | Recharger les artefacts (admin) |
| `GET` | `/api/system/status` | État du pipeline, de la capture et du modèle |
| `*` | `/api/admin/users` · `/settings` · `/blocked-ips` · `/pipeline/{action}` | Administration |
| `WS` | `/ws/packets` · `/ws/stats` · `/ws/alerts` | Temps réel (`?token=<JWT>`) |

## Pipeline d'analyse

`app/services/analysis.py`, toutes les `ANALYSIS_INTERVAL_SECONDS` (15 s) :

1. les paquets du cycle sont persistés et diffusés sur `/ws/packets` ;
2. les flux sont construits (CICFlowMeter) et enregistrés dans `flows` ;
3. le Random Forest classe chaque flux → `predictions` ;
4. les flux malveillants sont regroupés par (type, source, cible) → `attacks` ;
5. les statistiques agrégées sont écrites dans `statistics` ;
6. l'interface est notifiée sur `/ws/stats` et `/ws/alerts`, l'email est envoyé
   et l'IP source peut être bloquée automatiquement.

Une alerte est levée lorsqu'au moins `ATTACK_FLOW_THRESHOLD` flux d'un même
triplet dépassent `ATTACK_CONFIDENCE_THRESHOLD`. Sa criticité découle du volume
de flux et de la confiance moyenne.

## Rôles

| Rôle | Droits |
|---|---|
| `admin` | Tout, y compris utilisateurs, configuration et rechargement du modèle |
| `analyst` | Lecture + mitigation des alertes et blocage d'IP |
| `viewer` | Lecture seule |

## Qualité

```bash
uv run ruff check .
```
