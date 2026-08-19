# DDoS Monitor

Plateforme de surveillance et de détection des attaques DDoS en temps réel.
Elle combine la capture du trafic réseau, l'analyse par un modèle de Machine
Learning entraîné sur **CICDDoS2019** et l'historisation des événements.

```
┌──────────────┐   paquets    ┌──────────────┐   flux CSV    ┌──────────────┐
│   Capture    │─────────────▶│ Extraction   │──────────────▶│ Random Forest│
│ tshark / sim │              │ CICFlowMeter │               │  12 classes  │
└──────────────┘              └──────────────┘               └──────┬───────┘
                                                                    │
        ┌──────────────┐      ┌──────────────┐      ┌───────────────▼──────┐
        │  Interface   │◀─────│  PostgreSQL  │◀─────│  Alertes & blocage   │
        │ React + WS   │      │   8 tables   │      │  email · IP · sévé.  │
        └──────────────┘      └──────────────┘      └──────────────────────┘
```

## Démarrage rapide

```bash
docker compose up -d --build
```

| Service | URL | Détail |
|---|---|---|
| Interface | http://localhost:8080 | React + nginx (relaie `/api` et `/ws`) |
| API | http://localhost:8000/docs | FastAPI + OpenAPI |
| pgAdmin | http://localhost:5050 | Consultation de la base |
| Base | `127.0.0.1:5432` | PostgreSQL 16 |

### pgAdmin

Le serveur **DDoS Monitor** est déjà enregistré (`docker/pgadmin/servers.json`) :

1. se connecter avec `PGADMIN_EMAIL` / `PGADMIN_PASSWORD` (voir `.env`) ;
2. déplier *Serveurs → DDoS Monitor* ;
3. saisir le mot de passe PostgreSQL (`POSTGRES_PASSWORD`, `ddos` par défaut) —
   cocher « Save Password » pour ne plus l'avoir à le retaper.

Les huit tables sont alors accessibles sous
*Databases → ddos_monitor → Schemas → public → Tables*.

> L'adresse `PGADMIN_EMAIL` doit avoir un domaine valide : pgAdmin refuse les
> TLD comme `.local` et refuserait de démarrer.

**Comptes créés au premier démarrage** — à changer immédiatement :

| Identifiant | Mot de passe | Rôle |
|---|---|---|
| `admin` | `admin123` | Administrateur |
| `analyst` | `analyst123` | Analyste |

## Les trois fichiers compose

| Fichier | Rôle | Quand |
|---|---|---|
| `docker-compose.yml` | La pile complète : db, backend, frontend, pgAdmin. Porte déjà `cap_add: NET_ADMIN, NET_RAW` | Toujours |
| `docker-compose.capture.yml` | Bascule le backend sur le **réseau de l'hôte** (`network_mode: host`) | Serveur Linux, pour voir les interfaces de la machine |
| `docker-compose.firewall.yml` | Force `FIREWALL_ENABLED=true` + `FIREWALL_BACKEND=iptables` | Raccourci ; le `.env` suffit désormais |

> **Les capabilities sont dans le compose de base.** Sans `NET_ADMIN`/`NET_RAW`,
> le conteneur tourne avec `CapEff=0` : `tshark` ne voit aucune interface réelle
> et `iptables` répond « Operation not permitted ». Les deux fonctions centrales
> du projet étant la capture et le blocage, elles sont accordées par défaut.
> Retirez le bloc `cap_add` de `docker-compose.yml` si vous n'utilisez que les
> modes `simulator` ou `external`.

Les surcouches se combinent :

```bash
# Sonde complète sur un serveur Linux : capture réelle + blocage effectif
docker compose -f docker-compose.yml \
               -f docker-compose.capture.yml \
               -f docker-compose.firewall.yml up -d --build
```

## Les 12 classes détectées

`BENIGN` (trafic légitime) et 11 familles d'attaques par réflexion/amplification :
`DNS`, `LDAP`, `MSSQL`, `NTP`, `NetBIOS`, `SNMP`, `SSDP`, `Syn`, `TFTP`, `UDP`, `UDPLag`.

Le modèle reçoit un vecteur de **31 caractéristiques brutes** CICFlowMeter,
dans l'ordre exact du notebook d'entraînement (voir `backend/app/ml/features.py`).
C'est le `MinMaxScaler` sauvegardé avec le modèle qui les met à l'échelle : lui
seul connaît les bornes réelles du jeu d'entraînement. Normaliser en amont
produirait une double mise à l'échelle, donc des prédictions fausses.

## Fonctionnalités

| Page | Contenu |
|---|---|
| **Flux Live** | Tableau des paquets en temps réel (WebSocket), mise en couleur par protocole et par niveau de risque, débit réseau, défilement automatique |
| **Tableau de bord** | Indicateurs clés, histogramme des classes, camembert légitime/malveillant, courbe d'évolution, graphique polaire des confiances |
| **Historique** | Journal des alertes, filtres (type, criticité, état, période, IP), tri par criticité, export CSV, mitigation et blocage |
| **Prédictions** | Répartition des classes, niveaux de confiance, détail des flux classés, export CSV |
| **Métriques** | Accuracy / Precision / Recall / F1, rapport par classe, importance des caractéristiques, matrice de confusion, comportement en production |
| **Analyse fichier** | Dépôt d'un PCAP ou d'un CSV CICFlowMeter, classification hors ligne, mesure de l'exactitude si le fichier est étiqueté |
| **Administration** | Utilisateurs (3 rôles), configuration à chaud, démarrage/arrêt de la capture, IP bloquées |

## D'où viennent les données ? (à lire en premier)

Par défaut, **les données ne viennent pas de votre réseau**. Le backend démarre
en `CAPTURE_BACKEND=simulator` : il génère un trafic synthétique reproduisant
les signatures de chaque classe CICDDoS2019. Les adresses `192.168.1.101`,
`10.0.0.5` que vous voyez à l'écran sont fabriquées.

Trois modes existent, choisis par `CAPTURE_BACKEND` :

| Mode | Source des données | Fonctionne sur |
|---|---|---|
| `simulator` (défaut) | Trafic synthétique généré par le backend | Partout, sans privilège |
| `external` | **Le trafic réel de votre machine**, via un agent | macOS, Linux, Windows |
| `tshark` | Trafic réel capturé par le backend lui-même | Linux uniquement |

### Pourquoi un agent séparé sur votre machine ?

Docker Desktop exécute les conteneurs dans une **machine virtuelle Linux**. Un
conteneur ne voit donc jamais les interfaces réseau de votre Machine physique : même avec `network_mode: host`, il n'observerait que le réseau interne de la VM. La seule
façon de capturer votre trafic réel est de lancer la capture *sur machine physique*, puis
de l'envoyer à l'API.

```
┌──────────────── votre Machine ─────────────────┐
│  en0 (Wi-Fi)                               │
│      │                                     │
│      ▼                                     │
│  tools/capture_agent.py                    │   ← tshark tourne ICI
│  tshark → flux CICFlowMeter                │
│      │  POST /api/ingest                   │
└──────┼─────────────────────────────────────┘
       ▼
┌──────────────── Docker (VM Linux) ─────────┐
│  backend → modèle → alertes → PostgreSQL   │
│  frontend (nginx) ── http://localhost:8080 │
└────────────────────────────────────────────┘
```

### Capturer le trafic réel de votre Machine sous macOS

```bash
# 1. Installer tshark (une seule fois)
brew install wireshark

# 2. Autoriser la capture sans être root (une seule fois, à refaire au reboot)
sudo chmod +r /dev/bpf*

# 3. Basculer le backend en mode external
echo "CAPTURE_BACKEND=external" >> .env
docker compose up -d

# 4. Trouver votre interface (en0 = Wi-Fi sur la plupart des Machine)
cd backend
uv run python ../tools/capture_agent.py --list-interfaces

# 5. Lancer l'agent — le tableau de bord se remplit avec VOTRE trafic
uv run python ../tools/capture_agent.py --interface en0
```

L'agent affiche une ligne par cycle :

```
cycle    7 |   842 paquets |   96 flux |   1103.4 Ko
cycle    8 |  1204 paquets |  131 flux |   1580.2 Ko  ⚠ 1 alerte(s)
```

## Sous windows

````bash
# 1. Installer Wireshark (https://www.wireshark.org/download.html)

### Déploiement sur un serveur Linux : capture dans le conteneur

**C'est le mode à utiliser en production.** Aucun agent n'est nécessaire :
`tshark` est installé dans l'image du backend et le conteneur capture
directement l'interface du serveur.

```bash
CAPTURE_INTERFACE=eth0 docker compose \
  -f docker-compose.yml -f docker-compose.capture.yml up -d --build
```

Trois éléments rendent cela possible, tous déjà en place :

| Élément | Où | Rôle |
|---|---|---|
| `apt-get install tshark tcpdump libcap2-bin` | `backend/Dockerfile` | Installe la capture dans l'image |
| `setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap` | `backend/Dockerfile` | Autorise la capture **sans passer root** |
| `cap_add: [NET_ADMIN, NET_RAW]` + `network_mode: host` | `docker-compose.capture.yml` | Donne au conteneur l'accès aux interfaces du serveur |

Le conteneur continue de tourner sous l'utilisateur non privilégié `appuser` :
seules les capabilities strictement nécessaires sont accordées, et uniquement au
binaire `dumpcap` — pas à l'ensemble du processus. C'est le compromis habituel
entre capture réseau et moindre privilège.

Listez les interfaces du serveur avec `ip link`, puis renseignez
`CAPTURE_INTERFACE`. Le mode de capture se règle dans `.env` :

```bash
CAPTURE_BACKEND=tshark
CAPTURE_INTERFACE=eth0
```

> **Pourquoi cela ne marche pas sur votre Machine** : le même `docker-compose.capture.yml`
> s'exécute sans erreur sous machine physique, mais `network_mode: host` y désigne la VM
> Linux de Docker Desktop, pas votre Machine. Vous captureriez le réseau virtuel de
> la VM, pas votre Wi-Fi. D'où l'agent pour le développement local, et ce mode
> pour le serveur.

### Limite connue de l'extraction de flux

Le module `_aggregate_flows` (`backend/app/services/capture.py`) est un
**CICFlowMeter simplifié** : il reconstitue les 31 caractéristiques à partir des
champs fournis par tshark, mais ne reproduit pas exactement toutes les
définitions de l'outil original (seuils d'activité/inactivité, sous-flux, calcul
précis de `Fwd Seg Size Min`…). Sur du trafic réel, la détection binaire
légitime/malveillant reste pertinente, mais l'attribution de la classe exacte
peut différer de ce que donnerait CICFlowMeter. Pour une fidélité totale,
remplacez cette fonction par un appel au vrai CICFlowMeter sur les fichiers PCAP.

## Surveiller tout le réseau, pas seulement une machine

C'est l'objectif du système : la sonde doit voir le trafic **dirigé vers les
machines à protéger**, pas uniquement celui de l'ordinateur qui l'héberge.

### Pourquoi vous ne voyez qu'une seule machine

Un réseau moderne est **commuté**. Le switch (ou la box) n'envoie à chaque port
que les trames qui lui sont destinées, plus les diffusions. Une sonde branchée
sur un port ordinaire ne voit donc que son propre trafic — mesuré ici : **99,4 %
des paquets capturés impliquaient la machine de capture**, le reste étant du
multicast. Ce n'est pas une limite du logiciel : Wireshark seul ne verrait pas
davantage. Le mode « promiscuous » n'y change rien, car les trames des autres
machines n'atteignent jamais le port.

### Les quatre placements possibles

| Placement | Ce que la sonde voit | Prérequis |
|---|---|---|
| **Sur le serveur protégé** | Tout le trafic entrant et sortant de ce serveur | Aucun — c'est le placement le plus simple |
| **Port miroir (SPAN)** | Tout le trafic du switch | Switch administrable |
| **En coupure (bridge)** | Tout ce qui transite entre les deux segments | La machine devient un point de passage |
| **TAP réseau** | Tout le trafic du lien, sans interférer | Boîtier matériel dédié |

### Le placement recommandé pour ce mémoire

**Déployer la sonde sur le serveur à protéger.** C'est exactement l'architecture
du schéma du mémoire : la VM de capture est placée devant les services visés,
derrière le pare-feu. Elle voit alors 100 % du trafic d'attaque, puisqu'une
attaque DDoS converge par définition vers sa cible.

```bash
# Sur le serveur Linux à protéger
CAPTURE_BACKEND=tshark
CAPTURE_INTERFACE=eth0        # l'interface qui reçoit le trafic public

docker compose -f docker-compose.yml \
               -f docker-compose.capture.yml \
               -f docker-compose.firewall.yml up -d --build
```

La sonde observe alors tout ce qui arrive sur le serveur, détecte les rafales, et
`iptables` bloque les sources à la volée — la boucle complète du schéma :
capture → extraction → classification → alerte → mitigation.

### Avec un port miroir

Si votre switch le permet, configurez un SPAN vers le port de la sonde, puis
écoutez cette interface. Aucune modification du code n'est nécessaire : indiquez
simplement l'interface miroir dans `CAPTURE_INTERFACE`. Vous verrez alors le
trafic de **toutes** les machines du segment.

> Sur un réseau que vous n'administrez pas, capturer le trafic d'autrui est
> illégal dans la plupart des juridictions. Ces placements supposent que le
> réseau vous appartient ou que vous en avez l'autorisation écrite.

### Mesures relevées sur ce projet

Ces chiffres proviennent de tests menés sur l'installation elle-même ; ils
justifient expérimentalement les choix ci-dessus.

| Situation | Résultat mesuré | Conclusion |
|---|---|---|
| Conteneur par défaut, sans `cap_add` | `CapEff=0000000000000000`, **0 paquet**, aucune interface réelle listée | Les capabilities, pas le logiciel, sont le facteur bloquant |
| Même image avec `NET_ADMIN`/`NET_RAW` | `eth0` visible, **211 paquets capturés** | `tshark` fonctionne dès qu'il en a le droit |
| Wi-Fi domestique, mode promiscuous actif | 335 paquets propres, 23 ARP, 1 multicast, 1 IPv6 — **0 unicast de tiers** | Le switch, pas la sonde, limite la visibilité |
| Écoute du pont Docker `br-…` | 380 + 342 paquets PostgreSQL entre **deux autres conteneurs** | Le placement décide de ce qu'on voit |

La conclusion est constante : **le mode promiscuous ne suffit pas.** Il demande
à la carte d'accepter toutes les trames qui lui parviennent, mais sur un réseau
commuté rien d'étranger ne lui parvient. Seul un port miroir, un TAP, ou un
placement sur la machine cible élargit la visibilité.

### Ce que le simulateur peut, et ne peut pas, démontrer

Le simulateur fabrique des vecteurs de caractéristiques à partir de profils
écrits à la main. Confrontés au modèle réel, ces profils obtiennent des
confiances très inégales — mesuré sur un échantillon :

| Classe simulée | Confiance moyenne du modèle |
|---|---|
| `Syn` | **57,6 %** (pics > 76 %) |
| `NTP` | 35,7 % |
| `LDAP` | 33,0 % |
| `NetBIOS` | 27,4 % |
| `DNS` | 25,9 % |
| `SNMP`, `TFTP` | ~27 % |

Avec le seuil par défaut à 70 %, seules les rafales `Syn` franchissent la barre
et déclenchent une alerte puis un blocage. Les autres classes simulées restent
sous le seuil et sont ignorées — ce qui est le comportement souhaité : le
système ne bloque que ce dont il est sûr.

**À retenir** : le simulateur valide la *chaîne de traitement* (capture →
extraction → classification → alerte → mitigation), pas la *qualité du modèle*.
Celle-ci se mesure sur le jeu de test CICDDoS2019 — 92,10 % d'accuracy, voir la
page Métriques. Ne présentez pas les résultats du simulateur comme une
évaluation du modèle.

## Déployer le modèle du mémoire

Le conteneur embarque un **modèle de démonstration** entraîné à la construction
sur des données synthétiques (accuracy ≈ 0,95). L'interface le signale
explicitement sur la page Métriques.

Pour installer le vrai modèle, déposez les artefacts du notebook CICDDoS2019
dans `backend/app/ml/artifacts/` :

| Fichier | Requis | Contenu |
|---|---|---|
| `model.joblib` | oui | Le `RandomForestClassifier` entraîné |
| `scaler.joblib` | non | Scaler appliqué avant l'inférence |
| `metadata.json` | non | `{"classes": [...], "features": [...], "metrics": {...}}` |

Puis, dans **Administration → Recharger le modèle** (ou
`POST /api/model/reload`). Le dossier est monté en volume : aucune
reconstruction d'image n'est nécessaire.

### Importer le certificat du notebook

Si le notebook produit un « certificat » JSON (`metadate1.txt`), un convertisseur
le traduit au format attendu :

```bash
cd backend
uv run python ../tools/import_metadata.py
```

Il écrit `metadata.json`, signale les incohérences du certificat, et corrige
trois pièges : il ajoute `model_file` (sans quoi le backend refuse d'afficher les
métriques), convertit les importances de pourcentages en fractions, et recalcule
les moyennes **macro** à partir des scores par classe — le certificat ne
fournissant que les moyennes pondérées.

Le format de `metrics` attendu par la page Métriques :

```json
{
  "accuracy": 0.99, "precision_macro": 0.99, "recall_macro": 0.99, "f1_macro": 0.99,
  "per_class": { "BENIGN": {"precision": 1.0, "recall": 1.0, "f1": 1.0, "support": 240} },
  "confusion_matrix": [[240, 0]],
  "feature_importances": {"Flow Bytes/s": 0.12},
  "n_train": 20160, "n_test": 5760
}
```

## Alertes par email (Gmail)

Renseignez dans `.env` :

```bash
ALERT_EMAIL_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_STARTTLS=true
SMTP_USER=votreemail@gmail.com
SMTP_PASSWORD=              # ← mot de passe d'application (voir ci-dessous)
ALERT_RECIPIENTS=votreemailadmin@gmail.com
```

**`SMTP_PASSWORD` doit être un « mot de passe d'application » Google**, pas le
mot de passe du compte — Google refuse ce dernier depuis 2022 :

1. activer la validation en deux étapes sur le compte Google ;
2. générer un mot de passe sur https://myaccount.google.com/apppasswords ;
3. coller les 16 caractères dans `.env`, puis `docker compose up -d backend`.

Vérifiez ensuite depuis *Administration → Configuration* : un bandeau indique
l'état de la configuration et le bouton **Tester** envoie un email de test en
affichant l'erreur exacte en cas d'échec.

### À quoi sert chaque variable

| Variable | Rôle |
|---|---|
| `SMTP_USER` | Le compte qui **s'authentifie** auprès de Gmail |
| `SMTP_PASSWORD` | Son mot de passe **d'application** |
| `SMTP_FROM` | L'adresse annoncée comme **expéditeur** (Gmail peut la réécrire) |
| `ALERT_RECIPIENTS` | **Qui reçoit** les alertes — plusieurs adresses séparées par des virgules |

### Priorité entre `.env` et l'interface

Deux réglages existent à la fois dans `.env` et dans l'interface
(*destinataires* et *notifications par email*). La règle est :

1. **au démarrage**, toute variable présente dans l'environnement écrase la
   valeur en base — le `.env` décrit le déploiement et fait foi ;
2. **ensuite**, l'interface d'administration peut l'ajuster à chaud, et cet
   ajustement s'applique jusqu'au prochain redémarrage.

Le même principe vaut pour `CAPTURE_INTERFACE`, `ANALYSIS_INTERVAL_SECONDS`,
`ATTACK_CONFIDENCE_THRESHOLD` et `ATTACK_FLOW_THRESHOLD`.

> **Sur l'expéditeur** : Gmail réécrit l'en-tête `From` avec l'adresse du compte
> authentifié. Vos alertes partiront donc de `bobcodeur@gmail.com`, sauf si
> `abdoulayembaye885@gmail.com` est déclarée comme alias vérifié dans
> *Gmail → Paramètres → Comptes → « Envoyer des e-mails en tant que »*.

## Analyser un fichier (PCAP ou CSV CICFlowMeter)

La page *Analyse fichier* rejoue une capture à travers le modèle, sans dépendre
de la surveillance temps réel. C'est la voie la plus proche du flux décrit dans
le mémoire, et la seule qui permette de travailler sur les jeux de données
publics.

| Format | Ce qui se passe | Fidélité |
|---|---|---|
| `.pcap`, `.pcapng`, `.cap` | Relu par `tshark`, agrégé en flux, classé | Bonne — l'agrégation reste simplifiée |
| `.csv` (CICFlowMeter) | Les 31 caractéristiques sont lues directement | **Maximale** — calculées par l'outil de référence |

Les noms de colonnes des différentes versions de CICFlowMeter sont reconnus
automatiquement. Trois nomenclatures cohabitent et sont toutes gérées :

| Origine | Exemple | Statut |
|---|---|---|
| CICDDoS2019 (fichiers du dataset) | `Total Fwd Packets`, ` Flow Duration` | espaces en tête tolérés |
| CICFlowMeter V4 (Java) | `Tot Fwd Pkts`, `Flow Byts/s` | reconnu |
| `cicflowmeter` (Python) | `tot_fwd_pkts`, `flow_byts_s` | reconnu |

Les caractéristiques absentes sont mises à zéro et signalées dans le bandeau
d'avertissement.

Les étiquettes sont normalisées avant comparaison : le dataset écrit
`DrDoS_DNS`, `UDP-lag`, `DrDoS_NTP` là où le modèle prédit `DNS`, `UDPLag`,
`NTP`. Sans cette normalisation, une prédiction juste serait comptée comme
fausse et l'exactitude affichée s'effondrerait à tort.

### Le seuil de confiance s'applique aussi ici

Une classe d'attaque prédite **avec une confiance inférieure au seuil**
(`ATTACK_CONFIDENCE_THRESHOLD`, 0,70 par défaut) n'est pas comptée comme une
attaque — exactement comme dans la surveillance temps réel. Le nombre de flux
concernés reste affiché (« *N* sous le seuil de 70 % ») pour que rien ne soit
masqué.

C'est important à l'interprétation : sur une capture réelle de serveur, le
modèle attribue souvent une classe d'attaque avec 25–30 % de confiance
seulement. Ces flux sont du trafic légitime mal étiqueté, pas des attaques.

### Mesurer l'exactitude du modèle

Si le fichier contient une colonne `Label` — c'est le cas des CSV du dataset
CICDDoS2019 — l'application compare chaque prédiction à la vérité terrain et
affiche l'exactitude obtenue, ainsi qu'un ✓/✗ par flux.

C'est le moyen le plus direct de **valider votre modèle depuis l'application
elle-même**, sur des données réelles et étiquetées, plutôt que sur du trafic
simulé.

```bash
# En ligne de commande, si vous préférez
curl -X POST http://localhost:8000/api/analysis/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@capture.pcap"
```

### Capturer sur un serveur, analyser dans l'application

Le trajet le plus fidèle pour le mémoire — le serveur produit les flux avec le
vrai CICFlowMeter, l'application ne fait que classer :

```bash
# Sur le serveur surveillé (Linux)
sudo tshark -i ens33 -a duration:15 -w capture.pcap
cicflowmeter -f capture.pcap -c flows.csv
```

Déposez ensuite `flows.csv` dans la page *Analyse fichier*. Les 31
caractéristiques sont alors calculées par l'outil de référence, et non par
l'agrégation simplifiée appliquée aux PCAP.

Le même PCAP déposé directement donnera une répartition de classes différente :
c'est attendu, et c'est la mesure de l'écart entre l'agrégation interne et
CICFlowMeter.

Rien n'est enregistré en base : l'analyse est purement consultative, ce qui
évite de mélanger une capture rejouée au trafic réellement surveillé. Limite :
200 Mo par fichier — la même valeur est fixée dans nginx
(`client_max_body_size`), faute de quoi un dépôt depuis le navigateur serait
rejeté en 413 avant même d'atteindre l'API.

Un fichier **rapport** (`.txt` de synthèse, journal, notes) est refusé : seuls
un PCAP ou un tableau de flux — une ligne par flux — sont exploitables.

## Ne pas mélanger trafic simulé et trafic réel

Chaque enregistrement porte sa **provenance** (`source`) : `simulator`,
`external` ou `tshark`. Sans cela, basculer de mode additionnerait du trafic
fabriqué et du trafic réel dans les mêmes indicateurs — et le tableau de bord
afficherait « Attaque » sur un réseau parfaitement sain.

Un sélecteur en tête des pages *Flux Live* et *Tableau de bord* permet d'isoler
une source. L'effet est immédiat :

| Filtre | Flux | État |
|---|---|---|
| Toutes les sources | 17 093 | **Attaque** (venant du simulateur) |
| Trafic simulé | 15 288 | Attaque |
| Trafic réel (agent) | 1 805 | **Normal** |

Côté API, tous les agrégats acceptent le paramètre :

```bash
GET /api/dashboard?hours=24&source=external
GET /api/stats/live?source=simulator
```

La colonne est ajoutée automatiquement aux bases existantes au démarrage
(`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`), sans perte de données ; les
enregistrements antérieurs sont marqués `simulator`.

## Le blocage d'IP est-il réellement appliqué ?

Par défaut, **non**. La table `blocked_ips` est un inventaire de mitigation :
elle enregistre la décision, mais aucune règle de pare-feu n'est posée et le
trafic continue de passer. L'onglet *Administration → IP bloquées* l'affiche
explicitement par un bandeau.

Pour une mitigation effective :

`iptables` est installé dans l'image et reçoit la capability `CAP_NET_ADMIN`
au build, exactement comme `dumpcap` : le backend peut donc poser des règles
**sans tourner en root**.

Depuis que `cap_add` figure dans le compose de base, **deux variables du `.env`
suffisent** — la surcouche `docker-compose.firewall.yml` n'est plus qu'un
raccourci :

```bash
# Linux : le cas normal
FIREWALL_ENABLED=true
FIREWALL_BACKEND=iptables

# machine physique (backend lancé hors conteneur, en root pour accéder à pf)
FIREWALL_ENABLED=true
FIREWALL_BACKEND=pfctl
```

Attention : `FIREWALL_BACKEND=none` n'applique **aucune** règle, quel que soit
`FIREWALL_ENABLED` — la liste des IP reste alors un simple inventaire.

Pour vérifier que le blocage agit réellement :

```bash
curl -s localhost:8000/api/admin/firewall -H "Authorization: Bearer $TOKEN"
# {"enabled": true, "backend": "iptables", "active": true, ...}

docker compose exec backend iptables -S DDOS_MONITOR
# -A DDOS_MONITOR -s 117.175.194.67/32 -j DROP
```

Le service (`backend/app/services/firewall.py`) travaille dans des objets
dédiés — la chaîne `DDOS_MONITOR` pour iptables, la table
`ddos_monitor_blocked` pour pf — afin de ne jamais toucher aux règles
existantes de la machine. Les adresses sont validées avant usage et les
commandes construites sans shell. Au démarrage, la liste persistée est
ré-appliquée.

### Blocage automatique

Activé par l'interrupteur *Blocage automatique des IP* (ou `auto_block`), il
bloque la source d'une attaque **dès que l'alerte atteint la criticité élevée ou
critique**. Deux conditions doivent donc être réunies :

1. les flux malveillants dépassent `ATTACK_CONFIDENCE_THRESHOLD` (70 % par défaut) ;
2. le volume reçu par la cible atteint le palier `HIGH` (25 flux par cycle).

La criticité se mesure au volume subi par **la cible**, toutes sources
confondues — une attaque DDoS étant distribuée, la juger source par source
sous-estimerait systématiquement sa gravité.

> Attention : combiné à `auto_block`, un faux positif du modèle coupera du
> trafic légitime. Testez d'abord avec le blocage automatique désactivé, et
> surveillez la page *Historique* pendant quelques cycles.

## Configuration

Toutes les variables sont documentées dans `backend/.env.example`. Les plus
importantes, à surcharger dans un `.env` à la racine (lu par docker compose) :

```bash
SECRET_KEY=$(openssl rand -hex 32)   # obligatoire en production
FIRST_ADMIN_PASSWORD=...             # mot de passe administrateur initial
ANALYSIS_INTERVAL_SECONDS=15         # durée du cycle d'analyse
ATTACK_CONFIDENCE_THRESHOLD=0.70     # confiance minimale pour retenir une attaque
ATTACK_FLOW_THRESHOLD=3              # flux malveillants requis pour lever une alerte
ALERT_EMAIL_ENABLED=true             # notifications SMTP
```

Les paramètres de détection sont aussi modifiables **à chaud** depuis
l'interface d'administration (table `settings`), sans redémarrage.

## Développement hors conteneur

```bash
# Base de données
docker compose up -d db

# Backend (http://localhost:8000)
cd backend
uv sync
uv run python -m app.scripts.seed      # admin + historique de démonstration
uv run uvicorn app.main:app --reload

# Frontend (http://localhost:5173)
cd frontend
npm install
npm run dev
```

Vérifications :

```bash
cd backend  && uv run ruff check .
cd frontend && npm run lint && npm run build
```

## Structure

```
projet_FM/
├── docker-compose.yml           # db + backend + frontend
├── docker-compose.capture.yml   # surcouche capture réelle (tshark)
├── backend/                     # FastAPI + uv
│   ├── Dockerfile
│   ├── pyproject.toml
│   └── app/
│       ├── main.py              # cycle de vie, CORS, montage des routes
│       ├── core/                # config, base de données, sécurité JWT
│       ├── models/              # 8 tables SQLAlchemy
│       ├── schemas/             # contrats Pydantic
│       ├── api/routes/          # auth, monitoring, dashboard, attacks, metrics, admin, ws
│       ├── services/            # capture, ml, analysis, alerts, broadcast, settings
│       ├── ml/                  # features (31), modèle de démonstration, artefacts
│       └── scripts/seed.py      # comptes initiaux + historique
└── frontend/                    # Vite + React 19 + TypeScript + shadcn/ui
    ├── Dockerfile
    ├── nginx.conf               # SPA + relais /api et /ws
    └── src/
        ├── pages/               # login, live, dashboard, history, predictions, metrics, admin
        ├── components/shared/   # layout, sidebar, badges, KPI, tooltip
        ├── components/ui/       # primitives shadcn (new-york, base neutral)
        ├── service/             # client axios, auth, monitoring
        ├── hooks/               # use-auth, use-websocket
        └── lib/viz.ts           # palette de visualisation validée
```

## Base de données

| Table | Rôle |
|---|---|
| `flows` | Flux bruts CICFlowMeter (80 colonnes) |
| `predictions` | Classe prédite, confiance, indicateur d'attaque |
| `attacks` | Alertes consolidées (type, source, criticité, état) |
| `packets` | Paquets temps réel (fenêtre glissante) |
| `statistics` | Métriques agrégées par cycle |
| `users` | Authentification et rôles |
| `settings` | Configuration modifiable à chaud |
| `blocked_ips` | Blocage manuel et automatique |

Les tables sont créées au démarrage du backend ; la table `packets` est purgée
automatiquement pour ne conserver que la fenêtre récente.

## Choix de conception des visualisations

Les 12 classes ne sont **pas** encodées par 12 couleurs : au-delà de huit
teintes, aucune palette ne reste distinguable, en particulier en vision des
couleurs déficiente. L'encodage suit donc le sens des données — trafic légitime
contre trafic malveillant, soit deux teintes — l'identité de la classe étant
portée par l'axe et les étiquettes. Chaque paire utilisée a été validée dans les
deux thèmes (bande de clarté, plancher de chroma, séparation CVD, contraste
≥ 3:1). La criticité utilise une palette de statut distincte, toujours
accompagnée d'une icône et d'un libellé. Voir `frontend/src/lib/viz.ts`.

## Sécurité

Authentification JWT (`HS256`), mots de passe hachés en bcrypt, trois niveaux
d'accès (administrateur, analyste, lecture seule), backend exécuté sans
privilèges dans le conteneur, port PostgreSQL exposé sur la boucle locale
uniquement. En production : définissez `SECRET_KEY`, changez les mots de passe
initiaux, restreignez `CORS_ORIGINS` et placez l'ensemble derrière HTTPS.

======

Revenir au simulateur

# 1. arrêter l'agent
pkill -f capture_agent.py

# 2. basculer le mode
sed -i '' 's/^CAPTURE_BACKEND=external/CAPTURE_BACKEND=simulator/' .env

# 3. redémarrer le backend
docker compose up -d backend

Le simulateur reprend seul, en une vingtaine de secondes. Testé à l'instant : 3 467 paquets générés après bascule.

Revenir au trafic réel

sed -i '' 's/^CAPTURE_BACKEND=simulator/CAPTURE_BACKEND=external/' .env
docker compose up -d backend