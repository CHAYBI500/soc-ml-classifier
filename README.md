# soc-ml-classifier

Triage ML de niveau 1 (L1) pour les alertes Wazuh — classification automatique **True Positive / False Positive** afin de réduire la fatigue d'alerte des analystes et de ne router vers Telegram (via n8n) que les alertes réellement pertinentes, complétée par une **classification multi-classe du type de menace** (injection SQL, malware, brute force, DDoS, vulnérabilité/CVE, reconnaissance, attaque web, endpoint, réseau — voir section 9) avec une attention particulière portée à la détection des menaces liées aux bases de données.

---

## 1. Objectif

Ce projet vient compléter le pipeline SOC existant (Wazuh → n8n → Telegram/pfSense/GLPI) en ajoutant une étape de **pré-triage automatisé par Machine Learning**, en amont ou en parallèle du flux SOAR n8n déjà en place. Il ne remplace ni ne duplique :

- l'intégration native **VirusTotal** (integratord, groupe `syscheck`),
- l'intégration custom **AbuseIPDB** (`/var/ossec/integrations/custom-abuseipdb`),
- le workflow **n8n SOAR** existant (webhook → `rule.level >= 12` → pfSense/Telegram/GLPI),
- le pipeline Python `soc_pipeline` (Wazuh → Gemini → GLPI/email/SQLite) sur la VM `172.30.1.170`.

Il s'agit d'un **filtre supplémentaire, indépendant et interprétable**, basé sur un modèle Random Forest entraîné sur des alertes historiques labellisées.

---

## 2. Architecture

```
┌────────────────┐      alertes JSON       ┌──────────────────────┐
│  Wazuh Manager  │ ───────────────────────▶│ custom-ml-triage.py   │
│  10.212.2.170   │  (integrator, level>=3)  │ (intégration directe) │
└────────────────┘                          └──────────┬────────────┘
                                                         │ POST /predict
                                                         ▼
                                             ┌──────────────────────────┐
                                             │  API FastAPI (uvicorn)    │
                                             │  172.17.1.120:8000        │
                                             │  RandomForestClassifier   │
                                             └──────────┬───────────────┘
                                                         │
                                       ┌─────────────────┼─────────────────┐
                                       ▼                                   ▼
                            ┌────────────────────┐            ┌─────────────────────┐
                            │ dashboard/index.html│            │  n8n (workflow_example)│
                            │ (servi par FastAPI) │            │  → flux SOAR existant  │
                            └────────────────────┘            │  (pfSense/Telegram/GLPI)│
                                                                └─────────────────────┘
```

Deux chemins d'intégration coexistent, volontairement indépendants :

1. **Intégration directe Wazuh** (`custom-ml-triage` + `custom-ml-triage.py`) : chaque alerte de niveau ≥ 3 est envoyée directement à l'API par le manager Wazuh lui-même. Ce chemin ne fait que **journaliser** le verdict ML (aucun blocage automatique).
2. **n8n** (`n8n/workflow_example.json`) : un workflow minimal appelle `/predict` et ne relaie vers le flux SOAR existant (blocage pfSense, ticket GLPI, Telegram) que les alertes classées **True Positive avec confiance ≥ 0.6**.

---

## 3. Infrastructure cible

| Composant | Adresse / rôle |
|---|---|
| Wazuh manager | VM Linux — `10.212.2.170` |
| Agent Ubuntu | `172.17.1.115` |
| API ML (FastAPI/uvicorn) | `172.17.1.120:8000` |
| n8n (SOAR) | orchestrateur, webhook + logique conditionnelle |
| pfSense | blocage IP via alias + REST API (flux existant, non dupliqué ici) |
| GLPI | ticketing (flux existant) |
| SMTP | notifications email (flux existant) |
| Base de données | SQLite (pipeline Python séparé) |
| Threat intel | VirusTotal (native) + AbuseIPDB (custom, existant) |

---

## 4. Installation

### 4.1 Environnement de développement (Windows)

Ce projet a été développé sous Windows dans :
```
C:\Users\Administrateur\Downloads\soc-ml-classif\soc-ml-classifier
```

```powershell
cd soc-ml-classifier
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

> ⚠️ **Réseau** : la VM Wazuh (Linux, `10.212.2.170`) doit pouvoir atteindre ce poste Windows, port **8000** ouvert côté pare-feu Windows Defender (`netsh advfirewall firewall add rule name="soc-ml-api" dir=in action=allow protocol=TCP localport=8000`).
>
> **Recommandation** : ce setup de dev sur poste Windows n'est **pas adapté à un usage en production** (disponibilité réseau non garantie, poste susceptible d'être éteint/verrouillé). À terme, héberger l'API sur une **VM Linux dédiée** (ou directement sur la VM Wazuh) pour garantir la stabilité et la disponibilité 24/7 du service.

### 4.2 Environnement Linux (production visée)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 5. Entraînement des modèles

Le projet entraîne **deux modèles indépendants**, tous deux des `RandomForestClassifier`, sur le **même jeu de features** (`src/feature_engineering.py`) :

| Modèle | Sortie | Script | Fichier |
|---|---|---|---|
| Triage L1 (binaire) | `True Positive` / `False Positive` + confiance | `src/train_model.py` | `models/rf_classifier.joblib` |
| Catégorie de menace (multi-classe) | 1 des 8 catégories (voir section 9) + confiance | `src/train_category_model.py` | `models/rf_category_classifier.joblib` |

Le second modèle est **additif** : `/predict` renvoie toujours `prediction`/`confidence` (contrat inchangé pour n8n) et ajoute `category`/`category_label`/`category_confidence`.

### 5.1 Récupérer et convertir le dataset

```bash
python -m src.fetch_wazuh_ruleset              # optionnel mais recommandé, voir 5.1bis
python -m src.convert_hf_dataset --output data/processed/training_data.csv
```

Ce script combine **trois sources** :
1. `kholil-lil/wazuh-alerts` depuis HuggingFace (738 alertes labellisées TP/FP) ;
2. des alertes synthétiques basées sur des `rule.id`/groupes/MITRE plausibles (`src/seed_alerts.py`), pour les catégories peu couvertes par le dataset public ;
3. si `data/raw/wazuh_ruleset_rules.json` existe (voir 5.1bis), des alertes générées à partir de **vraies définitions de règles** du ruleset officiel Wazuh (`src/fetch_wazuh_ruleset.py`) — source ajoutée pour renforcer significativement le volume et la diversité, notamment sur `endpoint`/`bruteforce`/`vulnerability`/`ddos`.

Puis, pour chaque ligne : calcule les features (dont les features SQLi/CVE, voir section 9.2) et la catégorie heuristique (`src/attack_category.py`), et écrit `data/processed/training_data.csv` (features + `label` binaire + `category` multi-classe).

### 5.1bis Source additionnelle : ruleset officiel Wazuh (`src/fetch_wazuh_ruleset.py`)

Recherche effectuée (juillet 2026) sur le Hub HuggingFace pour d'autres datasets Wazuh avant
d'écrire ce module : `ruf0x/wazuh-alerts` et `wy777/wazuh-alerts` sont des **doublons exacts**
de `kholil-lil/wazuh-alerts` ; `yonatane22-bh/sereniq-wazuh-alerts` (10 000 lignes) s'est révélé
**entièrement templaté** (54 `rule_id` distincts répétés, label déterministe à partir de
`rule_level`/`is_known_bad_ip`) — le fusionner aurait dilué le signal réel sans rien apporter
que nos propres features ne capturent déjà ; `acezxn/event_correlation_wazuh` contient de
vraies alertes mais son label sert à une tâche différente (pertinence d'une étape
d'investigation), pas au triage TP/FP. Aucun n'a été retenu (même rigueur que pour CAM-LDS,
section 10).

À la place, `src/fetch_wazuh_ruleset.py` télécharge ~40 fichiers XML du dépôt public
`wazuh/wazuh-ruleset` (GPLv2), en extrait les vraies définitions de règles (id/level/
description/groupes/MITRE — pas des alertes avec un verdict TP/FP fourni), et applique un
label heuristique **volontairement conservateur** : une règle est exclue plutôt que labellisée
si son statut n'est pas clair (voir `_label_rule()` pour le détail complet — en résumé : MITRE
ou groupe de menace connu ⇒ TP, niveau ≤2 ou mot-clé de bruit routinier ⇒ FP, tout le reste
⇒ exclu). Deux problèmes de qualité identifiés et corrigés pendant le développement de ce
module, documentés dans son code : des placeholders `$(champ)` non résolus produisaient du
texte factice pour certaines règles (Palo Alto/OpenVAS), et un niveau élevé combiné à l'absence
de MITRE labellisait à tort des erreurs internes de logiciel (ex: "Windows Defender: ERROR: BAD
DB") comme incidents de sécurité — ce même travail a aussi révélé et corrigé un bug de
correspondance par sous-chaîne dans `attack_category.py` (`"scan"` matchait `"rescan"`).

```bash
python -m src.fetch_wazuh_ruleset            # télécharge + parse + écrit data/raw/wazuh_ruleset_rules.json
python -m src.fetch_wazuh_ruleset --offline  # reparse le cache XML local (data/raw/wazuh_ruleset/) sans réseau
```

Résultat (juillet 2026, 40 fichiers demandés, 2 ignorés pour XML mal formé) : 416 règles
retenues, réparties `{endpoint: 169, bruteforce: 71, other: 46, malware: 41, web: 32, sql: 28,
vulnerability: 13, ddos: 8, recon: 6, network: 2}`, dont 24 labellisées False Positive
(règles explicitement routinières/informationnelles). `convert_hf_dataset.py` génère ensuite
2 variations (agent/IP/firedtimes) par règle retenue.

### 5.2 Entraîner les deux Random Forest

```bash
python -m src.train_model --data data/processed/training_data.csv --output models/rf_classifier.joblib
python -m src.train_category_model --data data/processed/training_data.csv --output models/rf_category_classifier.joblib
```

Chaque script affiche le rapport de classification sur un split 80/20 (rapide mais bruité — variance élevée quand une classe a peu d'exemples), **puis une validation croisée stratifiée** (5-fold, ou moins si la classe la plus rare a moins de 5 exemples) sur l'intégralité du dataset : moyenne ± écart-type sur accuracy/f1_macro/precision_macro/recall_macro, une estimation nettement plus robuste qu'un split unique. Le modèle sauvegardé reste celui entraîné sur le split 80/20 (comportement inchangé). `train_category_model.py` avertit explicitement si une catégorie a moins de 10 exemples (métriques peu fiables pour cette classe).

Résultats de référence (juillet 2026, 1722 lignes = 738 kholil-lil + 152 seed_alerts + 832 ruleset) : modèle binaire — accuracy CV 99.6 % ± 0.4 % ; modèle de catégorie — accuracy CV 94.1 % ± 1.5 %, f1_macro CV 91.0 % ± 3.4 % (nettement plus crédible que les scores parfaits observés sur l'ancien dataset à 890 lignes, où plusieurs catégories n'avaient que 2 à 4 exemples dans le jeu de test).

Si `models/rf_category_classifier.joblib` est absent, `/predict` continue de fonctionner : il retombe automatiquement sur la classification heuristique (`category_source: "heuristic"` dans la réponse au lieu de `"model"`).

### 5.3 Tester en masse sans lancer l'API

```bash
python -m src.predict_batch --model models/rf_classifier.joblib --input data/raw/alerts.json --output data/processed/predictions.csv
```

---

## 6. Lancement de l'API

```bash
uvicorn src.api:app --host 0.0.0.0 --port 8000 --reload
```

Le dashboard est automatiquement servi sur `http://<host>:8000/` (même origine que l'API, pas de configuration CORS supplémentaire nécessaire côté client).

### Endpoints

| Méthode | Route | Description |
|---|---|---|
| GET | `/health` | `{"status": "ok", "model_loaded": bool}` |
| POST | `/predict` | Classifie une alerte Wazuh brute → `prediction`, `confidence`, `rule_id`, `rule_description`, `category`, `category_label`, `category_confidence`, `category_source` |
| POST | `/simulate` | Injecte une alerte de démo aléatoire (jeu de test embarqué) |
| GET | `/alerts/recent?limit=N` | Historique en mémoire des N dernières alertes traitées |
| GET | `/events/stream` | Flux Server-Sent Events (push temps réel) : events `alert` et `stats`, consommé par la Vue L1 du dashboard à la place du polling pour l'affichage des nouvelles alertes |
| GET | `/stats` | `total`, `true_positive`, `false_positive`, `tp_rate`, `alerts_per_min`, `avg_confidence`, `category_counts` |
| GET | `/model/importance` | Top 12 features par importance décroissante (modèle binaire) |
| GET | `/model/categories` | Taxonomie des catégories de menace (slug → libellé FR + couleur) et statut du modèle de catégorie |
| POST | `/ai/ask` | Assistant IA (Gemini 3.1 Flash Lite) qui répond à des questions en langage naturel sur l'état du SOC (stats + historique d'alertes serveur) |
| GET | `/sql/health` | Connectivité vers le SQL Server surveillé |
| GET | `/sql/sessions` | Connexions/sessions actives en direct (DMV `sys.dm_exec_sessions`) |
| GET | `/sql/users` | Utilisateurs actuellement connectés (agrégation des sessions actives) |
| GET | `/sql/permissions` | Rôles serveur + permissions explicites (niveau serveur SQL) |
| GET | `/sql/security-events` | Alertes Wazuh de l'agent SQL Server, déjà classifiées par le pipeline ML |
| GET | `/hygiene/health` | Connectivité vers l'API REST du manager Wazuh |
| GET | `/hygiene/agents` | Liste des agents Wazuh (id/nom/IP/OS/statut) |
| GET | `/hygiene/overview` | Score d'hygiène par agent, triés du plus au moins exposé |
| GET | `/hygiene/agent/{id}/packages` \| `/ports` \| `/processes` \| `/hotfixes` | Inventaire syscollector détaillé pour un agent |

### Vues du dashboard

Le dashboard (`dashboard/index.html`, monofichier HTML/CSS/JS sans dépendance externe, hors polices Google Fonts) expose 7 onglets, avec un push temps réel (`/events/stream`, voir ci-dessus) pour la Vue L1, une **palette de commandes** (`Ctrl`/`Cmd`+`K`) pour naviguer/agir sans souris, un système de toasts pour les alertes critiques entrantes, et un jeu d'icônes SVG inline (zéro dépendance) cohérent avec `dashboard/login.html`.

- **Vue L1** : flux d'alertes en direct (filtrable TP/FP/**SQL**, recherche règle/agent), badge de catégorie coloré sur chaque alerte (les alertes SQL ont une bordure et une couleur dédiées pour ressortir immédiatement), compteur dédié "Alertes SQL", compteurs clés, top agents, répartition par sévérité, export JSON. Les nouvelles alertes apparaissent instantanément (push SSE) avec une brève animation, et un toast signale les True Positive de sévérité ≥8 sans changer d'onglet.
- **Vue avancée** : statistiques agrégées, sparkline de volume, importance des features du modèle Random Forest binaire, répartition par catégorie de menace (session complète).
- **États SOC** : diagramme du cycle de vie d'une alerte, et couverture MITRE ATT&CK — les tactiques observées sont reliées entre elles par des liens quand elles apparaissent pour un même agent dans la fenêtre affichée (indice de chaîne d'attaque).
- **Réseau** : graphe de topologie force-directed (rendu en SVG pur, sans librairie externe) reliant les agents Wazuh aux IP sources/destination observées, coloré par ratio TP/FP et pondéré par volume ; et un classement des IP sources les plus à risque. Cliquer sur un nœud IP ou une ligne du classement filtre directement la vue L1 sur cette adresse.
- **SQL Server** : connexions actives, utilisateurs, rôles/permissions (lecture directe des DMV via un login dédié en lecture seule) et événements de sécurité corrélés (relit l'historique déjà classifié par le ML).
- **Hygiène IT** : vue personnalisée de l'inventaire syscollector Wazuh (logiciels installés, ports ouverts, processus, correctifs) par agent, avec un **score d'hygiène calculé par ce dashboard** (pas natif Wazuh) qui priorise visuellement les agents les plus exposés — voir section 13 pour la config et la méthodologie du score. Cliquer sur un agent dans le tableau ouvre son détail (5 sous-onglets : **Vulnérabilités** — liste lisible des failles détectées, sévérité/titre/détail, onglet ouvert par défaut — puis logiciels/ports/processus/correctifs, chacun filtrable).

L'assistant IA (panneau "Assistant SOC", 🤖 dans l'en-tête) répond désormais volontairement **court et direct** (1-3 phrases ou liste courte, pas d'intro/conclusion générique) — configuré via `system_instruction` + `max_output_tokens=350` côté `/ai/ask`, ce qui accélère aussi la génération.

**Synchronisation multi-fenêtres** : si le dashboard est ouvert dans plusieurs onglets/fenêtres du même navigateur (par ex. un mur d'écrans SOC avec une fenêtre par vue), chaque fenêtre interroge l'API indépendamment mais diffuse immédiatement les données reçues aux autres via `BroadcastChannel` — elles s'appliquent sans nouvel appel réseau, ce qui garde toutes les fenêtres visuellement synchronisées en quasi temps réel. Le thème clair/sombre est synchronisé de la même façon et persisté (`localStorage`). Une pastille dans l'en-tête ("Sync multi-fenêtres active") indique si la synchronisation est disponible ; en son absence (navigateur non compatible), chaque fenêtre continue de fonctionner normalement en autonome.

---

## 7. Branchement Wazuh (intégration directe)

### 7.1 Installer les fichiers d'intégration

```bash
sudo cp integrations/custom-ml-triage /var/ossec/integrations/
sudo cp integrations/custom-ml-triage.py /var/ossec/integrations/
sudo chmod 750 /var/ossec/integrations/custom-ml-triage
sudo chmod 750 /var/ossec/integrations/custom-ml-triage.py
sudo chown root:wazuh /var/ossec/integrations/custom-ml-triage*
```

### 7.2 Ajouter la configuration dans `ossec.conf` (manager)

```xml
<integration>
  <name>custom-ml-triage</name>
  <hook_url>http://172.17.1.120:8000/predict</hook_url>
  <alert_format>json</alert_format>
  <level>3</level>
</integration>
```

Le niveau ≥ 3 évite le bruit des alertes niveau 0-2 (ex. "log rotated"). Redémarrer le manager :

```bash
sudo systemctl restart wazuh-manager
```

Les résultats sont journalisés dans `/var/ossec/logs/integrations/custom-ml-triage.log` (rotation automatique, cohérent avec `custom-abuseipdb.py`).

### 7.3 Branchement n8n (complémentaire)

Importer `n8n/workflow_example.json` dans n8n. Ce workflow appelle `/predict` et ne transmet au flux SOAR existant (pfSense/Telegram/GLPI) que les alertes **True Positive avec confiance ≥ 0.6** — voir la note collée (`stickyNote`) dans le workflow pour le point de branchement exact. **Ne pas dupliquer** les branches pfSense/Telegram/GLPI déjà existantes.

---

## 8. Justification de l'algorithme : Random Forest

`sklearn.ensemble.RandomForestClassifier(class_weight="balanced")` a été retenu plutôt qu'un LLM ou un modèle de deep learning pour les raisons suivantes :

- **Données tabulaires structurées** : un ensemble d'arbres de décision est généralement plus performant qu'un réseau de neurones profond sur ce type de features (niveaux, comptages, flags booléens).
- **Latence en millisecondes**, critique pour un triage temps réel — un appel LLM par alerte serait trop lent et trop coûteux à l'échelle du volume d'alertes d'un SOC.
- **Interprétabilité** via `feature_importances_`, justifiable auprès d'un analyste SOC ou d'un auditeur (contrairement à une boîte noire de type LLM).
- **Robustesse** au bruit et aux features corrélées (fréquentes ici : `rule_level` et les flags de groupe sont partiellement redondants).
- **Cohérence avec la littérature publiée** sur l'intégration ML/Wazuh, qui rapporte des précisions de l'ordre de ~97 % avec Random Forest sur des tâches de triage similaires.

---

## 9. Catégorisation multi-classe des menaces (avec focus SQL)

En complément du triage binaire TP/FP, l'API classe chaque alerte dans une **catégorie de
menace/incident** — objectif : ne plus seulement dire "c'est réel ou pas", mais **quel type
d'attaque** c'est, avec une attention particulière portée aux menaces liées aux bases de
données (injection SQL, SQL Server) suite à un besoin exprimé sur ce point précis.

### 9.1 Taxonomie (`src/attack_category.py`)

| Catégorie | Libellé dashboard | Signal principal |
|---|---|---|
| `sql` | Injection SQL / Base de données | motif SQLi (9.2), groupes `mssql`/`mysql`/`postgresql`/`sql_injection`/`database`, mots-clés SQL Server/MySQL/PostgreSQL |
| `malware` | Malware / Intégrité fichier | groupes `malware`/`virustotal`/`rootcheck`, MITRE T1204/T1105/T1055 |
| `vulnerability` | Vulnérabilité / CVE | motif CVE explicite (`has_cve_pattern`), groupe `vulnerability-detector`, mots-clés "unpatched"/"exploit available" |
| `bruteforce` | Brute force / Authentification | groupes `sshd`/`authentication_failed`, MITRE T1110 |
| `ddos` | DDoS / Déni de service | groupes `ddos`/`dos`, MITRE T1498/T1499, mots-clés flood/déni de service — distingué du brute force via `distinct_srcip_5min` (rafale multi-IP vs mono-IP) |
| `recon` | Reconnaissance / Scan réseau | groupe `recon`, tactique MITRE "Reconnaissance" |
| `web` | Attaque Web (hors SQL) | groupe `web`, mots-clés XSS/RFI/LFI |
| `endpoint` | Windows / Endpoint | groupes `windows`/`powershell`/`sysmon` |
| `network` | Réseau / Pare-feu | groupe `firewall` |
| `other` | Autre / Non catégorisé | catégorie par défaut (bruit, log rotation, etc.) — voir `is_low_signal` (9.2) |

Ordre de priorité (le premier bloc qui matche l'emporte) : `sql` → `malware` → `vulnerability`
→ `bruteforce` → `ddos` → `recon` → `web` → `endpoint` → `network` → `other`. Une alerte qui
matche à la fois `web` et `sql` est classée `sql`, plus spécifique et actionnable.

Cette taxonomie est dérivée **heuristiquement** de champs que Wazuh fournit déjà sur chaque
alerte (`rule.groups`, MITRE) plutôt que d'un dataset externe labellisé par catégorie — aucun
des datasets Wazuh/HIDS publics disponibles ne fournit ce type de label (voir section 10).
Le modèle `rf_category_classifier.joblib` apprend ensuite à généraliser cette heuristique.

### 9.2 Détection d'injection SQL (`has_sqli_pattern`, `sqli_keyword_count`)

Deux features supplémentaires scannent le texte disponible de l'alerte (`rule.description` +
`full_log` + valeurs du bloc `data.*`, voir `parse_wazuh.py::text_blob`) à la recherche de
signatures d'injection SQL (UNION SELECT, `' OR '1'='1`, `xp_cmdshell`, `information_schema`,
`SLEEP()`/`BENCHMARK()`, encodage URL `%27`/`%20union%20`, etc.).

Le regex n'a pas été écrit "à l'instinct" : il a été **validé empiriquement** sur un vrai
dataset labellisé, [`firdhokk/autotrain-data-sql-injection`](https://huggingface.co/datasets/firdhokk/autotrain-data-sql-injection)
(HuggingFace, 50 568 requêtes SQL malveillantes/légitimes) — **recall = 0.95, precision =
0.67, F1 = 0.78** sur ce jeu de test. Ce dataset n'a **pas** été fusionné tel quel dans
`training_data.csv` : son schéma (requête SQL brute + label malveillant/légitime) est
incompatible avec celui des alertes Wazuh (rule_level/groupes/MITRE) — il a servi à calibrer
et valider le motif, pas à générer des lignes d'entraînement synthétiques.

Le recall est volontairement privilégié sur la précision : c'est un signal parmi d'autres
pour le Random Forest (pas un blocage automatique), donc rater une injection coûte plus cher
qu'un faux positif occasionnel.

### 9.2bis Autres features renforçant la détection / la réduction du bruit

- **`has_cve_pattern` / `cve_count`** : détecte un identifiant CVE explicite (`CVE-\d{4}-\d{4,7}`)
  dans le texte de l'alerte — signal principal de la catégorie `vulnerability`.
- **`distinct_srcip_5min`** : nombre d'IP sources distinctes ayant déclenché la même règle sur
  une fenêtre glissante de 5 min. Complète `rule_freq_5min` pour distinguer un brute force
  classique (peu d'IP, répétées) d'un DDoS distribué (beaucoup d'IP différentes, rafale brève).
- **`is_low_signal`** : vaut 1 si `rule_level <= 2` (informationnel/routine — rotation de logs,
  connexion/déconnexion d'agent, etc.). Aide le modèle binaire à trancher franchement ces cas
  routiniers plutôt que de se reposer uniquement sur `rule_level` en continu, ce qui réduit le
  nombre d'alertes inutiles remontées aux analystes.

### 9.3 Visualisation SQL dans le dashboard

- Couleur dédiée (`--sql`, rose/magenta) distincte de toutes les autres catégories, pour que
  les incidents SQL ressortent immédiatement visuellement, y compris dans un flux chargé.
- Compteur "Alertes SQL" dédié en Vue L1 (comptage session complète, pas juste la fenêtre affichée).
- Chip de filtre "SQL" dans le flux d'alertes.
- Bordure gauche colorée sur les alertes de catégorie SQL dans le flux (Vue L1 et onglet SQL Server).
- Panneau "Répartition par catégorie de menace" en Vue avancée.
- Section "Catégorie" dans le modal de détail d'une alerte (libellé + confiance du modèle).

---

## 10. Limites du dataset d'entraînement

Le dataset `kholil-lil/wazuh-alerts` (HuggingFace, 738 alertes labellisées TP/FP) présente des limites connues, à garder en tête avant toute mise en production :

- **Fort déséquilibre / répétition de patterns** : les règles firewall (`rule.id 651`) et log rotation (`rule.id 591`) sont très sur-représentées dans le dataset.
- **Méthodologie de labellisation non documentée** : on ne sait pas précisément comment les labels TP/FP ont été attribués par l'auteur du dataset.
- **Faible adoption** : seulement 64 téléchargements au moment de la rédaction → les labels doivent être considérés avec **prudence**, pas comme une vérité terrain validée.
- **Couverture incomplète** : le dataset ne couvre pas nécessairement les événements **Windows/WMI/Sysmon** spécifiques au réseau cible de ce projet (agents Windows avec monitoring étendu — Sysmon, PowerShell, Defender, RDP, AppLocker).
- **Catégories de menace absentes** : une fois passé par la taxonomie de la section 9, ce dataset ne contient **aucun exemple** des catégories `malware`, `recon`, `endpoint`, `network`, `vulnerability`, `ddos` — comblé par les alertes synthétiques de `src/seed_alerts.py` (152 alertes, voir section 9), mais un volume encore limité (12 à 36 exemples selon la catégorie). Les métriques rapportées par `train_category_model.py` sur ces catégories minoritaires sont donc à prendre avec beaucoup de prudence.

**Recommandation** : avant tout déploiement en production, ré-entraîner ou compléter le modèle avec des alertes réellement labellisées par les analystes du SOC cible, notamment pour les événements Windows et pour consolider les catégories minoritaires.

**Limite de la source ruleset officiel Wazuh (section 5.1bis)** : contrairement à kholil-lil/wazuh-alerts, ce ne sont pas des *alertes* avec un verdict TP/FP donné par un humain, mais des *définitions de règles* dont le label est dérivé par une heuristique (niveau/groupes/MITRE, voir `src/fetch_wazuh_ruleset.py::_label_rule`) volontairement conservatrice (exclut plutôt que devine en cas d'ambiguïté). C'est une base d'entraînement solide sur la diversité `rule_id`/`rule_level`/`groupes` réels, mais — comme les alertes synthétiques de `seed_alerts.py` — **pas un substitut à des alertes réellement vécues et confirmées par un analyste** du SOC cible.

### Dataset alternatif évalué : CAM-LDS (écarté pour l'instant)

**CAM-LDS** (Zenodo/AIT, [zenodo.org/records/18390561](https://zenodo.org/records/18390561)) — 81 techniques MITRE ATT&CK, 7 scénarios d'attaque réels simulés (34 runs), avec labels de vérité terrain mappés à MITRE ATT&CK. **Évalué dans cette version** (Zenodo est accessible depuis l'environnement de développement) mais **écarté** pour deux raisons concrètes :

1. **Schéma incompatible** : ce sont des logs bruts (Apache access log, Linux auditd), pas des alertes Wazuh déjà structurées — l'intégrer demanderait de construire un pipeline de parsing dédié pour mapper ces logs vers `rule.id`/`rule.level`/`rule.groups`, un chantier à part entière.
2. **Cible Linux, réseau majoritairement Windows** : le réseau surveillé ici est essentiellement Windows/SQL Server (voir section 3) ; les scénarios CAM-LDS (auditd, Apache) collent moins bien que des sources Windows/Sysmon.

À réévaluer si un pipeline auditd/Apache est ajouté au périmètre du SOC surveillé.

---

## 11. Roadmap

- [ ] Ré-entraîner sur des alertes réelles du SOC cible (notamment événements Windows/Sysmon)
- [x] Évaluer le dataset CAM-LDS (Zenodo/AIT) — évalué, écarté pour l'instant (voir section 10)
- [x] Évaluer des datasets HuggingFace additionnels (`ruf0x`/`wy777`/`sereniq`/`event_correlation_wazuh`) — tous écartés (doublons ou labels non fiables), remplacés par l'extraction du ruleset officiel Wazuh (section 5.1bis)
- [ ] Remplacer les alertes synthétiques de `src/seed_alerts.py`/`fetch_wazuh_ruleset.py` par de vraies alertes labellisées par un analyste dès qu'elles sont disponibles (le label heuristique reste une approximation, voir section 10)
- [ ] Historisation des prédictions dans Postgres (au lieu du deque en mémoire) pour survivre aux redémarrages de l'API
- [ ] Ajout d'un endpoint `/feedback` permettant à un analyste de corriger un verdict ou une catégorie (boucle de ré-entraînement)
- [ ] Migration de l'API vers une VM Linux dédiée (ou la VM Wazuh) pour la production
- [ ] Ajout d'un scoring de risque composite combinant le verdict ML avec les résultats AbuseIPDB/VirusTotal existants
- [ ] Tests automatisés (pytest) sur `parse_wazuh.py`, `feature_engineering.py` et `attack_category.py`

---

## 12. Structure du projet

```
soc-ml-classifier/
├── README.md
├── requirements.txt
├── .env.example                 # gabarit des variables d'environnement (GEMINI_API_KEY, SQLSRV_*)
├── data/
│   ├── raw/
│   │   ├── alerts.json          # alertes Wazuh brutes (predict_batch.py)
│   │   ├── sql_injection/       # dataset HF utilisé pour valider le motif SQLi (section 9.2)
│   │   ├── wazuh_ruleset/       # cache XML du ruleset officiel Wazuh (fetch_wazuh_ruleset.py)
│   │   └── wazuh_ruleset_rules.json  # règles extraites + labellisées (voir section 5.1bis)
│   ├── processed/               # CSV de features labellisées, prédictions
│   └── auth.db                  # base SQLite admin (comptes, sessions, historique) — créée au 1er démarrage
├── models/                      # modèles entraînés (.joblib)
│   ├── rf_classifier.joblib          # triage binaire TP/FP
│   └── rf_category_classifier.joblib # catégorie de menace (multi-classe)
├── src/
│   ├── __init__.py
│   ├── parse_wazuh.py            # parsing des alertes brutes
│   ├── feature_engineering.py    # construction des features ML (dont signal SQLi)
│   ├── attack_category.py        # taxonomie + dérivation heuristique de la catégorie
│   ├── seed_alerts.py            # alertes synthétiques pour combler les catégories minoritaires
│   ├── fetch_wazuh_ruleset.py    # extraction + labellisation heuristique du ruleset officiel Wazuh (section 5.1bis)
│   ├── convert_hf_dataset.py     # conversion du dataset HuggingFace + fusion seed_alerts + ruleset
│   ├── train_model.py            # entraînement du Random Forest binaire
│   ├── train_category_model.py   # entraînement du Random Forest multi-classe (catégorie)
│   ├── predict_batch.py          # inférence en masse hors-ligne
│   ├── sql_monitor.py            # connecteur DMV SQL Server (endpoints /sql/*)
│   ├── wazuh_inventory.py        # connecteur API REST Wazuh + score d'hygiène (endpoints /hygiene/*)
│   ├── security.py               # hachage mdp (scrypt), jetons de session, codes email
│   ├── auth_db.py                # base SQLite admin (comptes, codes, sessions, historique, throttle)
│   ├── mailer.py                 # envoi des emails de vérification/OTP (SMTP)
│   ├── auth.py                   # endpoints /auth/* (inscription, login 2FA, session, historique)
│   └── api.py                    # API FastAPI (/predict, /simulate, /model/categories, etc.)
├── dashboard/
│   ├── index.html               # dashboard SOC (L1, avancée, États SOC, Réseau, SQL Server, Hygiène IT)
│   └── login.html                # page de connexion / inscription admin (accessible sans session)
├── integrations/
│   ├── custom-ml-triage         # wrapper shell (intégration Wazuh directe)
│   └── custom-ml-triage.py      # script Python de l'intégration
└── n8n/
    └── workflow_example.json    # workflow n8n minimal, complémentaire au SOAR existant
```

---

## 13. Hygiène IT — configuration de l'API Wazuh

L'onglet dashboard "Hygiène IT" (`/hygiene/*`) est **différent** du webhook `/predict` : au lieu de recevoir des alertes, l'API **interroge activement** l'API REST du manager Wazuh (port `55000` par défaut) pour lire l'inventaire syscollector (logiciels, ports, processus, correctifs) de chaque agent.

### 13.1 Créer un utilisateur API Wazuh dédié en lecture seule

Ne jamais utiliser le compte admin par défaut de l'API Wazuh pour ce dashboard. Depuis le Wazuh Dashboard : **Server management → Users** (ou **Roles**), créer :

- un **rôle** avec uniquement les permissions `agent:read` et `syscollector:read` (RBAC Wazuh) ;
- un **utilisateur** dédié (ex. `soc_hygiene_ro`) rattaché à ce rôle.

### 13.2 Remplir `.env`

```env
WAZUH_API_HOST=10.212.2.170
WAZUH_API_PORT=55000
WAZUH_API_USER=soc_hygiene_ro
WAZUH_API_PASSWORD=le-mot-de-passe-choisi
WAZUH_API_VERIFY_SSL=no
```

`WAZUH_API_VERIFY_SSL=no` par défaut car le manager utilise un certificat TLS auto-signé sur l'API REST (cas standard en interne) ; passer à `yes` si un certificat valide a été installé.

### 13.3 Score d'hygiène

Calculé **côté ce dashboard** (`src/wazuh_inventory.py::compute_hygiene_score`), pas un score officiel Wazuh, volontairement simple et transparent (pas de base CVE embarquée) :

| Facteur | Impact |
|---|---|
| Port sensible exposé en écoute (RDP, SMB, bases de données, Telnet, VNC, WinRM, SNMP, NFS, r-services…) | -10 pts par port distinct (plafonné à -50) |
| Port en écoute supplémentaire au-delà de 5 (surface d'exposition générale) | -5 pts par port (plafonné à -20) |
| Agent Windows sans aucun correctif recensé par syscollector | -15 pts (signal faible — à vérifier manuellement, pas une certitude) |
| OS en fin de support connue (Windows XP/Vista/7/8, Server 2003/2008/2012, CentOS 6/7/8, Debian 8/9, Ubuntu 16.04/18.04…) | -25 pts (plus aucun correctif de sécurité fournisseur possible) |

La liste des ports sensibles est dans `SENSITIVE_PORTS` et celle des marqueurs de fin de support dans `_EOL_OS_MARKERS` (toutes deux dans `src/wazuh_inventory.py`), statique et à réviser périodiquement — pas un flux CVE/EOL en direct.

En plus du score agrégé, `compute_hygiene_score` retourne un tableau `findings` (sévérité `high`/`medium`/`low`, titre, détail) : une liste lisible des failles concrètes par agent, affichée dans l'onglet **Vulnérabilités** du détail agent (dashboard, onglet Hygiène IT → cliquer une ligne du tableau) au lieu d'un simple chiffre.

`/hygiene/overview` fait 1 + 2 appels API par agent (ports + hotfixes) : adapté à un petit/moyen parc d'agents, pas pensé pour scaler à des centaines d'agents sans mise en cache.

---

## 14. Authentification admin & sécurité du dashboard

Le dashboard (`dashboard/index.html`) et la quasi-totalité des endpoints de l'API (`/stats`, `/alerts/recent`, `/sql/*`, `/hygiene/*`, `/ai/ask`, `/model/*`) sont **inaccessibles sans session admin valide**. Seuls restent publics : `/login.html` (page de connexion elle-même), `/auth/*` (forcément, pour pouvoir se connecter), `/health` (supervision) et les webhooks machine-à-machine `/predict` / `/simulate` (appelés directement par le manager Wazuh et par n8n, sans navigateur — voir section 7).

### 14.1 Principe

Authentification en deux facteurs, sans dépendance externe (tout est stdlib Python : `hashlib`, `smtplib`, `sqlite3`) :

1. **Inscription** (`/auth/register`) : nécessite un mot de passe **et** la clé partagée `ADMIN_SETUP_KEY` (voir `.env.example`) — empêche quiconque atteignant le formulaire de créer un compte admin sans autorisation. Un code à 6 chiffres est envoyé par email pour activer le compte.
2. **Connexion** (`/auth/login` puis `/auth/login/verify`) : mot de passe, **puis** un second code à 6 chiffres envoyé par email (OTP), avant l'ouverture de la session. Un attaquant qui devine/vole le mot de passe ne peut pas se connecter sans accès à la boîte mail du compte.
3. **Session** : cookie opaque `HttpOnly` (inaccessible en JavaScript, donc pas volable via XSS), `SameSite=Lax`. Seul son hash SHA-256 est stocké côté serveur (`data/auth.db`) — un vol de la base ne permet pas de rejouer une session existante.

### 14.2 Configuration requise (`.env`)

```env
ADMIN_SETUP_KEY=une-valeur-forte-generee-une-fois   # ex: openssl rand -hex 24
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=...
SMTP_PASSWORD=...
```

Sans `SMTP_HOST`, aucun email n'est réellement envoyé : le code est seulement **loggé côté serveur** (mode dev). Un avertissement s'affiche au démarrage de l'API tant que ce n'est pas configuré — ne jamais laisser cet état en production.

### 14.3 Créer le premier compte admin

1. Démarrer l'API (`uvicorn src.api:app ...`), configurer `ADMIN_SETUP_KEY` et `SMTP_*` dans `.env`.
2. Ouvrir `http://<host>:8000/login.html`, onglet **Créer un compte**, renseigner nom/email/mot de passe (≥ 10 caractères, au moins une lettre et un chiffre) + la clé d'installation.
3. Saisir le code reçu par email (ou loggé côté serveur si SMTP non configuré) pour activer le compte.
4. Se connecter normalement (mot de passe puis code OTP).

Les comptes suivants se créent de la même façon (chacun nécessite la clé d'installation).

### 14.4 Historique des connexions

`GET /auth/history` (authentifié) retourne, pour chaque tentative de connexion : email, nom, adresse IP, **nom de machine**, user-agent, succès/échec et horodatage. Le nom de machine est résolu **côté serveur par DNS inverse** à partir de l'IP source (`socket.gethostbyaddr`) — un navigateur ne permettant pas de lire le hostname OS du poste client pour des raisons de vie privée, c'est la seule source fiable côté serveur. Cette résolution fonctionne correctement sur un LAN interne avec DNS/AD déjà en place (cas de ce SOC, réseau `172.17.1.0/24`) ; elle retourne `null` si l'IP n'est pas résolvable (ex: accès depuis l'extérieur du LAN sans PTR configuré).

### 14.5 Protections mises en place

| Risque | Protection |
|---|---|
| Injection SQL | `src/auth_db.py` n'utilise **que** des requêtes paramétrées (`?`), jamais de concaténation de chaîne avec une valeur utilisateur. Les requêtes vers le SQL Server surveillé (`src/sql_monitor.py`) sont statiques, sans aucune entrée utilisateur injectée. |
| Brute-force sur mot de passe / code OTP | Verrouillage temporaire (15 min) après 5 échecs, par couple **email** et **IP** séparément (`login_throttle` en base) ; codes OTP limités à 5 tentatives puis invalidés. |
| Mots de passe en clair | Hachés avec sel aléatoire par compte (`scrypt`, `src/security.py`) — jamais stockés ni loggés en clair. |
| Vol de session | Cookie `HttpOnly` + `SameSite=Lax` ; seul le hash SHA-256 du jeton est stocké côté serveur ; expiration configurable (`ADMIN_SESSION_TTL_HOURS`, défaut 8h) ; révocable via `/auth/logout`. |
| Accès direct à une page/donnée sans authentification | Middleware global (`require_admin_session` dans `src/api.py`) qui bloque **toute** requête sans session valide (redirection vers `/login.html` pour un navigateur, `401` JSON pour un appel programmatique), à l'exception des chemins publics listés en introduction de cette section. |
| CORS trop permissif | `allow_origins` n'est plus `*` (incompatible de toute façon avec les cookies de session) mais piloté par `CORS_ALLOWED_ORIGINS` (vide par défaut — le dashboard étant servi en même origine que l'API, aucune origine cross-origin n'est nécessaire). |
| Énumération de comptes | `/auth/resend-code` répond de façon identique que l'email existe ou non. |
| Clickjacking / MIME-sniffing | En-têtes `X-Frame-Options: DENY` et `X-Content-Type-Options: nosniff` ajoutés à toutes les réponses. |

### 14.6 Limite connue

`ADMIN_COOKIE_SECURE=no` par défaut car ce projet tourne en HTTP simple sur le LAN interne (voir section 4.1). Si l'API est un jour exposée derrière HTTPS (recommandé pour tout accès hors LAN de confiance), passer `ADMIN_COOKIE_SECURE=yes` pour que le cookie de session ne soit jamais transmis en clair.

---
