<div align="center">

<img src="../../assets/logo.svg" alt="Logo DualVerify-Sentinel — hexagone de vérification avec double coche, nœuds réseau et bande de balayage" width="110">

# DUALVERIFY-SENTINEL

### ENGINEERED FOR TRUST.
### BUILT FOR CONTROL.

**Moteur de validation de sécurité piloté par politiques**

Exécution déterministe. Limites d'autorisation explicites. Preuves de sécurité auditables.

`zyh798-cell` / `DualVerify-Sentinel` · MIT

<img src="../../assets/banner.gif" alt="DualVerify-Sentinel — bannière animée : révélation du titre en pixels, ligne de balayage et flux de données" width="720">

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Verified-085041)](#4-prérequis)
[![Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-0C447C)](#4-prérequis)
[![Use](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-BA7517)](#8-autorisation-et-sécurité)
[![Status](https://img.shields.io/badge/Status-Gen--1-0C447C)](#11-état-du-projet)

[English](../../README.md) · [中文](README.zh-CN.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · [Español](README.es.md) · **Français**

[Autorisation](#porte-dautorisation) · [Moteur de politiques](#moteur-de-politiques-et-échelle-de-risque) · [TaskGraph](#orchestration-taskgraph) · [Adaptateurs](#adaptateurs-doutils-nuclei--bandit) · [Audit](#journal-daudit) · [Rapports](#rapports-structurés) · [Installation](#5-installation) · [Sécurité](../../SECURITY.md)

> ⚠️ **TESTS DE SÉCURITÉ AUTORISÉS UNIQUEMENT**

</div>

---

## 1. Qu'est-ce que c'est ?

DualVerify-Sentinel est un **moteur de validation de sécurité fondé sur des
règles** (explicitement **NON piloté par modèle**) : chaque étape d'exécution est
vérifiée par rapport à un périmètre d'autorisation lisible par machine, consignée
dans un journal d'audit à chaîne de hachage infalsifiable, et fonctionne en
**fail-closed** — une autorisation absente, corrompue ou expirée signifie un
*refus*, jamais une vérification ignorée.

C'est une couche d'ingénierie de sécurité : une porte d'autorisation associée à
un moteur d'exécution déterministe. La couche planification/décision de Gen-1 est
volontairement déterministe, et non pilotée par modèle.

## 2. Ce qu'il sait faire

Gen-1 s'exécute comme un pipeline déterministe unique — chaque capacité ci-dessous est appliquée par des chemins de code explicites, et non par un jugement de modèle.

### Porte d'autorisation

Le JSON de périmètre lisible par machine est validé dans un **sous-processus isolé** ; absent/corrompu/expiré → REFUSED (code de sortie 2). Aucune voie de contournement n'existe. Les adaptateurs n'acceptent que les tickets émis par le moteur de politiques ; le hachage du périmètre, le mode, la cible et la fenêtre sont **revérifiés de manière indépendante à l'exécution**.

### Moteur de politiques et échelle de risque

Cinq modes à plafond de risque croissant (R0–R4, voir [Utilisation de base](#6-utilisation-de-base)). Règles explicites P0–P8 : tout refus/abandon/échec arrête la boucle ; les cibles ne sont **jamais** élargies.

### Orchestration TaskGraph

Machine à états avec budgets stricts (max 32 nœuds, profondeur de spawn 2, 8 spawns) ; les spawns dynamiques exigent un parent COMPLETED.

### Adaptateurs d'outils (nuclei / bandit)

`nuclei` (scan de modèles) et `bandit` (analyse statique) — ignorés proprement (SKIPPED) avec un rapport de prévol si non installés. Exécution sûre : chaîne de 12 vérifications par étape ; aucune technique destructive, aucune persistance, aucune construction de payload, aucune exfiltration des données découvertes.

### Journal d'audit

Chaîne de hachage en ajout seul (`seq`/`prev`/`h`, SHA-256) ; détection de falsification/réordonnancement ; un échec d'audit termine avec le code 3 au lieu de se déguiser en résultat normal.

### Rapports structurés

Les constatations sont enregistrées telles quelles ; les sorties non vérifiées ne sont jamais étiquetées vulnérabilités confirmées ; les limitations connues sont listées dans chaque rapport.

### Adaptateurs supplémentaires et schéma unifié des constatations

Deux adaptateurs optionnels supplémentaires sont implémentés dans
`vuln_hunter/adapters_ext/` : `gitleaks` (détection de secrets, étape
`s4-gitleaks`) et `semgrep` (analyse statique, **fichiers de règles locaux
uniquement**, étape `s5-semgrep`). Tous deux sont planifiés sous condition pour
les arborescences de sources de portée « système de fichiers », nécessitent leurs
propres binaires et ne récupèrent jamais de règles par le réseau. Toutes les
sorties d'adaptateur sont normalisées via le schéma unifié des constatations
(`findings.py`), qui valide la sévérité et la forme de l'enregistrement avant
qu'une constatation n'atteigne un rapport.

> Ces adaptateurs sont **implémentés en code**, mais la vérification de bout en
> bout avec les outils réels **n'est pas terminée**. La présence d'un adaptateur
> n'est pas la preuve d'une exécution vérifiée — voir section 11.

## 3. Cas d'usage

- Valider vos propres cibles de laboratoire et les hôtes explicitement autorisés.
- Exécuter des vérifications de sécurité répétables, productrices de preuves et
  dotées d'une piste d'audit complète.
- Comme couche de base pour construire des pipelines de vérification de niveau
  supérieur.

## 4. Prérequis

| Prérequis | Détail |
|---|---|
| Python | >= 3.10 (testé uniquement sur 3.13.14) |
| Dépendances tierces | **Aucune** — bibliothèque standard uniquement |
| Système d'exploitation | Windows **Vérifié** ; Linux/macOS **Pas encore vérifié** |
| Outils externes (optionnels) | `nuclei`, `bandit`, `gitleaks`, `semgrep` — adaptateurs implémentés ; ignorés s'ils sont absents ; exécutions avec outils réels non encore vérifiées |

## 5. Installation

```bash
git clone https://github.com/zyh798-cell/DualVerify-Sentinel.git
cd DualVerify-Sentinel

python -m venv .venv
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Windows (CMD):
.venv\Scripts\activate.bat
# Linux/macOS :
source .venv/bin/activate

pip install .
```

L'installation éditable `pip install -e .` est également disponible pour le
développement.

## 6. Utilisation de base

**Étape 1 — valider le fichier de périmètre (toujours en premier) :**

```bash
dvs gate-check scripts/example-scope.json
# code de sortie 0 = périmètre valide · 1 = refusé
```

**Étape 2 — lancer une validation :**

```bash
dvs run --scope scripts/example-scope.json --mode safe_scan --target 127.0.0.1:8080
# ou : python -m vuln_hunter run --scope ... --mode ... --target ...
```

Modes (plafond de risque croissant) : `passive` → `safe_scan` →
`vuln_validation` → `attack_simulation` → `high_risk` (R0–R4). `nuclei` n'est
invoqué qu'à partir de R2.

Codes de sortie : `0` toutes les étapes COMPLETED · `1` terminé avec
échecs/refus · `2` refus au niveau porte/politique (rien n'a été exécuté) ·
`3` **échec d'audit** (journal non inscriptible/non vérifiable — les résultats ne
sont pas certifiés).

`scripts/example-scope.json` est un exemple fictif — **ce n'est pas une
autorisation réelle**.

## 7. Sémantique du périmètre

- Les entrées sont comparées par **égalité du nom d'hôte analysé** (une entrée
  sans port correspond à n'importe quel port de cet hôte). **Les plages CIDR ne
  sont PAS prises en charge** — utilisez des entrées `hôte` ou `hôte:port`.
- La fenêtre d'autorisation est **revérifiée à chaque étape d'exécution** ; une
  expiration en cours d'exécution interrompt les étapes suivantes.
- Le hachage du contenu du périmètre est lié à chaque ticket ; modifier le
  périmètre invalide les tickets en attente.
- Les étapes à périmètre de système de fichiers ignorent uniquement la
  vérification du périmètre réseau ; toutes les autres vérifications de
  politique s'appliquent normalement.

## 8. Autorisation et sécurité

> ⚠️ **N'utilisez cet outil QUE contre des systèmes que vous possédez ou
> exploitez, des cibles de laboratoire locales, ou des hôtes pour lesquels vous
> détenez une autorisation écrite explicite du propriétaire.** Les
> configurations non autorisées, hors périmètre, à fenêtre expirée ou corrompues
> sont refusées (fail-closed). Aucun chemin de code n'ignore l'autorisation.

Le périmètre d'exemple fourni est fictif. Les missions réelles exigent un
enregistrement d'autorisation réel et lisible par machine — conservez-le hors de
ce dépôt.

## 9. Le durcissement d'API n'est PAS un bac à sable

Le frozen dataclass de RunTicket et son registre privé constituent un
**durcissement d'API**, pas un bac à sable — du code hostile intra-processus peut
contourner toute vérification au niveau Python. Une isolation forte nécessite des
mesures au niveau du processus (non implémentées). La CLI est le seul point
d'entrée pris en charge.

## 10. Limitations connues

1. **Pas de bac à sable intra-processus** — voir section 9.
2. **Windows d'abord** — le chemin de dépassement de délai sous Windows effectue
   un nettoyage d'arbre de processus équipé sur le terrain (`taskkill /T /F`
   s'exécute avant la destruction de la racine, tous les résultats consignés) ;
   il est vérifié par un exercice contrôlé d'arbre à trois niveaux mais
   **n'est pas une garantie absolue** — pas de vérification des résidus à
   l'exécution, `rc=0` ne prouve pas que tout l'arbre a été nettoyé, et les
   formes réelles des descendants de Nuclei ne sont pas vérifiées. Sur les
   plateformes non Windows, la destruction d'arbre est ignorée (racine
   uniquement). Le chemin de secours de nuclei suppose une disposition locale
   `~/Tools/nuclei/`.
3. **Aucune promesse d'exactitude de détection** — la sortie des outils est
   enregistrée telle quelle ; les résultats non vérifiés ne sont jamais marqués
   comme vulnérabilités confirmées.
4. **Linux/macOS non vérifié** — la CI ne couvre pas les plateformes non Windows.
5. **Troncature de la fin du journal** — détectable uniquement si une ancre head
   externe a été sauvegardée ; les ancres du rapport servent uniquement aux
   contrôles de cohérence.
6. **Le planificateur Gen-1 est un modèle statique** — la planification est
   déterministe, ni pilotée par modèle ni adaptative.

## 11. État du projet

- **Gen-1 est implémenté** : la porte d'autorisation, le moteur de politiques
  (R0–R4), TaskGraph, le journal d'audit, les rapports structurés, le schéma
  unifié des constatations et les adaptateurs `nuclei` / `bandit` / `gitleaks` /
  `semgrep` existent en tant que chemins de code. Les suites de tests se trouvent
  sous `tests/` — exécutez-les et fiez-vous à la sortie réelle ; ce dépôt ne formule
  aucune affirmation anticipée de « tout au vert » ni de nombre de vérifications
  réussies.
- **Non vérifié / non implémenté** : la vérification de bout en bout avec les outils
  réels n'est pas terminée ; la Phase B n'a pas été exécutée ; les éléments W1-03,
  W1-04, W1-06 et CR-06 ainsi que la base de référence Semgrep réelle restent
  ouverts ; la vérification Linux/macOS et le CI ne sont pas en place ; Gen-2 n'est
  pas implémenté dans ce dépôt. La présence du code d'un adaptateur n'est pas la
  preuve d'une exécution vérifiée, et le durcissement d'API n'est pas un bac à sable
  au niveau du système d'exploitation (voir section 9).
- Le packaging doit être jugé sur une construction de cette version ; les anciens
  artefacts de construction ne constituent pas une preuve pour la version actuelle.

## 12. Licence et retours

- **Licence** : MIT — voir [LICENSE](../../LICENSE).
- **Politique de sécurité** : voir [SECURITY.md](../../SECURITY.md).
- **Contribuer** : voir [CONTRIBUTING.md](../../CONTRIBUTING.md).
- Les issues et pull requests sont bienvenues. Pour les signalements liés à la
  sécurité, suivez les consignes de SECURITY.md plutôt que d'ouvrir une issue
  publique.

---

<div align="center">
<sub>DualVerify-Sentinel · Deterministic Security Validation Engine · MIT © 2026 zyh798-cell</sub>
</div>
