<div align="center">

# DualVerify-Sentinel

**Moteur de validation de sécurité déterministe à contrôle d'autorisation.**

`zyh798-cell` / `DualVerify-Sentinel` · Gen-1 Stable · MIT

<img src="../../assets/banner.gif" alt="DualVerify-Sentinel — bannière animée style pixel où le titre apparaît lettre par lettre avec une ligne de balayage et des flux de données" width="720">

**DualVerify-Sentinel — Deterministic Security Validation Engine**
⚠️ **TESTS DE SÉCURITÉ AUTORISÉS UNIQUEMENT**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Verified-0078D6?logo=windows&logoColor=white)](#4-pr%C3%A9requis)
[![Platform](https://img.shields.io/badge/Platform-Linux%2FmacOS%20Unverified-6b7280)](#10-limitations-connues)
[![Checks](https://img.shields.io/badge/Offline%20Checks-427%2B%20Passing-2EA043)](#11-%C3%A9tat-du-projet)
[![Status](https://img.shields.io/badge/Status-Gen--1%20Stable-8250DF)](#11-%C3%A9tat-du-projet)

[English](../../README.md) · [中文](README.zh-CN.md) · [日本語](README.ja.md) · [Español](README.es.md) · **Français**

</div>

---

## 1. Qu'est-ce que c'est ?

DualVerify-Sentinel est un **moteur de validation de sécurité fondé sur des
règles** (explicitement **NON piloté par modèle**) : chaque étape d'exécution est
vérifiée par rapport à un périmètre d'autorisation lisible par machine, consignée
dans un journal d'audit à chaîne de hachage infalsifiable, et fonctionne en
**fail-closed** — une autorisation absente, corrompue ou expirée signifie un
*refus*, jamais une vérification ignorée.

C'est la couche d'ingénierie de sécurité (porte d'autorisation + moteur
d'exécution fiable) d'une architecture de vérification de nouvelle génération
planifiée. La couche planification/décision de Gen-1 est volontairement
déterministe.

## 2. Ce qu'il sait faire

| Capacité | Fonctionnement |
|---|---|
| Porte d'autorisation | Le JSON de périmètre lisible par machine est validé dans un **sous-processus isolé** ; absent/corrompu/expiré → REFUSED (code de sortie 2). Aucune voie de contournement n'existe. |
| Tickets d'exécution | Les adaptateurs n'acceptent que les tickets émis par le moteur de politiques ; hachage du périmètre, mode, cible et fenêtre sont **revérifiés de manière indépendante à l'exécution**. |
| Exécution sûre | Chaîne de 12 vérifications par étape ; aucune technique destructive, aucune persistance, aucune construction de payload, aucune exfiltration des données découvertes. |
| Journal d'audit | Chaîne de hachage en ajout seul (`seq`/`prev`/`h`, SHA-256) ; détection de falsification/réordonnancement ; un échec d'audit termine avec le code 3 au lieu de se déguiser en résultat normal. |
| Boucle de décision déterministe | Règles explicites P0–P8 : tout refus/abandon/échec arrête la boucle ; les cibles ne sont **jamais** élargies. |
| Graphe de tâches | Machine à états avec budgets stricts (max 32 nœuds, profondeur de spawn 2, 8 spawns) ; les spawns dynamiques exigent un parent COMPLETED. |
| Adaptateurs d'outils optionnels | `nuclei` (scan de modèles) et `bandit` (analyse statique) — ignorés proprement (SKIPPED) avec un rapport de prévol si non installés. |
| Rapports honnêtes | Les constatations sont enregistrées telles quelles ; les sorties non vérifiées ne sont jamais étiquetées vulnérabilités confirmées ; les limitations connues sont listées dans chaque rapport. |

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
| Outils externes (optionnels) | `nuclei`, `bandit` — ignorés s'ils sont absents |

## 5. Installation

```bash
git clone https://github.com/zyh798-cell/DualVerify-Sentinel.git
cd DualVerify-Sentinel

python -m venv .venv
# Windows :
.venv\Scripts\activate
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
2. **Windows d'abord** — la suppression par délai d'attente ne suit pas les
   processus petits-enfants sous Windows ; le chemin de secours de nuclei suppose
   une disposition locale `~/Tools/nuclei/`.
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

- **Gen-1 est stable** : 18 suites de tests hors ligne, plus de 427 vérifications
  réussies en local (Windows, Python 3.13.14). Packaging testé par des
  constructions wheel/sdist.
- Une **architecture Gen-2** (un dépôt futur et séparé) est planifiée avec
  une séparation proposition/adjudication. Le travail Gen-2 n'aura pas lieu dans
  ce dépôt.
- Les commandes de test complètes figurent dans les suites sous `tests/` —
  exécutez-les et fiez-vous aux résultats réels ; ce dépôt ne formule aucune
  affirmation anticipée de « tout au vert ».

## 12. Licence et retours

- **Licence** : MIT — voir [LICENSE](../../LICENSE).
- **Politique de sécurité** : voir [SECURITY.md](../../SECURITY.md).
- Les issues et pull requests sont bienvenues. Pour les signalements liés à la
  sécurité, suivez les consignes de SECURITY.md plutôt que d'ouvrir une issue
  publique.

---

<div align="center">
<sub>DualVerify-Sentinel · Deterministic Security Validation Engine · MIT © 2026 zyh798-cell</sub>
</div>
