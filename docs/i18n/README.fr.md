<div align="center">

<img src="../../assets/logo.svg" alt="DualVerify-Sentinel logo — deep navy shield with dual verification check, cyan orbit nodes and the DVS wordmark" width="110">

# DUALVERIFY-SENTINEL

### ENGINEERED FOR TRUST.
### BUILT FOR CONTROL.

**Un moteur de validation de sécurité fondé sur une autorisation explicite, une exécution déterministe et des preuves vérifiables.**

Exécution déterministe. Limites d'autorisation explicites. Preuves de sécurité auditables.

`zyh798-cell` / `DualVerify-Sentinel` · MIT

<img src="../../assets/banner.svg" alt="DualVerify-Sentinel banner — shield mark, project name, one-line description and authorized-testing-only notice" width="720">

[![Star on GitHub](https://img.shields.io/badge/Star_on-GitHub-181717?style=for-the-badge&logo=github)](https://github.com/zyh798-cell/DualVerify-Sentinel)
[![Star](https://img.shields.io/badge/Star-grey?style=for-the-badge&logo=github)](https://github.com/zyh798-cell/DualVerify-Sentinel)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Verified-085041)](#sec-7)
[![Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-0C447C)](#sec-3)
[![Use](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-BA7517)](#sec-5)
[![Status](https://img.shields.io/badge/Status-Gen--1-0C447C)](#sec-8)

[English](../../README.md) · [中文](README.zh-CN.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · [Español](README.es.md) · **Français**

[Présentation](#sec-1) · [Fonctionnalités](#sec-2) · [Démarrage rapide](#sec-4) · [Sécurité](#sec-5) · [Tests de plateforme](#sec-7) · [Contribuer](#sec-9) · [Security](../../SECURITY.md)

> ⭐ **Si ce projet vous est utile, attribuez-lui une étoile. Les tests communautaires et les contributions sont bienvenus.**

> ⚠️ **RÉSERVÉ AUX TESTS DE SÉCURITÉ AUTORISÉS**

</div>

---

<a id="sec-1"></a>
## 1. Qu'est-ce que DualVerify-Sentinel ?

DualVerify-Sentinel (DVS) est un **moteur de validation de sécurité piloté par
des politiques** : chaque étape d'exécution est vérifiée contre un périmètre
d'autorisation lisible par machine, consignée dans un journal de preuves
inviolable, et applique un **échec fermé (fail-closed)** — une autorisation
absente, corrompue ou expirée produit un refus, jamais une vérification omise.

C'est une couche socle d'ingénierie de sécurité : une porte d'autorisation et un
moteur d'exécution déterministe. La planification Gen-1 est un **modèle statique
fondé sur des règles**, et non un planificateur piloté par modèle ou adaptatif.

**Ce que DVS n'est pas aujourd'hui** : une plateforme d'agents généraliste, un
runtime d'agents LLM, un système de décision autonome piloté par modèle, ou un
bac à sable au niveau du système d'exploitation. Ce sont des orientations à long
terme, pas des capacités actuelles.

<a id="sec-2"></a>
## 2. Ce qu'il fait aujourd'hui

Chaque capacité ci-dessous est appliquée par des chemins de code explicites, et non par le jugement d'un modèle.

| Capacité | Ce qui est implémenté |
|---|---|
| **Autorisation explicite** | JSON de périmètre validé dans un **sous-processus isolé** ; hachage du périmètre, mode, cible et fenêtre revérifiés indépendamment à l'exécution. Périmètre absent, corrompu ou expiré → REFUS. Aucun contournement n'existe. |
| **Exécution pilotée par politiques** | Cinq modes à plafond de risque croissant : `passive` (R0), `safe_scan` (R1), `vuln_validation` (R2), `attack_simulation` (R3), `high_risk` (R4). Des règles de décision explicites arrêtent la boucle sur refus, abandon ou échec ; les cibles ne sont jamais étendues. |
| **Contrôles conscients du risque** | Machine à états TaskGraph avec budgets stricts (32 nœuds max, profondeur de dérivation 2, 8 dérivations), dérivations dynamiques conditionnées au statut COMPLETED du parent, et chaîne de 12 vérifications par étape. Aucune technique destructive, aucune persistance, aucune construction de charge, aucune exfiltration des données découvertes. |
| **Intégration d'outils de sécurité** | Adaptateurs principaux `nuclei` et `bandit` ; adaptateurs optionnels `gitleaks` et `semgrep` dans `vuln_hunter/adapters_ext/` (fichiers de règles locaux uniquement, aucune récupération de règles par le réseau). Toutes les sorties sont normalisées via le Finding Schema unifié (`findings.py`). Un binaire absent est ignoré proprement avec un rapport préalable. |
| **Preuves d'audit vérifiables** | Chaîne de hachage SHA-256 en ajout seul (`seq` / `prev` / `h`) avec détection de manipulation et de réordonnancement. Un échec d'audit se termine par le code 3 au lieu de présenter un résultat non certifié comme normal. |
| **Rapports honnêtes et structurés** | Les constats sont enregistrés tels quels ; une sortie d'outil non vérifiée n'est jamais qualifiée de vulnérabilité confirmée ; les limites connues figurent dans chaque rapport ; aucune affirmation d'exactitude de détection n'est faite. |

> Les adaptateurs sont **implémentés sous forme de code**. Leur présence ne
> prouve pas une exécution vérifiée avec l'outil réel — la vérification de
> bout en bout avec outils réels n'est pas terminée (voir la section 8).

<a id="sec-3"></a>
## 3. Prérequis

| Prérequis | Détail |
|---|---|
| Python | >= 3.10 (vérifié sur 3.13.14) |
| Dépendances | **Bibliothèque standard uniquement** — aucune dépendance tierce à l'exécution |
| OS | Windows **vérifié** ; Linux / macOS **pas encore vérifiés** — voir la section 7 |
| Outils externes optionnels | `nuclei`, `bandit`, `gitleaks`, `semgrep` — ignorés proprement s'ils sont absents |

<a id="sec-4"></a>
## 4. Installation et démarrage rapide

```bash
git clone https://github.com/zyh798-cell/DualVerify-Sentinel.git
cd DualVerify-Sentinel

python -m venv .venv
# Windows (PowerShell) : .venv\Scripts\Activate.ps1
# Windows (CMD) :        .venv\Scripts\activate.bat
# Linux/macOS :          source .venv/bin/activate

pip install .
```

`pip install -e .` est également pris en charge pour le développement.

**Étape 1 — toujours valider d'abord le fichier de périmètre :**

```bash
dvs gate-check scripts/example-scope.json
# 0 = valide · 1 = refusé · 2 = erreur d'usage
```

**Étape 2 — lancer une validation :**

```bash
dvs run --scope scripts/example-scope.json --mode safe_scan --target 127.0.0.1:8080
# ou : python -m vuln_hunter run --scope ... --mode ... --target ...
```

Modes (plafond de risque croissant) : `passive` → `safe_scan` →
`vuln_validation` → `attack_simulation` → `high_risk` (R0–R4). `nuclei` n'est
invoqué qu'à partir de R2.

Codes de sortie : `0` toutes les étapes COMPLETED · `1` terminé avec échecs/refus ·
`2` refus au niveau porte/politique (rien exécuté) · `3` **échec d'audit** (le
journal est inaccessible en écriture ou invérifiable, les résultats ne sont donc pas certifiés).

`scripts/example-scope.json` est un exemple fictif, **pas une autorisation réelle**.

<a id="sec-5"></a>
## 5. Autorisation et sécurité

> ⚠️ **N'utilisez DVS que sur des systèmes que vous possédez ou exploitez, des
> cibles de laboratoire locales, ou des hôtes pour lesquels vous disposez d'une
> autorisation écrite explicite du propriétaire.**

Les configurations non autorisées, hors périmètre, à fenêtre expirée ou
corrompues sont refusées. Aucun chemin de code ne contourne l'autorisation.

- Les entrées sont comparées par **égalité du nom d'hôte analysé** ; une entrée
  sans port correspond à n'importe quel port de cet hôte. **Les plages CIDR ne
  sont pas prises en charge** — utilisez des entrées `host` ou `host:port`.
- La fenêtre d'autorisation est revérifiée **à chaque étape d'exécution** ; une
  expiration en cours d'exécution interrompt les étapes suivantes.
- Le contenu du périmètre est lié par hachage à chaque ticket d'exécution ;
  modifier le périmètre invalide les tickets en attente.
- Les étapes à périmètre de système de fichiers n'omettent que la vérification
  de périmètre réseau ; toutes les autres vérifications de politique s'appliquent.

Conservez les véritables enregistrements d'autorisation hors de ce dépôt. Le
périmètre d'exemple fourni est fictif.

**Le durcissement d'API n'est pas un bac à sable au niveau de l'OS.** Le
dataclass gelé de `RunTicket` et son registre privé sont un durcissement au
niveau Python ; du code hostile dans le même processus pourrait les contourner.
Une isolation forte exige des mesures au niveau du processus, non implémentées.
La CLI est le seul point d'entrée pris en charge.

<a id="sec-6"></a>
## 6. Preuves et rapports honnêtes

Le journal d'audit est en ajout seul et chaîné par hachage ; toute manipulation
ou réorganisation est détectée, et un échec d'audit est exposé explicitement
plutôt que masqué. Les rapports distinguent les résultats complets, partiels et
incomplets ; les résultats incomplets échouent fermés et ne fournissent aucun
constat récolté.

Deux limites méritent d'être énoncées clairement : la sortie des outils est
enregistrée telle quelle et une sortie non vérifiée n'est jamais promue au rang
de vulnérabilité confirmée ; et une troncature de la fin du journal ne peut être
détectée que si une ancre de tête a été sauvegardée extérieurement.

<a id="sec-7"></a>
## 7. Compatibilité des plateformes et tests communautaires

**Les tests communautaires sont bienvenus. Aidez-nous à étendre la compatibilité des plateformes.**

DVS est actuellement **orienté Windows**. Sous Windows, le chemin de timeout
effectue un nettoyage tracé de l'arbre de processus (`taskkill /T /F` est
exécuté avant la terminaison du processus racine, chaque résultat étant
consigné) ; ce comportement a été exercé lors d'un exercice contrôlé mais ne
garantit pas absolument l'absence de résidus. Sur les plateformes non Windows,
la terminaison de l'arbre est omise et seul le processus racine est terminé. Le
repli de chemin de `nuclei` suppose également une disposition d'installation
locale particulière.

Linux et macOS **n'ont pas été vérifiés** et la CI ne les couvre pas encore. Si
vous exécutez DVS sur une autre plateforme, partagez dans une issue ce qui
fonctionne et ce qui ne fonctionne pas — le comportement des adaptateurs, le
nettoyage des processus et l'empaquetage sont particulièrement utiles. N'incluez
pas de données de cibles réelles, d'identifiants ou de sorties d'analyses non autorisées.

<a id="sec-8"></a>
## 8. État du projet et orientation

| | |
|---|---|
| **Livré (Gen-1)** | Porte d'autorisation, moteur de politiques (R0–R4), TaskGraph, journal d'audit, rapports structurés, Finding Schema unifié, et chemins de code des adaptateurs `nuclei` / `bandit` / `gitleaks` / `semgrep`. |
| **En cours de construction / vérification** | Vérification de bout en bout avec outils réels, vérification et CI pour les plateformes non Windows, et vérification de l'empaquetage de cette version exacte. Les suites de tests sont dans `tests/` — exécutez-les et fiez-vous à leur sortie réelle ; ce dépôt n'affirme pas à l'avance que « tout est vert ». |
| **Orientation à long terme** | Planification pilotée par modèle, isolation plus forte au niveau processus, et prise en charge plus large des plateformes. Ce ne sont que des orientations, **non implémentées** dans Gen-1. |

La couche de planification actuelle est un modèle statique déterministe. La
présence de code d'adaptateur ne prouve pas une exécution vérifiée de l'outil, et
le durcissement d'API n'est pas un bac à sable au niveau de l'OS. L'empaquetage
doit être jugé en construisant cette version ; d'anciens artefacts de build ne
constituent pas une preuve pour la version actuelle. C'est une base
d'ingénierie, pas un produit d'évaluation prêt pour la production.

<a id="sec-9"></a>
## 9. Contribuer et participer

Une étoile aide d'autres personnes à découvrir le projet. Essayer DVS sur vos
propres cibles de laboratoire, signaler vos observations et ouvrir une pull
request sont tout aussi bienvenus. Voir [CONTRIBUTING.md](../../CONTRIBUTING.md)
pour le guide complet.

Façons d'aider :

- **Adaptation de plateformes et tests de compatibilité** — comportement
  Linux/macOS, nettoyage de l'arbre de processus, empaquetage.
- **Intégration de fournisseurs / adaptateurs d'outils de sécurité** — nouvelles
  intégrations respectant la porte d'autorisation et la conception fail-closed.
- **Cas de tests et bases de régression** — vérifications reproductibles produisant des preuves.
- **Documentation et traductions** — les six langues du README, exemples, clarté.
- **Corrections de bogues et qualité de code** — modifications ciblées avec preuves exécutables.
- **Recherche en sécurité** — suivez [SECURITY.md](../../SECURITY.md) ; n'ouvrez jamais une issue publique pour une vulnérabilité non divulguée.
- **Expérience d'utilisation et idées de fonctionnalités** — ouvrez d'abord une issue pour convenir du périmètre.

Utilisez **Issues** pour les bogues, les résultats de plateforme et les
propositions ; utilisez les **Pull Requests** pour les modifications de code et de
documentation. Ne joignez à aucune issue ou PR de données de cibles réelles,
d'identifiants, d'enregistrements d'autorisation privés ou de sorties d'analyses
non autorisées.

<a id="sec-10"></a>
## 10. Licence et liens

- **Licence** : MIT — voir [LICENSE](../../LICENSE).
- **Politique de sécurité** : [SECURITY.md](../../SECURITY.md).
- **Guide de contribution** : [CONTRIBUTING.md](../../CONTRIBUTING.md).
- **Issues et PR** : [ouvrir une issue](https://github.com/zyh798-cell/DualVerify-Sentinel/issues) · [ouvrir une PR](https://github.com/zyh798-cell/DualVerify-Sentinel/pulls).
- **Traductions** : 中文 · 日本語 · 한국어 · Español · Français (voir le sélecteur de langue ci-dessus).

---

<div align="center"><sub>DualVerify-Sentinel · Engineered for Trust. Built for Control. · MIT © 2026 zyh798-cell</sub></div>
