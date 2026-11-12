<div align="center">

<img src="../../assets/logo.svg" alt="DualVerify-Sentinel ロゴ — デュアルチェック、シアンの軌道ノード、DVS ワードマークを備えた深納のシールド" width="110">

# DUALVERIFY-SENTINEL

### ENGINEERED FOR TRUST.
### BUILT FOR CONTROL.

**ポリシー駆動のセキュリティ検証エンジン**

決定論的な実行。明示的な認可境界。監査可能なセキュリティ証跡。

`zyh798-cell` / `DualVerify-Sentinel` · MIT

<img src="../../assets/banner.svg" alt="DualVerify-Sentinel バナー — シールドマーク、プロジェクト名、一行説明、authorized testing only の注意書き" width="720">

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Verified-085041)](#4-要件)
[![Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-0C447C)](#4-要件)
[![Use](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-BA7517)](#8-認可と安全性)
[![Status](https://img.shields.io/badge/Status-Gen--1-0C447C)](#11-プロジェクトの状態)

[English](../../README.md) · [中文](README.zh-CN.md) · **日本語** · [한국어](README.ko.md) · [Español](README.es.md) · [Français](README.fr.md)

[認可ゲート](#認可ゲート) · [ポリシーエンジン](#ポリシーエンジンとリスクラダー) · [TaskGraph](#taskgraph-オーケストレーション) · [ツールアダプタ](#ツールアダプタ-nuclei--bandit) · [監査ジャーナル](#監査ジャーナル) · [レポート](#構造化レポート) · [インストール](#5-インストール) · [セキュリティ](../../SECURITY.md)

> ⚠️ **AUTHORIZED SECURITY TESTING ONLY**

</div>

---

## 1. これは何か

DualVerify-Sentinel は**ルールベースのセキュリティ検証エンジン**です
（明示的に**モデル非駆動**）：すべての実行ステップは機械可読な認可スコープに
対してポリシーチェックされ、改ざん検知可能なハッシュチェーンの監査ジャーナルに
記録され、**フェイルクローズド**で動作します — 認可の欠落・破損・期限切れは
*拒否*を意味し、チェックの省略ではありません。

認可ゲートと決定論的な実行エンジンからなる、セキュリティエンジニアリングの
基盤層です。Gen-1 の計画/決定層は意図的に決定論的であり、モデル駆動ではありません。

## 2. 何ができるか

Gen-1 は単一の決定論的パイプラインとして動作します — 以下の各機能はモデル判断ではなく、明示的なコードパスによって強制されます。

### 認可ゲート

機械可読な scope JSON を**独立サブプロセス**で検証。欠落/破損/期限切れ → REFUSED（終了コード 2）。バイパス経路は存在しません。アダプタはポリシーエンジン発行のチケットのみ受諾。スコープハッシュ・モード・ターゲット・ウィンドウを**実行時に再独立検証**します。

### ポリシーエンジンとリスクラダー

リスク上限が昇順の 5 モード（R0–R4、[基本的な使い方](#6-基本的な使い方)参照）。明示的ルール P0–P8：拒否/中断/失敗があればループ停止。ターゲットは**決して**拡大しません。

### TaskGraph オーケストレーション

ハード予算つきステートマシン（最大 32 ノード、スポーン深度 2、8 スポーン）。動的スポーンは親の COMPLETED を前提条件とします。

### ツールアダプタ (nuclei / bandit)

`nuclei`（テンプレートスキャン）と `bandit`（静的解析）— 未インストール時は preflight レポート付きで SKIPPED。安全な実行：ステップごとに 12 項目のチェックチェーン。破壊的技術なし、永続化なし、ペイロード構築なし、発見データの外部送信なし。

### 監査ジャーナル

追加専用ハッシュチェーン（`seq`/`prev`/`h`、SHA-256）。改ざん/並べ替え検知。監査障害は終了コード 3 で終了し、通常結果として偽装しません。

### 構造化レポート

発見内容はそのまま記録。未検証の出力が確認済み脆弱性として標識されることはありません。既知の制限はレポートごとに列挙されます。

### 追加アダプタと統合 Finding Schema

`vuln_hunter/adapters_ext/` には、さらに 2 つの任意アダプタが実装されています：
`gitleaks`（シークレット検出、ステップ `s4-gitleaks`）と `semgrep`（静的解析、
**ローカルのルールファイルのみ使用**、ステップ `s5-semgrep`）。いずれも
ファイルシステム範囲のソースツリーに対して条件付きで計画され、それぞれ専用の
実行ファイルを必要とし、ネットワークからルールを取得することはありません。
すべてのアダプタ出力は統合 Finding Schema（`findings.py`）で正規化され、
レポートに到達する前に重大度とレコード形状が検証されます。

> これらのアダプタは**コードとして実装済み**ですが、実ツールのエンドツーエンド
> 検証は**未完了**です。アダプタが存在することは、ツール実行が検証済みである
> ことの証拠にはなりません — 第 11 節を参照。

## 3. ユースケース

- 自分のラボターゲットや明示的に認可されたホストの検証。
- 完全な監査証跡を持つ、再現可能でエビデンスを生成するセキュリティチェック。
- より高度な検証パイプラインの基盤層として。

## 4. 要件

| 要件 | 詳細 |
|---|---|
| Python | >= 3.10（3.13.14 のみでテスト済み） |
| サードパーティ依存 | **なし** — 標準ライブラリのみ |
| OS | Windows **検証済み**、Linux/macOS **未検証** |
| 外部ツール（任意） | `nuclei`、`bandit`、`gitleaks`、`semgrep` — アダプタは実装済み。無ければスキップ。実ツールの実行は未検証 |

## 5. インストール

```bash
git clone https://github.com/zyh798-cell/DualVerify-Sentinel.git
cd DualVerify-Sentinel

python -m venv .venv
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Windows (CMD):
.venv\Scripts\activate.bat
# Linux/macOS:
source .venv/bin/activate

pip install .
```

開発用には編集可能インストール `pip install -e .` も利用できます。

## 6. 基本的な使い方

**ステップ 1 — scope ファイルの検証（必ず最初に）：**

```bash
dvs gate-check scripts/example-scope.json
# 終了コード 0 = スコープ有効 · 1 = 拒否
```

**ステップ 2 — 検証の実行：**

```bash
dvs run --scope scripts/example-scope.json --mode safe_scan --target 127.0.0.1:8080
# または: python -m vuln_hunter run --scope ... --mode ... --target ...
```

モード（リスク上限の昇順）：`passive` → `safe_scan` → `vuln_validation` →
`attack_simulation` → `high_risk`（R0–R4）。`nuclei` は R2 以上でのみ呼び出されます。

終了コード：`0` 全ステップ COMPLETED · `1` 失敗/拒否ありで完了 ·
`2` ゲート/ポリシーレベルの拒否（何も実行されず） · `3` **監査障害**
（ジャーナルが書き込めない/検証できない — 結果は保証されません）。

`scripts/example-scope.json` は架空の例であり、**実在の認可ではありません**。

## 7. スコープのセマンティクス

- エントリは**パース済みホスト名の一致**で判定されます（ポートなしのエントリは
  そのホストの任意のポートに一致）。**CIDR 範囲は非対応** — `host` または
  `host:port` 形式を使用してください。
- 認可ウィンドウは**実行ステップごとに**再チェックされ、実行中の期限切れは
  以降のステップを中止します。
- スコープ内容のハッシュは各実行チケットにバインドされ、スコープ変更は
  未完了チケットを無効化します。
- ファイルシステムスコープのステップはネットワークスコープチェックのみを
  スキップし、その他のポリシーチェックは通常どおり適用されます。

## 8. 認可と安全性

> ⚠️ **本ツールは、自分が所有・運営するシステム、ローカルラボターゲット、
> または所有者から明示的な書面による認可を得ているホストに対してのみ使用して
> ください。** 未認可・範囲外・期限切れ・破損した設定は拒否されます
> （フェイルクローズド）。認可をスキップするコードパスは存在しません。

同梱のサンプルスコープは架空のものです。実際のエンゲージメントには実在の、
機械可読な認可記録が必要です — リポジトリの外で保管してください。

## 9. API 強化はサンドボックスではない

RunTicket の frozen dataclass とプライベートレジストリは **API 強化**であり、
サンドボックスではありません — 敵対的なプロセス内コードはあらゆる
Python レベルのチェックを回避できます。強固な分離にはプロセスレベルの対策が
必要です（未実装）。CLI が唯一のサポート対象エントリポイントです。

## 10. 既知の制限

1. **プロセス内サンドボックスなし** — セクション 9 を参照。
2. **Windows 優先** — Windows のタイムアウト経路には実装済みのプロセスツリー
   クリーンアップがあります（ルート kill の前に `taskkill /T /F` を実行し、
   全結果を記録）。管理された 3 層プロセスツリー訓練で検証済みですが、
   **絶対的な保証ではありません** — ランタイムの残存確認はなく、taskkill の
   rc=0 はツリー全体の消去完了を証明せず、実 Nuclei の子孫プロセス形態は
   未検証です。非 Windows ではツリー kill をスキップします（ルートのみ kill）。
   nuclei のパスフォールバックは特定の `~/Tools/nuclei/` レイアウトを想定し
   ています。
3. **検出の正確性は保証しない** — ツール出力はそのまま記録され、未検証の
   結果が確認済み脆弱性として標識されることはありません。
4. **Linux/macOS 未検証** — CI は非 Windows プラットフォームをカバーしません。
5. **ジャーナル末尾の切り詰め** — 外部に head アンカーを保存した場合のみ検知
   可能。レポート内アンカーは整合性確認用です。
6. **Gen-1 プランナーは静的テンプレート** — 計画は決定論的であり、
   モデル駆動でも適応的でもありません。

## 11. プロジェクトの状態

- **Gen-1 は実装済み**：認可ゲート、ポリシーエンジン（R0–R4）、TaskGraph、
  監査ジャーナル、構造化レポート、統合 Finding Schema、および `nuclei` /
  `bandit` / `gitleaks` / `semgrep` アダプタがコードパスとして存在します。
  テストスイートは `tests/` 配下にあります — 実行し、実際の出力を信頼してください。
  本リポジトリは事前の「オールグリーン」や合格件数の主張を行いません。
- **未検証 / 未実装**：実ツールのエンドツーエンド検証は未完了です；Phase B は
  未実行です；W1-03、W1-04、W1-06、CR-06 の各項目および実際の Semgrep ベースラインは
  未解決です；Linux/macOS での検証と CI は整備されていません；Gen-2 は本リポジトリに
  実装されていません。アダプタのコードが存在することは検証済みのツール実行の証拠には
  ならず、API 強化は OS レベルのサンドボックスでもありません（第 9 節参照）。
- パッケージングは本バージョンのビルドで判断する必要があります。古いビルド成果物は
  現行リリースの証拠になりません。

## 12. ライセンスとフィードバック

- **ライセンス**：MIT — [LICENSE](../../LICENSE) を参照。
- **セキュリティポリシー**：[SECURITY.md](../../SECURITY.md) を参照。
- **コントリビューション**: [CONTRIBUTING.md](../../CONTRIBUTING.md) を参照。
- Issue と Pull Request を歓迎します。セキュリティ関連の報告は、公開 issue を
  作成せず SECURITY.md のガイダンスに従ってください。

---

<div align="center">
<sub>DualVerify-Sentinel · Deterministic Security Validation Engine · MIT © 2026 zyh798-cell</sub>
</div>
