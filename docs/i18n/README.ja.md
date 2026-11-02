<div align="center">

# DualVerify-Sentinel

**決定論的・認可ゲート付きセキュリティ検証エンジン。**

`zyh798-cell` / `DualVerify-Sentinel` · Gen-1 Stable · MIT

<img src="../../assets/banner.gif" alt="DualVerify-Sentinel — ピクセル風アニメーションバナー。タイトルが1文字ずつ現れ、スキャンラインとデータフローのエフェクトが流れる" width="720">

**DualVerify-Sentinel — Deterministic Security Validation Engine**
⚠️ **AUTHORIZED SECURITY TESTING ONLY**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Verified-0078D6?logo=windows&logoColor=white)](#4-%E8%A6%81%E4%BB%B6)
[![Platform](https://img.shields.io/badge/Platform-Linux%2FmacOS%20Unverified-6b7280)](#10-%E6%97%A2%E7%9F%A5%E3%81%AE%E5%88%B6%E9%99%90)
[![Checks](https://img.shields.io/badge/Offline%20Checks-427%2B%20Passing-2EA043)](#11-%E3%83%97%E3%83%AD%E3%82%B8%E3%82%A7%E3%82%AF%E3%83%88%E3%81%AE%E7%8A%B6%E6%85%8B)
[![Status](https://img.shields.io/badge/Status-Gen--1%20Stable-8250DF)](#11-%E3%83%97%E3%83%AD%E3%82%B8%E3%82%A7%E3%82%AF%E3%83%88%E3%81%AE%E7%8A%B6%E6%85%8B)

[English](../../README.md) · [中文](README.zh-CN.md) · **日本語** · [Español](README.es.md) · [Français](README.fr.md)

</div>

---

## 1. これは何か

DualVerify-Sentinel は**ルールベースのセキュリティ検証エンジン**です
（明示的に**モデル非駆動**）：すべての実行ステップは機械可読な認可スコープに
対してポリシーチェックされ、改ざん検知可能なハッシュチェーンの監査ジャーナルに
記録され、**フェイルクローズド**で動作します — 認可の欠落・破損・期限切れは
*拒否*を意味し、チェックの省略ではありません。

次世代検証アーキテクチャ（認可ゲート + 信頼性の高い実行エンジン）の
セキュリティエンジニアリング基盤層です。Gen-1 の計画/決定層は意図的に
決定論的に保たれています。

## 2. 何ができるか

| 機能 | 実装方式 |
|---|---|
| 認可ゲート | 機械可読な scope JSON を**独立サブプロセス**で検証。欠落/破損/期限切れ → REFUSED（終了コード 2）。バイパス経路は存在しません。 |
| 実行チケット（RunTicket） | アダプタはポリシーエンジン発行のチケットのみ受諾。スコープハッシュ・モード・ターゲット・ウィンドウを**実行時に再独立検証**。 |
| 安全な実行 | ステップごとに 12 項目のチェックチェーン。破壊的技術なし、永続化なし、ペイロード構築なし、発見データの外部送信なし。 |
| 監査ジャーナル | 追加専用ハッシュチェーン（`seq`/`prev`/`h`、SHA-256）。改ざん/並べ替え検知。監査障害は終了コード 3 で終了し、通常結果として偽装しません。 |
| 決定論的決定ループ | 明示的ルール P0–P8：拒否/中断/失敗があればループ停止。ターゲットは**決して**拡大しません。 |
| タスクグラフ | ステートマシン + ハード予算（最大 32 ノード、スポーン深度 2、8 スポーン）。動的スポーンは親の COMPLETED を前提条件。 |
| オプションのツールアダプタ | `nuclei`（テンプレートスキャン）と `bandit`（静的解析）— 未インストール時は preflight レポート付きで SKIPPED。 |
| 正直なレポート | 発見内容はそのまま記録。未検証の出力が確認済み脆弱性として標識されることはありません。既知の制限はレポートごとに列挙。 |

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
| 外部ツール（任意） | `nuclei`、`bandit` — 無ければスキップ |

## 5. インストール

```bash
git clone https://github.com/zyh798-cell/DualVerify-Sentinel.git
cd DualVerify-Sentinel

python -m venv .venv
# Windows:
.venv\Scripts\activate
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
2. **Windows 優先** — Windows でのプロセスタイムアウト抹消は孫プロセスを
   追跡しません。nuclei のパスフォールバックは特定の `~/Tools/nuclei/`
   レイアウトを想定しています。
3. **検出の正確性は保証しない** — ツール出力はそのまま記録され、未検証の
   結果が確認済み脆弱性として標識されることはありません。
4. **Linux/macOS 未検証** — CI は非 Windows プラットフォームをカバーしません。
5. **ジャーナル末尾の切り詰め** — 外部に head アンカーを保存した場合のみ検知
   可能。レポート内アンカーは整合性確認用です。
6. **Gen-1 プランナーは静的テンプレート** — 計画は決定論的であり、
   モデル駆動でも適応的でもありません。

## 11. プロジェクトの状態

- **Gen-1 は安定**：18 のオフラインテストスイート、427+ チェックがローカルで
  合格（Windows、Python 3.13.14）。wheel/sdist ビルドによるパッケージング
  スモークテスト済み。
- **Gen-2 アーキテクチャ**（将来の独立リポジトリ）を計画中。
  提案/裁定の分離を導入予定。Gen-2 の作業はこのリポジトリでは行いません。
- 完全なテストコマンドは `tests/` 配下を参照 — 実行して実際の結果を信頼して
  ください。このリポジトリは事前の「オールグリーン」主張を行いません。

## 12. ライセンスとフィードバック

- **ライセンス**：MIT — [LICENSE](../../LICENSE) を参照。
- **セキュリティポリシー**：[SECURITY.md](../../SECURITY.md) を参照。
- Issue と Pull Request を歓迎します。セキュリティ関連の報告は、公開 issue を
  作成せず SECURITY.md のガイダンスに従ってください。

---

<div align="center">
<sub>DualVerify-Sentinel · Deterministic Security Validation Engine · MIT © 2026 zyh798-cell</sub>
</div>
