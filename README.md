# oss-security-risk-check-agent

OSS プロジェクト（主にソースコード/設定/依存関係/CI/CD 定義）を静的に走査し、セキュリティリスクを Markdown レポートとして出力する Python ツールです。  
`TARGET_DIR` で指定したディレクトリを対象に、`src/rules/` 配下のルールを実行して検知結果をまとめます。

## 特徴

- `.env` ベースで対象ディレクトリと出力先を設定
- `src/rules/` のルールクラスを動的ロードして実行
- 12カテゴリ（A〜L）のルール群を実装
  - `code`, `dependencies`, `cicd`, `config`, `auth`, `secrets`, `runtime`, `crypto`, `logging`, `maintenance`, `license`, `malware`
- 実行結果を Markdown（`report_YYYYMMDD_HHMMSS.md`）で出力
- ルール実行時の例外もレポートに記録

## セットアップ

### 前提

- Python 3.10 以上（推奨）

### インストール

```bash
pip install -r requirements.txt
```

### 環境変数設定

`.env.example` をコピーして `.env` を作成します。

```bash
copy .env.example .env
```

`.env` の例:

```env
# 診断対象ディレクトリ（必須）
TARGET_DIR=C:/path/to/scan-target

# レポート出力先（任意）
# 未設定にするとプロジェクト直下の .reports が使われます
OUTPUT_DIR=C:/path/to/output
```

> `TARGET_DIR` は必須です。未設定または存在しない場合は終了します。

## 使い方

```bash
python main.py
```

実行後、標準出力に以下が表示されます。

- 診断対象ディレクトリ
- レポート出力先
- 読み込みルール数 / 実行ルール数
- 検知件数
- 生成されたレポートファイルパス

## レポート

レポートは Markdown 形式で出力され、主に次を含みます。

- 対象ディレクトリ
- 生成日時（UTC）
- 深刻度別サマリ（Critical / High / Medium / Low / Info）
- 検知一覧（ルールID、カテゴリ、場所、メッセージ）
- ルール実行エラー（発生時）

## ディレクトリ構成

```text
.
├─ main.py                 # エントリポイント
├─ requirements.txt
├─ .env.example
├─ docs/
│  └─ rule_list_catalog.md # ルール仕様カタログ
└─ src/
   ├─ config.py            # .env 読み込み、TARGET_DIR/OUTPUT_DIR 解決
   ├─ scan.py              # 実行フロー（設定→ルール実行→レポート出力）
   ├─ rule_engine.py       # ルール読み込みと実行制御
   ├─ reporting.py         # Markdown レポート生成
   ├─ models.py            # RiskRecord / Severity
   └─ rules/               # 各カテゴリの診断ルール
```

## 注意事項

- 本ツールは静的解析ベースのため、検知結果には誤検知・見逃しが含まれる可能性があります。
- 重要な判断は、検知箇所のコードレビューと追加検証を前提にしてください。
- ルールの詳細は `docs/rule_list_catalog.md` を参照してください。
