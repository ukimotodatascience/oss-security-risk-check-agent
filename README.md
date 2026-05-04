# oss-security-risk-check-agent

OSS プロジェクト（主にソースコード/設定/依存関係/CI/CD 定義）を静的に走査し、セキュリティリスクを Markdown レポートとして出力する Python ツールです。  
`TARGET_DIR` で指定したローカルディレクトリ、または `TARGET_REPO_URL` で指定した GitHub リポジトリ URL を対象に、`src/rules/` 配下のルールを実行して検知結果をまとめます。

## 特徴

- `.env` ベースで対象と出力先を設定
- GitHub URL 指定スキャンに対応（`git clone` は行わず archive snapshot を静的解析）
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

開発・テスト用の依存関係もインストールする場合:

```bash
pip install -r requirements-dev.txt
```

### 環境変数設定

`.env.example` をコピーして `.env` を作成します。

```bash
copy .env.example .env
```

`.env` の例:

```env
# 診断対象ディレクトリ（TARGET_REPO_URL と同時指定不可）
TARGET_DIR=C:/path/to/scan-target

# GitHub URL 指定で診断する場合（TARGET_DIR と同時指定不可）
# TARGET_REPO_URL=https://github.com/owner/repo
# TARGET_REF=main
# TARGET_SUBDIR=

# remote archive safety limits
TARGET_FETCH_TIMEOUT_SEC=60
TARGET_MAX_DOWNLOAD_MB=100
TARGET_MAX_EXTRACTED_MB=300
TARGET_MAX_FILES=30000
TARGET_MAX_SINGLE_FILE_MB=10

# レポート出力先（任意）
# 未設定にするとプロジェクト直下の .reports が使われます
OUTPUT_DIR=C:/path/to/output

# ---- Vulnerability provider settings (B-1) ----
VULN_PROVIDER_ORDER=osv,github,nvd
OSV_API_KEY=
GITHUB_TOKEN=
NVD_API_KEY=
VULN_API_TIMEOUT_SEC=10
VULN_MAX_RETRIES=2
VULN_ENABLE_FALLBACK=true
```

> `TARGET_DIR` または `TARGET_REPO_URL` のどちらか一方を指定してください。両方を同時に指定すると終了します。

### URL指定スキャンの安全方針

`TARGET_REPO_URL` を使う場合、このツールは対象リポジトリを `git clone` しません。初期実装では GitHub の HTTPS URL のみを許可し、GitHub archive zipball を一時ディレクトリへ安全に展開して静的解析します。

URL指定スキャンでは以下を行いません。

- `git clone` / `git fetch` / `git checkout`
- `git submodule update`
- `git lfs pull`
- リポジトリ内スクリプトの実行
- 依存関係のインストールやビルド

archive 展開時には zip slip、絶対パス、`..`、symlink、ファイル数・サイズ上限を検査します。submodule や Git LFS の実体は自動取得せず、取得した snapshot 内の通常ファイルのみを解析します。

### B-1（Known Vulnerabilities）外部データ連携

- B-1 は `VULN_PROVIDER_ORDER` の順に `osv / github / nvd` を照会します。
- APIキー未設定でも動作します（必要なAPIのみ設定）。
- `VULN_ENABLE_FALLBACK=true` の場合は複数プロバイダを順次参照し、重複IDを除外して統合します。

## 使い方

```bash
python main.py
```

GitHub URL はコマンド引数でも指定できます。

```bash
python main.py https://github.com/owner/repo --ref main
```

リポジトリ内の一部ディレクトリだけをスキャンする場合:

```bash
python main.py https://github.com/owner/repo --ref main --subdir backend
```

出力先もコマンド引数で指定できます。

```bash
python main.py https://github.com/owner/repo --ref main --output-dir .reports
```

コマンド引数で URL を指定した場合は、`.env` の `TARGET_DIR` / `TARGET_REPO_URL` よりもコマンド引数の URL が優先されます。

GitHub URL を指定する場合の `.env` 例:

```env
TARGET_REPO_URL=https://github.com/owner/repo
TARGET_REF=main
OUTPUT_DIR=.reports
```

## テスト

```bash
python -m pytest -q
```

カバレッジを確認する場合:

```bash
python -m pytest --cov=src --cov-report=term-missing
```

実行後、標準出力に以下が表示されます。

- 診断対象ディレクトリ
- レポート出力先
- 読み込みルール数 / 実行ルール数
- 検知件数
- 生成されたレポートファイルパス

## レポート

レポートは Markdown 形式で出力され、主に次を含みます。

- 実行情報（対象ディレクトリ、生成日時、検知件数、ルール実行エラー件数）
- エグゼクティブサマリ（Critical / High の件数と確認優先度）
- 集計（深刻度別、カテゴリ別、ルール別 Top 10、ディレクトリ別 Top 10）
- 対応優先リスク（Critical / High の上位検知を表形式で表示）
- 詳細検知一覧（深刻度 → ルール単位にグルーピングした表形式の一覧）
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
   ├─ config.py            # .env 読み込み、対象/OUTPUT_DIR 解決
   ├─ scan.py              # 実行フロー（設定→対象解決→ルール実行→レポート出力）
   ├─ rule_engine.py       # ルール読み込みと実行制御
   ├─ reporting.py         # Markdown レポート生成
   ├─ models.py            # RiskRecord / Severity
   ├─ targets/             # local/remote archive の対象解決
   └─ rules/               # 各カテゴリの診断ルール
```

## 注意事項

- 本ツールは静的解析ベースのため、検知結果には誤検知・見逃しが含まれる可能性があります。
- 重要な判断は、検知箇所のコードレビューと追加検証を前提にしてください。
- ルールの詳細は `docs/rule_list_catalog.md` を参照してください。
