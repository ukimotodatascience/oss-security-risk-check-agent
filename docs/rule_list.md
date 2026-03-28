# OSSセキュリティ診断ルールカタログ

---

# A：コード自体の脆弱性（code）

## A-1 OSコマンドインジェクション
### 概要
外部入力がOSコマンド実行に直接渡されることで、任意コマンド実行につながるリスクを検知する。

### インプット
- ソースコード
- 抽出対象API
  - `os.system`
  - `subprocess.run`
  - `subprocess.Popen`
  - `subprocess.call`
  - `exec`
  - `eval`

### 判定基準
#### 判定条件
1. 外部入力がコマンド文字列の生成に使われている
2. かつ、文字列連結・f-string・format等でコマンドを組み立てている
3. かつ、`shell=True` またはシェル解釈ありの実行方法を使っている  
→ 上記を満たす場合、危険性が高いとみなす

4. 外部入力がコマンド引数に使われているが、配列引数で渡されており、`shell=True` ではない  
→ 危険性は相対的に低いが、文脈によって注意とみなす

5. 外部入力を使用しておらず、固定コマンドのみを実行している  
→ 問題なしとみなす

#### 返却値
- 条件1〜3を満たす場合
  - `status: FAIL`
  - `severity: HIGH`
  - `message: "外部入力を用いてシェルコマンドを組み立てて実行しています"`
  - `confidence: HIGH`

- 条件4を満たす場合
  - `status: WARN`
  - `severity: MEDIUM`
  - `message: "外部入力をコマンド引数に使用しています。引数の妥当性確認が必要です"`
  - `confidence: MEDIUM`

- 条件5を満たす場合
  - `status: PASS`
  - `severity: LOW`
  - `message: "危険なコマンド実行パターンは検出されませんでした"`
  - `confidence: HIGH`

#### 補足
- `shell=True` は強い危険シグナル
- 入力元がHTTPパラメータ、CLI引数、環境変数、設定ファイルの場合は優先的に確認する

---

## A-2 SQLインジェクション
### 概要
外部入力を含むSQL文が安全にパラメータ化されていない場合のリスクを検知する。

### インプット
- ソースコード
- SQL実行API
- ORM利用箇所

### 判定基準
#### 判定条件
1. 外部入力を文字列連結・f-string・formatでSQL文に埋め込んでいる  
→ 高リスク

2. 外部入力を含むが、プレースホルダやパラメータバインドを利用している  
→ 問題なし

3. SQL文は固定文字列だが、テーブル名やカラム名だけを動的に構築している  
→ 文脈依存のため注意

#### 返却値
- 条件1
  - `status: FAIL`
  - `severity: HIGH`
  - `message: "外部入力をSQL文字列に直接埋め込んでいます"`
  - `confidence: HIGH`

- 条件3
  - `status: WARN`
  - `severity: MEDIUM`
  - `message: "SQL構造の一部を動的に組み立てています。安全性確認が必要です"`
  - `confidence: MEDIUM`

- 条件2
  - `status: PASS`
  - `severity: LOW`
  - `message: "SQLはパラメータ化されており、安全な実装と判断されます"`
  - `confidence: HIGH`

---

## A-3 Unsafe Deserialization
### 概要
信頼できない入力を危険な方法でデシリアライズする実装を検知する。

### インプット
- ソースコード
- 利用ライブラリ
  - `pickle`
  - `yaml.load`
  - その他の危険デシリアライズ関数

### 判定基準
#### 判定条件
1. 外部入力に対して `pickle.loads`, `pickle.load`, `yaml.load(Loader未指定)` 等を使用  
→ 高リスク

2. `yaml.safe_load` 等の安全な関数を使用  
→ 問題なし

3. 危険関数を使っているが、入力元が固定ファイルで改ざん不能と判断できる  
→ 注意

#### 返却値
- 条件1
  - `status: FAIL`
  - `severity: HIGH`
  - `message: "信頼できない入力に対して危険なデシリアライズ関数を使用しています"`
  - `confidence: HIGH`

- 条件3
  - `status: WARN`
  - `severity: MEDIUM`
  - `message: "危険なデシリアライズ関数が使用されています。入力元の安全性確認が必要です"`
  - `confidence: MEDIUM`

- 条件2
  - `status: PASS`
  - `severity: LOW`
  - `message: "安全なデシリアライズ関数が使用されています"`
  - `confidence: HIGH`

---

# B：依存関係（dependencies）

## B-1 既知脆弱性
### 概要
使用中の依存ライブラリが既知の脆弱性情報に該当するかを判定する。

### インプット
- `requirements.txt`
- `package.json`
- `poetry.lock`
- `package-lock.json`
- 脆弱性DB照合結果

### 判定基準
#### 判定条件
1. 依存パッケージ名とバージョンが脆弱性DBに一致し、深刻度がHIGH以上  
→ 高リスク

2. 一致するが、深刻度がLOWまたはMEDIUM  
→ 注意

3. 一致しない  
→ 問題なし

4. バージョン未固定で照合不能  
→ 注意

#### 返却値
- 条件1
  - `status: FAIL`
  - `severity: HIGH`
  - `message: "既知脆弱性を含む依存ライブラリが検出されました"`
  - `confidence: HIGH`

- 条件2
  - `status: WARN`
  - `severity: MEDIUM`
  - `message: "既知脆弱性を含む依存ライブラリが検出されましたが、深刻度は限定的です"`
  - `confidence: HIGH`

- 条件4
  - `status: WARN`
  - `severity: MEDIUM`
  - `message: "依存バージョンが固定されておらず、正確な脆弱性照合ができません"`
  - `confidence: MEDIUM`

- 条件3
  - `status: PASS`
  - `severity: LOW`
  - `message: "既知脆弱性に該当する依存は検出されませんでした"`
  - `confidence: HIGH`

---

## B-2 バージョン未固定
### 概要
依存ライブラリのバージョンが固定されておらず、再現性や安全性が低い状態を検知する。

### インプット
- 依存定義ファイル
- lockfile の有無

### 判定基準
#### 判定条件
1. `*`, `latest`, `>=`, `^`, `~` のみで管理されている  
→ 注意

2. lockfile が存在せず、実解決バージョンが不明  
→ 注意

3. 依存が厳密に固定されている  
→ 問題なし

#### 返却値
- 条件1または2
  - `status: WARN`
  - `severity: MEDIUM`
  - `message: "依存バージョンが未固定、または再現性が不足しています"`
  - `confidence: HIGH`

- 条件3
  - `status: PASS`
  - `severity: LOW`
  - `message: "依存バージョンは適切に固定されています"`
  - `confidence: HIGH`

---

# C：CI/CD（cicd）

## C-1 curl | sh
### 概要
外部取得したスクリプトを検証せず、そのままシェル実行するパターンを検知する。

### インプット
- GitHub Actions
- CI設定ファイル
- Makefile
- シェルスクリプト

### 判定基準
#### 判定条件
1. `curl ... | sh`, `wget ... | bash` のような直接実行を検出  
→ 高リスク

2. 一度ファイル保存し、署名やハッシュ検証後に実行  
→ 問題なし

3. ダウンロードするが実行まではしていない  
→ 注意

#### 返却値
- 条件1
  - `status: FAIL`
  - `severity: HIGH`
  - `message: "外部スクリプトを取得後そのまま実行しています"`
  - `confidence: HIGH`

- 条件3
  - `status: WARN`
  - `severity: MEDIUM`
  - `message: "外部スクリプトをダウンロードしています。実行方法の確認が必要です"`
  - `confidence: MEDIUM`

- 条件2
  - `status: PASS`
  - `severity: LOW`
  - `message: "外部取得物に対して安全確認が行われています"`
  - `confidence: HIGH`

---

# F：シークレット（secrets）

## F-1 ハードコード秘密情報
### 概要
ソースコードや設定ファイルに秘密情報が直接記述されている状態を検知する。

### インプット
- ソースコード
- 設定ファイル
- ドキュメント

### 判定基準
#### 判定条件
1. APIキー、トークン、秘密鍵、パスワード形式の文字列を検出  
→ 高リスク

2. ダミー値やプレースホルダと思われる値を検出  
→ 注意

3. 秘密情報らしき値を検出しない  
→ 問題なし

#### 返却値
- 条件1
  - `status: FAIL`
  - `severity: CRITICAL`
  - `message: "ハードコードされた秘密情報が検出されました"`
  - `confidence: HIGH`

- 条件2
  - `status: WARN`
  - `severity: LOW`
  - `message: "秘密情報に見える値がありますが、ダミー値の可能性があります"`
  - `confidence: LOW`

- 条件3
  - `status: PASS`
  - `severity: LOW`
  - `message: "ハードコードされた秘密情報は検出されませんでした"`
  - `confidence: MEDIUM`

---

# G：実行環境（runtime）

## G-1 root実行
### 概要
コンテナや実行環境が不要に高い権限で動作する状態を検知する。

### インプット
- Dockerfile
- docker-compose.yml
- Kubernetes manifest

### 判定基準
#### 判定条件
1. Dockerfile に `USER` 指定がなく、root実行が前提  
→ 注意

2. 明示的に root 実行を指定  
→ 高リスク

3. 非rootユーザーで実行  
→ 問題なし

#### 返却値
- 条件2
  - `status: FAIL`
  - `severity: HIGH`
  - `message: "コンテナが明示的に root 権限で実行されます"`
  - `confidence: HIGH`

- 条件1
  - `status: WARN`
  - `severity: MEDIUM`
  - `message: "非rootユーザー指定がなく、root実行の可能性があります"`
  - `confidence: MEDIUM`

- 条件3
  - `status: PASS`
  - `severity: LOW`
  - `message: "非rootユーザーでの実行が設定されています"`
  - `confidence: HIGH`

---

# H：暗号（crypto）

## H-1 TLS検証無効
### 概要
HTTPS通信において証明書検証を無効にしている実装を検知する。

### インプット
- HTTPクライアント利用コード
- 設定ファイル

### 判定基準
#### 判定条件
1. `verify=False` や同等設定を検出  
→ 高リスク

2. 開発環境限定の設定として明記されている  
→ 注意

3. 証明書検証が有効  
→ 問題なし

#### 返却値
- 条件1
  - `status: FAIL`
  - `severity: HIGH`
  - `message: "TLS証明書の検証が無効化されています"`
  - `confidence: HIGH`

- 条件2
  - `status: WARN`
  - `severity: MEDIUM`
  - `message: "TLS検証無効が確認されました。開発用途限定か確認が必要です"`
  - `confidence: MEDIUM`

- 条件3
  - `status: PASS`
  - `severity: LOW`
  - `message: "TLS証明書検証は有効です"`
  - `confidence: HIGH`

---
# 共通返却形式

## 返却オブジェクト
```json
{
  "rule_id": "A-1",
  "title": "OSコマンドインジェクション",
  "status": "FAIL",
  "severity": "HIGH",
  "message": "外部入力を用いてシェルコマンドを組み立てて実行しています",
  "evidence": [
    {
      "file": "app/main.py",
      "line": 42,
      "snippet": "subprocess.run(f'ping {host}', shell=True)"
    }
  ],
  "confidence": "HIGH"
}