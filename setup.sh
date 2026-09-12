#!/usr/bin/env bash
set -euo pipefail

# アーキテクチャの判定とチェックサム設定
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|amd64)
    ARCH_KEY="amd64"
    EXPECTED_SHA256="53aa07786f2d985d0755ff9caad4e38c0a22596708de0728c5274f84ae48f785"
    ;;
  aarch64|arm64)
    ARCH_KEY="arm64"
    EXPECTED_SHA256="d59d75eec0e91abbe65365b866fd0f298ddb9f4bcdda207a7f650720015d0f4f"
    ;;
  *)
    echo "Error: Unsupported architecture for Scorecard pre-install: ${ARCH}" >&2
    exit 1
    ;;
esac

# 配置先ディレクトリの作成（アプリ専用キャッシュパスを最優先）
LOCAL_BIN="$HOME/.local/bin"
CACHE_DIR="$HOME/.cache/oss_security_agent"
CACHE_BIN="${CACHE_DIR}/bin"

mkdir -p "${LOCAL_BIN}"
mkdir -p "${CACHE_BIN}"

# 安全な権限設定 (chmod 700) - 権限変更失敗時は警告を出力
chmod 700 "${CACHE_DIR}" "${CACHE_BIN}" 2>/dev/null || {
  echo "Warning: Could not set secure permissions (chmod 700) on ${CACHE_BIN}" >&2
}

SCORECARD_TAR="scorecard_4.13.1_linux_${ARCH_KEY}.tar.gz"
SCORECARD_URL="https://github.com/ossf/scorecard/releases/download/v4.13.1/${SCORECARD_TAR}"

# 終了時に一時ファイルを確実に削除するクリーンアップ trap を登録 (P2)
cleanup() {
  rm -f "${SCORECARD_TAR}" scorecard 2>/dev/null || true
}
trap cleanup EXIT

# OpenSSF Scorecard v4.13.1 の安全取得 (100MBサイズ制限)
echo "Installing OpenSSF Scorecard v4.13.1 (${ARCH_KEY}) for Streamlit environment..."
curl -sSL --max-time 60 --retry 3 --max-filesize 104857600 "${SCORECARD_URL}" -o "${SCORECARD_TAR}"

# SHA-256 チェックサムの照合・検証 (P1)
if command -v sha256sum >/dev/null 2>&1; then
  echo "${EXPECTED_SHA256}  ${SCORECARD_TAR}" | sha256sum -c -
elif command -v shasum >/dev/null 2>&1; then
  echo "${EXPECTED_SHA256}  ${SCORECARD_TAR}" | shasum -a 256 -c -
else
  ACTUAL_SHA256="$(openssl dgst -sha256 "${SCORECARD_TAR}" | awk '{print $NF}')"
  if [ "${ACTUAL_SHA256}" != "${EXPECTED_SHA256}" ]; then
    echo "Error: Checksum mismatch! Expected ${EXPECTED_SHA256}, got ${ACTUAL_SHA256}" >&2
    exit 1
  fi
fi

# 解凍および安全配置
tar -xzf "${SCORECARD_TAR}" scorecard
chmod 0755 scorecard

# アプリ専用キャッシュパスへの配置
cp scorecard "${CACHE_BIN}/scorecard"
chmod 0755 "${CACHE_BIN}/scorecard"

# 既存のユーザーバイナリを不用意に上書きしない保護 (P2)
if [ ! -f "${LOCAL_BIN}/scorecard" ]; then
  cp scorecard "${LOCAL_BIN}/scorecard"
  chmod 0755 "${LOCAL_BIN}/scorecard"
fi

# PATH の反映
export PATH="${CACHE_BIN}:${LOCAL_BIN}:$PATH"

echo "Scorecard v4.13.1 (${ARCH_KEY}) successfully installed and verified."
