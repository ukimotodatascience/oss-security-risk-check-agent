#!/usr/bin/env bash
set -euo pipefail

# OS の判定（Linux 以外は拒否: P2）
OS_NAME="$(uname -s)"
if [ "${OS_NAME}" != "Linux" ]; then
  echo "Error: Scorecard pre-installation only supports Linux environment (got ${OS_NAME})" >&2
  exit 1
fi

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

# 配置先ディレクトリの設定（アプリ専用キャッシュパスに限定）
HOME_CACHE="$HOME/.cache"
CACHE_DIR="${HOME_CACHE}/oss_security_agent"
CACHE_BIN="${CACHE_DIR}/bin"

# シンボリックリンクのチェック（祖先ディレクトリ $HOME/.cache を含む: P2）
if [ -h "${HOME_CACHE}" ] || [ -L "${HOME_CACHE}" ] || \
   [ -h "${CACHE_DIR}" ] || [ -L "${CACHE_DIR}" ] || \
   [ -h "${CACHE_BIN}" ] || [ -L "${CACHE_BIN}" ]; then
  echo "Error: Dedicated cache path or its parent directory (${HOME_CACHE}) must not be a symbolic link." >&2
  exit 1
fi

mkdir -p "${HOME_CACHE}"
mkdir -p "${CACHE_DIR}"
mkdir -p "${CACHE_BIN}"

# 安全な権限設定 (chmod 700) - 不安全な場合は失敗終了 (P2)
chmod 700 "${CACHE_DIR}" "${CACHE_BIN}" 2>/dev/null || {
  echo "Error: Could not set secure permissions (chmod 700) on ${CACHE_BIN}" >&2
  exit 1
}

# 孤立した作業用一時ディレクトリの作成とクリーンアップ trap (P2)
TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

SCORECARD_TAR="scorecard_4.13.1_linux_${ARCH_KEY}.tar.gz"
SCORECARD_URL="https://github.com/ossf/scorecard/releases/download/v4.13.1/${SCORECARD_TAR}"

# OpenSSF Scorecard v4.13.1 の安全取得 (1回15s, リトライ上限35s, 総計<50s, 100MB制限: P2)
echo "Installing OpenSSF Scorecard v4.13.1 (${ARCH_KEY}) for Streamlit environment..."
curl -sSL --max-time 15 --retry 2 --retry-max-time 35 --max-filesize 104857600 "${SCORECARD_URL}" -o "${TMP_DIR}/${SCORECARD_TAR}"

# SHA-256 チェックサムの照合・検証
if command -v sha256sum >/dev/null 2>&1; then
  echo "${EXPECTED_SHA256}  ${TMP_DIR}/${SCORECARD_TAR}" | sha256sum -c -
elif command -v shasum >/dev/null 2>&1; then
  echo "${EXPECTED_SHA256}  ${TMP_DIR}/${SCORECARD_TAR}" | shasum -a 256 -c -
else
  ACTUAL_SHA256="$(openssl dgst -sha256 "${TMP_DIR}/${SCORECARD_TAR}" | awk '{print $NF}')"
  if [ "${ACTUAL_SHA256}" != "${EXPECTED_SHA256}" ]; then
    echo "Error: Checksum mismatch! Expected ${EXPECTED_SHA256}, got ${ACTUAL_SHA256}" >&2
    exit 1
  fi
fi

# 解凍および安全配置
tar -xzf "${TMP_DIR}/${SCORECARD_TAR}" -C "${TMP_DIR}"
BIN_FILE="$(find "${TMP_DIR}" -maxdepth 1 -type f -name "scorecard*" ! -name "*.tar.gz" | head -n 1)"
if [ -z "${BIN_FILE}" ] || [ ! -f "${BIN_FILE}" ]; then
  echo "Error: Could not find extracted scorecard binary in archive" >&2
  exit 1
fi
chmod 0755 "${BIN_FILE}"

TARGET_BIN="${CACHE_BIN}/scorecard"

# 配置先の既存ファイルがシンボリックリンクであるかを検査して拒否 (P2)
if [ -h "${TARGET_BIN}" ] || [ -L "${TARGET_BIN}" ]; then
  echo "Error: Target binary destination (${TARGET_BIN}) must not be a symbolic link." >&2
  exit 1
fi

# アプリ専用キャッシュパスへのアトミックな配置
TMP_TARGET="${CACHE_BIN}/.scorecard.tmp.$$"
cp "${BIN_FILE}" "${TMP_TARGET}"
chmod 0755 "${TMP_TARGET}"
mv -f "${TMP_TARGET}" "${TARGET_BIN}"
chmod 0755 "${TARGET_BIN}"

# PATH の反映（現在のシェル環境および GitHub Actions 環境への引き継ぎ）
export PATH="${CACHE_BIN}:$PATH"
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "${CACHE_BIN}" >> "${GITHUB_PATH}"
fi

echo "Scorecard v4.13.1 (${ARCH_KEY}) successfully installed and verified."
