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

# 孤立した作業用一時ディレクトリと自身の配置一時ファイルの作成・クリーンアップ trap (P2)
TMP_DIR="$(mktemp -d)"
TMP_TARGET=""
cleanup() {
  if [ -n "${TMP_TARGET:-}" ] && [ -f "${TMP_TARGET}" ]; then
    rm -f "${TMP_TARGET}" 2>/dev/null || true
  fi
  rm -rf "${TMP_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

# シンボリックリンクのチェック（$HOME および祖先ディレクトリを含む: P2）
if [ -h "$HOME" ] || [ -L "$HOME" ] || \
   [ -h "${HOME_CACHE}" ] || [ -L "${HOME_CACHE}" ] || \
   [ -h "${CACHE_DIR}" ] || [ -L "${CACHE_DIR}" ] || \
   [ -h "${CACHE_BIN}" ] || [ -L "${CACHE_BIN}" ]; then
  echo "Error: Dedicated cache path or its parent directory ($HOME) must not be a symbolic link." >&2
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

# 親ディレクトリおよび祖先パスのセキュリティ検証 ($HOME で走査停止・app.py の _is_secure_directory と同等基準: P2)
if command -v python3 >/dev/null 2>&1; then
  if ! python3 -c '
import sys, os, pathlib
dir_path = pathlib.Path(sys.argv[1])
uid = os.getuid()

if dir_path.is_symlink() or os.path.islink(dir_path):
    sys.exit(1)

if dir_path.exists():
    st = dir_path.lstat()
    if st.st_uid != uid or (st.st_mode & 0o077 != 0):
        sys.exit(1)

home = pathlib.Path.home()
home_resolved = home.resolve()
curr = dir_path
while True:
    if curr == home or curr == home_resolved or curr == curr.parent:
        break
    parent = curr.parent
    if parent.exists():
        if parent.is_symlink() or os.path.islink(parent):
            sys.exit(1)
        p_st = parent.lstat()
        if p_st.st_uid not in (uid, 0) or (p_st.st_mode & 0o022 != 0):
            sys.exit(1)
    if parent == home or parent == home_resolved:
        break
    curr = parent
' "${CACHE_BIN}"; then
    echo "Error: Cache directory ${CACHE_BIN} or its parent failed security check (owner matching / non-group-writable / no-symlink)." >&2
    exit 1
  fi
fi

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

# 配置先の既存パスがディレクトリまたはシンボリックリンクであるかを検査して拒否 (P2)
if [ -d "${TARGET_BIN}" ] || [ -h "${TARGET_BIN}" ] || [ -L "${TARGET_BIN}" ]; then
  echo "Error: Target binary destination (${TARGET_BIN}) must not be a directory or symbolic link." >&2
  exit 1
fi

# アプリ専用キャッシュパスへのアトミックな配置と mktemp による排他的一時ファイル管理 (P2)
TMP_TARGET="$(mktemp "${CACHE_BIN}/.scorecard.tmp.XXXXXX")"
if [ ! -f "${TMP_TARGET}" ] || [ -h "${TMP_TARGET}" ] || [ -L "${TMP_TARGET}" ]; then
  echo "Error: Failed to create exclusive temporary target file in ${CACHE_BIN}" >&2
  exit 1
fi
cp "${BIN_FILE}" "${TMP_TARGET}"
chmod 0755 "${TMP_TARGET}"
mv -f "${TMP_TARGET}" "${TARGET_BIN}"
chmod 0755 "${TARGET_BIN}"
TMP_TARGET=""

# PATH の反映（現在のシェル環境および GitHub Actions 環境への引き継ぎ）
export PATH="${CACHE_BIN}:$PATH"
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "${CACHE_BIN}" >> "${GITHUB_PATH}"
fi

echo "Scorecard v4.13.1 (${ARCH_KEY}) successfully installed and verified."
