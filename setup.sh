#!/usr/bin/env bash
set -euo pipefail

# bin ディレクトリの作成
mkdir -p "$HOME/.local/bin"

# アーキテクチャの判定
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|amd64)
    ARCH_KEY="amd64"
    ;;
  aarch64|arm64)
    ARCH_KEY="arm64"
    ;;
  *)
    echo "Error: Unsupported architecture for Scorecard pre-install: ${ARCH}" >&2
    exit 1
    ;;
esac

# OpenSSF Scorecard v4.13.1 の安全取得と配置
echo "Installing OpenSSF Scorecard v4.13.1 (${ARCH_KEY}) for Streamlit environment..."
SCORECARD_TAR="scorecard_4.13.1_linux_${ARCH_KEY}.tar.gz"
SCORECARD_URL="https://github.com/ossf/scorecard/releases/download/v4.13.1/${SCORECARD_TAR}"

curl -sSL --max-time 60 --retry 3 "${SCORECARD_URL}" -o "${SCORECARD_TAR}"
tar -xzf "${SCORECARD_TAR}" scorecard
mv scorecard "$HOME/.local/bin/scorecard"
chmod +x "$HOME/.local/bin/scorecard"
rm -f "${SCORECARD_TAR}"

# PATH の反映
export PATH="$HOME/.local/bin:$PATH"

echo "Scorecard v4.13.1 (${ARCH_KEY}) successfully installed to $HOME/.local/bin/scorecard"
