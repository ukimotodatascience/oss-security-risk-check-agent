#!/usr/bin/env bash
set -euo pipefail

# bin ディレクトリの作成
mkdir -p "$HOME/.local/bin"

# OpenSSF Scorecard v4.13.1 の安全取得と配置
echo "Installing OpenSSF Scorecard v4.13.1 for Streamlit environment..."
SCORECARD_TAR="scorecard_4.13.1_linux_amd64.tar.gz"
SCORECARD_URL="https://github.com/ossf/scorecard/releases/download/v4.13.1/${SCORECARD_TAR}"

curl -sSL "${SCORECARD_URL}" -o "${SCORECARD_TAR}"
tar -xzf "${SCORECARD_TAR}" scorecard
mv scorecard "$HOME/.local/bin/scorecard"
chmod +x "$HOME/.local/bin/scorecard"
rm -f "${SCORECARD_TAR}"

# PATH の反映
export PATH="$HOME/.local/bin:$PATH"

echo "Scorecard v4.13.1 successfully installed to $HOME/.local/bin/scorecard"
