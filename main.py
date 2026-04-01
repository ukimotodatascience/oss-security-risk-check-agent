from __future__ import annotations

import sys
from pathlib import Path


class Main:
    """スクリプト実行時のブートストラップと `SecurityScan` の起動。"""

    @classmethod
    def project_root(cls) -> Path:
        """プロジェクトのルートディレクトリを返す"""
        return Path(__file__).resolve().parent

    @classmethod
    def run(cls) -> None:
        """プロジェクトのルートディレクトリを取得し、SecurityScanを起動"""
        root = cls.project_root()
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))

        from src.scan import SecurityScan

        SecurityScan(root).run()


if __name__ == "__main__":
    Main.run()
