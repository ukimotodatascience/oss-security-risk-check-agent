from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CliOptions:
    """コマンドラインから指定されたスキャン対象オプション。"""

    target_url: str | None = None
    target_ref: str | None = None
    target_subdir: str | None = None
    output_dir: str | None = None


class Main:
    """スクリプト実行時のブートストラップと `SecurityScan` の起動。"""

    @classmethod
    def parse_args(cls, argv: list[str] | None = None) -> CliOptions:
        """CLI 引数を読み取り、必要な値だけをアプリケーションへ渡す。"""

        parser = argparse.ArgumentParser(
            description="OSS プロジェクトのセキュリティリスクを静的診断します。"
        )
        parser.add_argument(
            "target_url",
            nargs="?",
            help="スキャン対象の GitHub URL（例: https://github.com/owner/repo）",
        )
        parser.add_argument(
            "--ref",
            dest="target_ref",
            help="GitHub archive 取得時のブランチ・タグ・コミット（例: main）",
        )
        parser.add_argument(
            "--subdir",
            dest="target_subdir",
            help="リポジトリ内の一部ディレクトリだけをスキャンする場合に指定",
        )
        parser.add_argument(
            "--output-dir",
            dest="output_dir",
            help="Markdown レポートの出力先ディレクトリ",
        )

        args = parser.parse_args(argv)
        return CliOptions(
            target_url=args.target_url,
            target_ref=args.target_ref,
            target_subdir=args.target_subdir,
            output_dir=args.output_dir,
        )

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

        SecurityScan(root, cli_options=cls.parse_args()).run()


if __name__ == "__main__":
    Main.run()
