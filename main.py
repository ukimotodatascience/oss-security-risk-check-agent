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
    mvp: bool = True


class Main:
    """スクリプト実行時のブートストラップとスキャンの起動。"""

    @classmethod
    def parse_args(cls, argv: list[str] | None = None) -> CliOptions:
        """CLI 引数を読み取り、必要な値だけをアプリケーションへ渡す。"""

        parser = argparse.ArgumentParser(
            description="OSS プロジェクトのセキュリティリスクを静的診断します。"
        )
        parser.add_argument(
            "target_url",
            nargs="?",
            default=None,
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
            help="スキャン結果 JSON の出力先ディレクトリ",
        )
        parser.add_argument(
            "--mvp",
            action="store_true",
            help="8カテゴリ MVP 診断モード（GitHub Pages 用 JSON 生成）で実行する",
        )
        parser.add_argument(
            "--legacy",
            action="store_true",
            help="旧仕様の Markdown レポート出力モードで実行する",
        )

        args = parser.parse_args(argv)

        is_mvp = bool(args.mvp)

        return CliOptions(
            target_url=args.target_url,
            target_ref=args.target_ref,
            target_subdir=args.target_subdir,
            output_dir=args.output_dir,
            mvp=is_mvp,
        )

    @classmethod
    def project_root(cls) -> Path:
        """プロジェクトのルートディレクトリを返す"""
        return Path(__file__).resolve().parent

    @classmethod
    def run(cls) -> None:
        root = cls.project_root()
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))

        options = cls.parse_args()

        if options.mvp:
            from src.orchestrator import MVPOrchestrator
            from src.targets.url_validator import parse_github_repo_url

            target_url = options.target_url
            if not target_url:
                try:
                    from src.config import ScanConfig

                    cfg = ScanConfig(root)
                    target_url = cfg.resolve_target_spec().repo_url
                except Exception:
                    pass

            target_url = (
                target_url
                or "https://github.com/ukimotodatascience/oss-security-risk-check-agent"
            )
            try:
                ref = parse_github_repo_url(target_url)
                safe_url = f"https://github.com/{ref.owner}/{ref.repo}"
            except Exception as e:
                print(f"[!] Error: Invalid target URL specified: {e}", file=sys.stderr)
                sys.exit(1)

            effective_options = CliOptions(
                target_url=safe_url,
                target_ref=options.target_ref,
                target_subdir=options.target_subdir,
                output_dir=options.output_dir,
                mvp=options.mvp,
            )

            out_dir = Path(options.output_dir) if options.output_dir else None

            print(f"[*] Running MVP OSS Security Scan for {safe_url}...")
            orchestrator = MVPOrchestrator(root, cli_options=effective_options)
            result = orchestrator.run_full_scan(
                safe_url, save_to_docs=True, output_dir=out_dir
            )
            print(
                f"[+] Scan completed! Overall Score: {result.overall_score}/10, Status: {result.status.value}"
            )
            save_dest = (
                out_dir / "scan_result.json" if out_dir else "docs/scan_result.json"
            )
            print(f"[+] Result saved to {save_dest} for GitHub Pages UI.")
        else:
            from src.config import ScanConfig
            from src.logger import setup_logging
            from src.scan import SecurityScan

            config = ScanConfig(root)
            setup_logging(
                level=config.resolve_log_level(), log_file=config.resolve_log_file()
            )
            SecurityScan(root, cli_options=options).run()


if __name__ == "__main__":
    Main.run()
