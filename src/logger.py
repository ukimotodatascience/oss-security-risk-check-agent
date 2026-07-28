from __future__ import annotations

import logging
import sys
from pathlib import Path


def setup_logging(level: str = "INFO", log_file: Path | None = None) -> None:
    """アプリケーション全体のロギングを設定する。

    Args:
        level: ログレベル文字列 ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")。
        log_file: ログ出力先ファイルパス。
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    handlers: list[logging.Handler] = []

    # 標準出力へのハンドラー
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    console_handler.setFormatter(formatter)
    handlers.append(console_handler)

    # ファイルへのハンドラー（指定された場合）
    if log_file:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(numeric_level)
            file_handler.setFormatter(formatter)
            handlers.append(file_handler)
        except Exception as exc:
            # ログファイルの作成に失敗した場合は標準エラー出力に警告を出して継続
            sys.stderr.write(
                f"警告: ログファイルの作成に失敗しました ({log_file}): {exc}\n"
            )

    logging.basicConfig(
        level=numeric_level,
        handlers=handlers,
        force=True,  # 既存の基本的な設定があれば上書きする
    )
