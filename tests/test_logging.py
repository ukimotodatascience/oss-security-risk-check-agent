from __future__ import annotations

import logging
from pathlib import Path

import pytest

from src.config import ScanConfig
from src.logger import setup_logging


def test_resolve_log_level_defaults_to_info(tmp_path, monkeypatch):
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    config = ScanConfig(tmp_path)
    assert config.resolve_log_level() == "INFO"


def test_resolve_log_level_valid_levels(tmp_path, monkeypatch):
    config = ScanConfig(tmp_path)
    for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        monkeypatch.setenv("LOG_LEVEL", level)
        assert config.resolve_log_level() == level

        # Case insensitivity
        monkeypatch.setenv("LOG_LEVEL", level.lower())
        assert config.resolve_log_level() == level


def test_resolve_log_level_invalid_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "INVALID_LEVEL")
    config = ScanConfig(tmp_path)
    assert config.resolve_log_level() == "INFO"


def test_resolve_log_file(tmp_path, monkeypatch):
    # Not set -> None
    monkeypatch.delenv("LOG_FILE", raising=False)
    config = ScanConfig(tmp_path)
    assert config.resolve_log_file() is None

    # Set -> Path
    monkeypatch.setenv("LOG_FILE", "my_scan.log")
    log_file = config.resolve_log_file()
    assert log_file is not None
    assert log_file.name == "my_scan.log"


def test_setup_logging_configures_root_logger(tmp_path):
    log_file = tmp_path / "subdir" / "test.log"

    setup_logging(level="DEBUG", log_file=log_file)

    root_logger = logging.getLogger()
    assert root_logger.level == logging.DEBUG

    # Check if file handler is added and file path is correct
    handlers = root_logger.handlers
    assert len(handlers) >= 1

    file_handlers = [h for h in handlers if isinstance(h, logging.FileHandler)]
    assert len(file_handlers) == 1
    assert Path(file_handlers[0].baseFilename) == log_file.resolve()
