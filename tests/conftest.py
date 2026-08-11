"""Shared fixtures: paths to the example corpus and file factories."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VULNERABLE_DIR = PROJECT_ROOT / "examples" / "vulnerable"
SECURE_DIR = PROJECT_ROOT / "examples" / "secure"


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Repository root."""
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def vulnerable_dir() -> Path:
    """Directory holding the intentionally insecure examples."""
    return VULNERABLE_DIR


@pytest.fixture(scope="session")
def secure_dir() -> Path:
    """Directory holding the hardened examples."""
    return SECURE_DIR


@pytest.fixture
def runner() -> CliRunner:
    """Click/Typer runner used to exercise the CLI end to end."""
    return CliRunner()


@pytest.fixture
def write_tf(tmp_path: Path) -> Callable[[str], Path]:
    """Write a Terraform snippet to a temporary directory and return the directory."""

    def _write(content: str, name: str = "main.tf") -> Path:
        (tmp_path / name).write_text(content, encoding="utf-8")
        return tmp_path

    return _write


@pytest.fixture
def write_dockerfile(tmp_path: Path) -> Callable[[str], Path]:
    """Write a Dockerfile to a temporary directory and return its path."""

    def _write(content: str, name: str = "Dockerfile") -> Path:
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        return path

    return _write
