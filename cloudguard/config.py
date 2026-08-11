"""Optional project configuration loaded from ``.cloudguard.toml``.

Command line flags always win: the file provides the defaults a team agrees on
once, so that a developer running ``cloudguard full-scan .`` locally gets exactly
the verdict the CI pipeline will produce.

Example::

    # .cloudguard.toml
    [cloudguard]
    fail_on = "HIGH"
    ignore = ["CG_IAC_015"]  # access logging handled by CloudTrail
    exclude = ["examples/vulnerable", "legacy/"]
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

from cloudguard.models import Severity

if sys.version_info >= (3, 11):  # pragma: no cover - version dependent
    import tomllib
else:  # pragma: no cover - version dependent
    import tomli as tomllib

CONFIG_FILENAME = ".cloudguard.toml"


class ConfigError(ValueError):
    """Raised when the configuration file exists but cannot be used."""


#: Values of ``fail_on`` meaning "report everything, never fail the command".
NEVER_VALUES: frozenset[str] = frozenset({"never", "none", "off"})


@dataclass
class Config:
    """Resolved configuration for a scan."""

    fail_on: Severity | None = None
    #: ``fail_on = "never"`` — distinct from "not configured", which is ``None``.
    fail_on_never: bool = False
    ignore: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    source: Path | None = None

    @property
    def is_empty(self) -> bool:
        """``True`` when nothing was configured."""
        return (
            self.fail_on is None and not self.fail_on_never and not self.ignore and not self.exclude
        )

    @property
    def configures_threshold(self) -> bool:
        """``True`` when the file has an opinion on the failure threshold."""
        return self.fail_on is not None or self.fail_on_never


def find_config(start: Path) -> Path | None:
    """Look for ``.cloudguard.toml`` in ``start`` then in its parent directories."""
    current = start.resolve()
    if current.is_file():
        current = current.parent
    for directory in [current, *current.parents]:
        candidate = directory / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
    return None


def load_config(path: Path | None) -> Config:
    """Load a configuration file, returning an empty config when ``path`` is ``None``."""
    if path is None:
        return Config()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc

    section = data.get("cloudguard", data)
    if not isinstance(section, dict):
        raise ConfigError(f"{path}: the [cloudguard] section must be a table")

    fail_on: Severity | None = None
    fail_on_never = False
    raw_fail_on = section.get("fail_on")
    if raw_fail_on is not None:
        text = str(raw_fail_on).strip().lower()
        if text in NEVER_VALUES:
            fail_on_never = True
        else:
            try:
                fail_on = Severity.parse(text)
            except ValueError as exc:
                raise ConfigError(f"{path}: {exc}") from exc

    return Config(
        fail_on=fail_on,
        fail_on_never=fail_on_never,
        ignore=tuple(str(item).strip().upper() for item in section.get("ignore", ())),
        exclude=tuple(str(item) for item in section.get("exclude", ())),
        source=path,
    )


@dataclass
class ScanSettings:
    """Effective settings after merging CLI flags with the configuration file."""

    fail_on: Severity
    ignore: frozenset[str] = field(default_factory=frozenset)
    exclude: tuple[str, ...] = ()
    config_source: Path | None = None
