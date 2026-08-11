"""CloudGuard-IaC — shift-left security scanner for Infrastructure as Code and containers.

CloudGuard-IaC statically analyses Terraform configurations and Dockerfiles and
reports misconfigurations *before* they reach a cloud account or a registry.

Public API::

    from cloudguard import scan_paths, Severity

    result = scan_paths(["infra/"])
    if result.max_severity >= Severity.HIGH:
        ...
"""

from cloudguard.models import Finding, ScanResult, Severity
from cloudguard.rules import RULES, Rule, get_rule

__all__ = [
    "RULES",
    "Finding",
    "Rule",
    "ScanResult",
    "Severity",
    "__version__",
    "get_rule",
    "scan_paths",
]

__version__ = "1.0.0"


def scan_paths(*args: object, **kwargs: object) -> "ScanResult":
    """Lazy re-export of :func:`cloudguard.engine.scan_paths`.

    Imported lazily so that ``import cloudguard`` stays cheap for consumers that
    only need the data models (for example a custom reporter).
    """
    from cloudguard.engine import scan_paths as _scan_paths

    return _scan_paths(*args, **kwargs)  # type: ignore[arg-type]
