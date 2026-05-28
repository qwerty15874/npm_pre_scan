from enum import Enum
from typing import Optional

from .registry import get_package_info
from .typosquat import check_typosquat, load_top_packages
from .age_check import check_age_and_downloads
from .maintainer import check_maintainer_change
from .namespace import check_namespace_conflict, load_top_scoped_packages


class Verdict(str, Enum):
    PASS = "PASS"
    SUSPECT = "SUSPECT"
    BLOCK = "BLOCK"
    ERROR = "ERROR"


_SEVERITY_ORDER = {"BLOCK": 3, "SUSPECT": 2, "INFO": 1}


def _aggregate_verdict(findings: list[dict]) -> Verdict:
    for f in findings:
        if f.get("severity") == "BLOCK":
            return Verdict.BLOCK
    for f in findings:
        if f.get("severity") == "SUSPECT":
            return Verdict.SUSPECT
    return Verdict.PASS


def run_layer0(
    package_name: str,
    top_packages: Optional[list[str]] = None,
    top_scoped: Optional[list[str]] = None,
) -> dict:
    """
    Run all Layer 0 metadata checks against a package name.

    Returns:
        {
            "package": str,
            "verdict": "PASS" | "SUSPECT" | "BLOCK" | "ERROR",
            "findings": [ { "check": str, "severity": str, "message": str, ... } ]
        }
    """
    if top_packages is None:
        top_packages = load_top_packages()
    if top_scoped is None:
        top_scoped = load_top_scoped_packages()

    findings: list[dict] = []

    # --- Check 1: Typosquatting ---
    ts = check_typosquat(package_name, top_packages)
    if ts:
        findings.append({"check": "typosquat", **ts})

    # --- Check 2: Namespace conflict ---
    ns = check_namespace_conflict(package_name, top_scoped)
    if ns:
        findings.append({"check": "namespace", **ns})

    # --- Fetch registry metadata for remaining checks ---
    info = get_package_info(package_name)
    if info is None:
        # Package not on registry — could be local/private; skip registry checks
        verdict = _aggregate_verdict(findings)
        return {
            "package": package_name,
            "verdict": verdict.value,
            "findings": findings,
            "note": "Package not found on npm registry; registry-based checks skipped",
        }

    # --- Check 3: Age + download spike ---
    age = check_age_and_downloads(package_name, info)
    if age:
        findings.append({"check": "age_downloads", **age})

    # --- Check 4: Maintainer change ---
    maint = check_maintainer_change(info)
    if maint:
        findings.append({"check": "maintainer", **maint})

    verdict = _aggregate_verdict(findings)
    return {
        "package": package_name,
        "verdict": verdict.value,
        "findings": findings,
    }
