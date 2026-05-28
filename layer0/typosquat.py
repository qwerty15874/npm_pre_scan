import os
from typing import Optional

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    m, n = len(a), len(b)
    # Use two rows to reduce memory
    prev = list(range(n + 1))
    curr = [0] * (n + 1)
    for i in range(1, m + 1):
        curr[0] = i
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
        prev, curr = curr, prev
    return prev[n]


def load_top_packages() -> list[str]:
    path = os.path.join(_DATA_DIR, "top_packages.txt")
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def check_typosquat(name: str, top_packages: Optional[list[str]] = None) -> dict:
    """
    Check if `name` is suspiciously close to a popular package.
    Returns {"severity": ..., "closest": ..., "distance": ...} or None if clean.
    """
    if top_packages is None:
        top_packages = load_top_packages()

    # Strip scope for comparison — @scope/name → compare "name" part
    bare_name = name.split("/")[-1] if "/" in name else name

    closest_pkg = None
    min_dist = 999

    for pkg in top_packages:
        bare_pkg = pkg.split("/")[-1] if "/" in pkg else pkg
        # Skip exact match — the package itself may be popular
        if bare_name == bare_pkg:
            return {"severity": "INFO", "closest": pkg, "distance": 0, "message": f"Exact match with known popular package '{pkg}'"}
        dist = levenshtein(bare_name, bare_pkg)
        if dist < min_dist:
            min_dist = dist
            closest_pkg = pkg

    if min_dist == 1:
        return {
            "severity": "BLOCK",
            "closest": closest_pkg,
            "distance": min_dist,
            "message": f"Very likely typosquat of '{closest_pkg}' (Levenshtein distance={min_dist})",
        }
    if min_dist == 2:
        return {
            "severity": "SUSPECT",
            "closest": closest_pkg,
            "distance": min_dist,
            "message": f"Possible typosquat of '{closest_pkg}' (Levenshtein distance={min_dist})",
        }
    return None
