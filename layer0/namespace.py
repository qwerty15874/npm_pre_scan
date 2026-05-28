import os
from typing import Optional

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


def load_top_scoped_packages() -> list[str]:
    path = os.path.join(_DATA_DIR, "top_scoped_packages.txt")
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def check_namespace_conflict(name: str, top_scoped: Optional[list[str]] = None) -> Optional[dict]:
    """
    Detect if an unscoped package name conflicts with a popular scoped package.
    Attack pattern: publish `aws-sdk-client-s3` when `@aws-sdk/client-s3` is popular.
    """
    # Only applies to unscoped packages
    if name.startswith("@"):
        return None

    if top_scoped is None:
        top_scoped = load_top_scoped_packages()

    # Normalize: remove scope, replace / and - with a canonical form for comparison
    def normalize(pkg: str) -> str:
        # @aws-sdk/client-s3 → aws-sdk-client-s3
        if pkg.startswith("@"):
            pkg = pkg.lstrip("@")
            pkg = pkg.replace("/", "-")
        return pkg.lower()

    name_norm = normalize(name)

    for scoped_pkg in top_scoped:
        if normalize(scoped_pkg) == name_norm:
            return {
                "severity": "BLOCK",
                "message": (
                    f"Name '{name}' conflicts with popular scoped package '{scoped_pkg}' "
                    "(possible namespace confusion attack)"
                ),
                "conflicting_scoped": scoped_pkg,
            }

    return None
