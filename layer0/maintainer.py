from datetime import datetime, timezone, timedelta
from typing import Optional

MAINTAINER_CHANGE_WINDOW_DAYS = 30


def _extract_maintainer_names(maintainers: list) -> set[str]:
    result = set()
    for m in maintainers:
        if isinstance(m, dict):
            result.add(m.get("name", ""))
        elif isinstance(m, str):
            result.add(m)
    return result - {""}


def check_maintainer_change(info: dict) -> Optional[dict]:
    """
    Detect if the latest version was published by a maintainer not present
    in the first version. Flags account-takeover / suspicious handoff scenarios.
    """
    versions = info.get("versions", {})
    time_data = info.get("time", {})

    if not versions or not time_data:
        return None

    # Sort versions by publish time
    def version_time(v):
        ts = time_data.get(v, "")
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    sorted_versions = sorted(versions.keys(), key=version_time)
    if len(sorted_versions) < 2:
        return None

    first_version = sorted_versions[0]
    latest_version = sorted_versions[-1]

    first_maintainers = _extract_maintainer_names(
        versions[first_version].get("maintainers", [])
    )
    latest_maintainers = _extract_maintainer_names(
        versions[latest_version].get("maintainers", [])
    )

    new_maintainers = latest_maintainers - first_maintainers
    if not new_maintainers:
        return None

    # Check if the new maintainer appeared recently
    latest_time = version_time(latest_version)
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAINTAINER_CHANGE_WINDOW_DAYS)
    if latest_time < cutoff:
        return None

    return {
        "severity": "SUSPECT",
        "message": (
            f"New maintainer(s) appeared in latest version '{latest_version}': "
            f"{', '.join(sorted(new_maintainers))}"
        ),
        "first_maintainers": sorted(first_maintainers),
        "latest_maintainers": sorted(latest_maintainers),
        "new_maintainers": sorted(new_maintainers),
        "latest_version": latest_version,
    }
