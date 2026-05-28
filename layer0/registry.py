import requests
from datetime import datetime, timezone
from typing import Optional

REGISTRY_BASE = "https://registry.npmjs.org"
DOWNLOADS_BASE = "https://api.npmjs.org/downloads/point"

_session = requests.Session()
_session.headers["User-Agent"] = "npm-pre-scan/0.1"


def get_package_info(name: str) -> Optional[dict]:
    url = f"{REGISTRY_BASE}/{requests.utils.quote(name, safe='@/')}"
    try:
        r = _session.get(url, timeout=10)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def get_downloads(name: str, period: str = "last-week") -> Optional[int]:
    url = f"{DOWNLOADS_BASE}/{period}/{requests.utils.quote(name, safe='@/')}"
    try:
        r = _session.get(url, timeout=10)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        data = r.json()
        return data.get("downloads")
    except Exception:
        return None


def get_package_age_days(info: dict) -> Optional[float]:
    time_field = info.get("time", {})
    created_str = time_field.get("created")
    if not created_str:
        return None
    try:
        created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return (now - created).total_seconds() / 86400
    except Exception:
        return None
