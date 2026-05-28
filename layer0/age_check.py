from .registry import get_downloads, get_package_age_days

NEW_PACKAGE_DAYS = 7
DOWNLOAD_SPIKE_RATIO = 5.0   # last-week vs last-month/4 ratio to flag spike
DOWNLOAD_SPIKE_MIN = 1000    # minimum weekly downloads to bother checking spike


def check_age_and_downloads(name: str, info: dict) -> dict | None:
    """
    Flag packages that are brand-new (<7 days) with an unusual download spike.
    Returns finding dict or None if clean.
    """
    age_days = get_package_age_days(info)
    if age_days is None:
        return None

    if age_days >= NEW_PACKAGE_DAYS:
        return None

    # New package — check for download spike (could indicate coordinated campaign)
    weekly = get_downloads(name, "last-week")
    monthly = get_downloads(name, "last-month")

    finding = {
        "age_days": round(age_days, 1),
        "weekly_downloads": weekly,
        "monthly_downloads": monthly,
    }

    if weekly and monthly and monthly > 0:
        expected_weekly = monthly / 4.0
        if weekly >= DOWNLOAD_SPIKE_MIN and weekly / expected_weekly >= DOWNLOAD_SPIKE_RATIO:
            return {
                "severity": "SUSPECT",
                "message": (
                    f"Package is {finding['age_days']} days old with unusual download spike "
                    f"({weekly} weekly vs ~{int(expected_weekly)} expected)"
                ),
                **finding,
            }

    if age_days < NEW_PACKAGE_DAYS:
        return {
            "severity": "INFO",
            "message": f"Package is very new ({finding['age_days']} days old)",
            **finding,
        }

    return None
