from datetime import datetime, timezone, timedelta
from shared.schemas import Incident

# Sentinel for sorting: alerts whose timestamp cannot be parsed sort to the end.
# Using a timezone-naive max so we can always compare after normalisation.
_FALLBACK_SORT_KEY = datetime.max


def _parse_timestamp(ts):
    """
    Parse a timestamp string into a timezone-NAIVE UTC datetime for sorting.

    Handles:
      - Plain ISO-8601 without offset:  2026-09-10T10:00:00
      - With microseconds:              2026-09-10T10:00:00.123456
      - UTC 'Z' suffix:                 2026-09-10T10:00:00Z
      - With UTC offset:                2026-09-10T15:30:00+05:30
      - Space separator:                2026-09-10 10:00:00
      - Date only:                      2026-09-10

    Returns a naive datetime (UTC-normalised) on success,
    _FALLBACK_SORT_KEY on any failure so the alert still appears in timeline.
    """
    if not ts:
        return _FALLBACK_SORT_KEY

    s = str(ts).strip()

    # --- Strategy 1: Python 3.7+ fromisoformat handles offsets in 3.11+,
    #     but we normalise the 'Z' suffix ourselves to stay compatible with
    #     Python 3.7-3.10 where fromisoformat does not accept 'Z'. ---
    try:
        normalised = s
        if normalised.endswith("Z"):
            normalised = normalised[:-1] + "+00:00"
        dt = datetime.fromisoformat(normalised)
        # Convert to naive UTC so all timestamps are comparable
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except (ValueError, OverflowError):
        pass

    # --- Strategy 2: explicit strptime formats for older string styles ---
    naive_formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d",
    ]
    for fmt in naive_formats:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue

    return _FALLBACK_SORT_KEY


def _build_event_desc(alert) -> str:
    """Compose a human-readable one-line description for an analyst."""
    parts = []

    # Event type (prettify underscores -> spaces)
    if alert.event_type:
        parts.append(str(alert.event_type).replace("_", " ").capitalize())
    else:
        parts.append("Event")

    # Source
    if alert.source:
        parts[-1] += f" [{alert.source}]"

    # Actor / origin
    if alert.ip:
        parts.append(f"from {alert.ip}")

    # Target asset
    if alert.asset:
        parts.append(f"on {alert.asset}")

    # Severity
    if alert.severity:
        parts.append(f"(severity: {alert.severity})")

    return " ".join(parts)


def build_timeline(incident: Incident) -> Incident:
    """
    Feature #9: Attack Timeline.
    Fill: incident.attack_timeline (list of dicts: {"time": ..., "event_desc": ...})
    """
    if not incident.alerts:
        incident.attack_timeline = []
        return incident

    # Sort a shallow copy — do NOT mutate the original list or alert objects.
    try:
        sorted_alerts = sorted(
            incident.alerts,
            key=lambda a: _parse_timestamp(a.timestamp)
        )
    except Exception:
        sorted_alerts = list(incident.alerts)

    timeline = []
    for alert in sorted_alerts:
        try:
            timeline.append({
                "time": alert.timestamp if alert.timestamp is not None else "",
                "event_desc": _build_event_desc(alert),
            })
        except Exception:
            pass  # skip a single broken entry; never crash the whole function

    incident.attack_timeline = timeline
    return incident
