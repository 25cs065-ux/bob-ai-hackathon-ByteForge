from shared.schemas import Incident

# ---------------------------------------------------------------------------
# Fields in alert.raw_data that carry explicit reputation context.
# We read ONLY these fields — never infer reputation from the IP value itself.
# ---------------------------------------------------------------------------
_REPUTATION_FIELDS  = ("reputation", "ip_reputation")
_KNOWN_BAD_FIELDS   = ("known_bad", "malicious")
_THREAT_LEVEL_FIELD = "threat_level"

# Additional indicator types that may exist in raw_data
_EXTRA_INDICATOR_FIELDS = (
    ("hash",      "hash"),
    ("domain",    "domain"),
    ("indicator", "indicator"),
)


def _normalise_reputation(value) -> str:
    """Map raw source values to a controlled vocabulary string."""
    if value is None:
        return "unknown"
    s = str(value).strip().lower()
    if s in ("malicious", "bad", "evil", "hostile"):
        return "malicious"
    if s in ("suspicious", "suspect", "warn", "warning"):
        return "suspicious"
    if s in ("clean", "safe", "good", "benign", "ok"):
        return "clean"
    if s in ("unknown", ""):
        return "unknown"
    return s  # pass through any other non-empty string as-is


def _normalise_known_bad(value) -> bool:
    """Coerce a raw_data value to a boolean without inventing information."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return False


def _build_ip_indicator(ip: str, raw_data: dict) -> dict:
    """
    Build a single IP indicator dict from explicitly supplied raw_data fields.

    Rules:
    - reputation is derived only from 'reputation', 'ip_reputation', or
      'threat_level' fields that are already in raw_data.
    - known_bad is derived only from 'known_bad' or 'malicious' fields.
    - known_bad is NEVER automatically set to True merely because
      reputation == "malicious".  The two fields are independent.
    - If no explicit fields are present, reputation="unknown" and
      known_bad=False.
    """
    reputation = "unknown"
    known_bad  = False

    # --- reputation ---
    for field in _REPUTATION_FIELDS:
        if field in raw_data:
            reputation = _normalise_reputation(raw_data[field])
            break
    # Fall back to threat_level if no dedicated reputation field found
    if reputation == "unknown" and _THREAT_LEVEL_FIELD in raw_data:
        reputation = _normalise_reputation(raw_data[_THREAT_LEVEL_FIELD])

    # --- known_bad: ONLY from an explicit flag in raw_data ---
    for field in _KNOWN_BAD_FIELDS:
        if field in raw_data:
            known_bad = _normalise_known_bad(raw_data[field])
            break

    return {
        "type":       "ip",
        "value":      ip,
        "reputation": reputation,
        "known_bad":  known_bad,
    }


def _build_extra_indicators(raw_data: dict) -> list:
    """
    Extract hash / domain / generic indicator values already in raw_data.
    Reputation and known_bad are copied from raw_data if present;
    they are never invented.
    """
    extras = []
    for field, itype in _EXTRA_INDICATOR_FIELDS:
        if field in raw_data and raw_data[field]:
            extras.append({
                "type":       itype,
                "value":      str(raw_data[field]),
                "reputation": _normalise_reputation(raw_data.get("reputation")),
                "known_bad":  _normalise_known_bad(raw_data.get("known_bad", False)),
            })
    return extras


def enrich_with_threat_intel(incident: Incident) -> Incident:
    """
    Feature #10: Threat Intelligence Enrichment.
    Fill: incident.threat_intel (dict with "indicators" list and "summary" dict)

    Builds the threat-intel picture purely from information already present
    in incident.alerts (alert.ip and alert.raw_data).
    No external calls, no network requests, no invented data.
    """
    seen_keys: set  = set()   # deduplicate by (type, value)
    indicators: list = []

    for alert in (incident.alerts or []):
        # Guard: raw_data must be a dict; tolerate None or other unexpected types
        raw_data = alert.raw_data if isinstance(alert.raw_data, dict) else {}

        # --- IP indicator ---
        if alert.ip:
            key = ("ip", alert.ip)
            if key not in seen_keys:
                seen_keys.add(key)
                indicators.append(_build_ip_indicator(alert.ip, raw_data))

        # --- Additional indicators from raw_data ---
        for extra in _build_extra_indicators(raw_data):
            key = (extra["type"], extra["value"])
            if key not in seen_keys:
                seen_keys.add(key)
                indicators.append(extra)

    known_bad_count = sum(1 for ind in indicators if ind.get("known_bad"))

    incident.threat_intel = {
        "indicators": indicators,
        "summary": {
            "total_indicators": len(indicators),
            "known_bad_count":  known_bad_count,
        },
    }
    return incident
