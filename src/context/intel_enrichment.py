from shared.schemas import Incident

_REPUTATION_FIELDS  = ("reputation", "ip_reputation")
_KNOWN_BAD_FIELDS   = ("known_bad", "malicious")
_THREAT_LEVEL_FIELD = "threat_level"

_EXTRA_INDICATOR_FIELDS = (
    ("hash",      "hash"),
    ("domain",    "domain"),
    ("indicator", "indicator"),
)


def _normalise_reputation(value) -> str:
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
    return s


def _normalise_known_bad(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return False


def _build_ip_indicator(ip: str, raw_data: dict) -> dict:
    reputation = "unknown"
    known_bad  = False

    for field in _REPUTATION_FIELDS:
        if field in raw_data:
            reputation = _normalise_reputation(raw_data[field])
            break
    if reputation == "unknown" and _THREAT_LEVEL_FIELD in raw_data:
        reputation = _normalise_reputation(raw_data[_THREAT_LEVEL_FIELD])

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
    """
    seen_keys: set  = set()
    indicators: list = []

    for alert in (incident.alerts or []):
        raw_data = alert.raw_data if isinstance(alert.raw_data, dict) else {}

        if alert.ip:
            key = ("ip", alert.ip)
            if key not in seen_keys:
                seen_keys.add(key)
                indicators.append(_build_ip_indicator(alert.ip, raw_data))

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


if __name__ == "__main__":
    from shared.schemas import Incident, NormalizedAlert

    sample_alert = NormalizedAlert(
        alert_id="TEST-001",
        timestamp="2024-01-15T10:00:00Z",
        source="siem",
        ip="203.0.113.10",
        asset="server-01",
        severity="critical",
        event_type="privilege_escalation",
        raw_data={"reputation": "malicious", "known_bad": True},
    )
    incident = Incident(incident_id="INC-TEST-001", alerts=[sample_alert])

    result = enrich_with_threat_intel(incident)
    print("threat_intel:", result.threat_intel)