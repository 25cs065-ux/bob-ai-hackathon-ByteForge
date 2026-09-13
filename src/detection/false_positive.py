from shared.schemas import Incident

# Event types that are considered inherently suspicious
_SUSPICIOUS_EVENT_TYPES = {
    "login failure",
    "authentication failure",
    "privilege escalation",
    "powershell",
    "command execution",
    "malware",
    "suspicious process",
    "data transfer",
    "file access",
    "unauthorized access",
    "lateral movement",
}

# Severity weights used to judge overall alert posture
_SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Keywords in raw_data values that raise suspicion
_RAW_DATA_SUSPICIOUS_TERMS = {
    "malware", "exploit", "ransomware", "backdoor", "c2", "command and control",
    "exfiltration", "privilege", "escalation", "unauthorized", "lateral",
    "powershell", "encoded", "obfuscated",
}

# Asset name fragments that suggest a high-value target
_IMPORTANT_ASSET_TERMS = {"critical", "server", "database", "gateway", "control"}


def _is_suspicious_event_type(event_type: str) -> bool:
    et = event_type.lower()
    return any(term in et for term in _SUSPICIOUS_EVENT_TYPES)


def _has_suspicious_raw_data(raw_data: dict) -> bool:
    for value in raw_data.values():
        if isinstance(value, str):
            v = value.lower()
            if any(term in v for term in _RAW_DATA_SUSPICIOUS_TERMS):
                return True
    return False


def _is_important_asset(asset: str) -> bool:
    a = asset.lower()
    return any(term in a for term in _IMPORTANT_ASSET_TERMS)


def check_false_positive(incident: Incident) -> Incident:
    """
    Feature #4: Threat Detection & False-Positive Reduction.
    Decide if this incident is a genuine threat or likely noise.
    Fill: incident.is_false_positive (bool), incident.false_positive_reason (str)
    """
    alerts = incident.alerts or []

    # Empty alerts — treat as false positive (no evidence at all)
    if not alerts:
        incident.is_false_positive = True
        incident.false_positive_reason = "No alerts present in incident"
        return incident

    reasons_for_suspicion = []

    # --- Count alerts and gather per-alert signals ---
    alert_count = len(alerts)
    if alert_count >= 3:
        reasons_for_suspicion.append(f"high alert volume ({alert_count} alerts)")

    high_critical_count = sum(
        1 for a in alerts if a.severity in ("high", "critical")
    )
    if high_critical_count > 0:
        reasons_for_suspicion.append(
            f"{high_critical_count} high/critical severity alert(s)"
        )

    suspicious_event_count = sum(
        1 for a in alerts if a.event_type and _is_suspicious_event_type(a.event_type)
    )
    if suspicious_event_count > 0:
        reasons_for_suspicion.append(
            f"{suspicious_event_count} suspicious event type(s)"
        )

    # Repeated suspicious events (same event_type appears more than once)
    from collections import Counter
    event_type_counts = Counter(
        a.event_type.lower() for a in alerts if a.event_type
    )
    repeated = [et for et, cnt in event_type_counts.items() if cnt > 1]
    if repeated:
        reasons_for_suspicion.append(
            f"repeated suspicious events: {', '.join(repeated)}"
        )

    # Source diversity
    unique_sources = {a.source for a in alerts if a.source}
    if len(unique_sources) > 1:
        reasons_for_suspicion.append(
            f"alerts from multiple sources: {', '.join(sorted(unique_sources))}"
        )

    # Suspicious IP patterns (RFC 1918 private-space IPs are normal;
    # non-private or multiple distinct IPs are more suspicious)
    ips = [a.ip for a in alerts if a.ip]
    unique_ips = set(ips)
    if len(unique_ips) > 1:
        reasons_for_suspicion.append(f"multiple distinct IPs ({len(unique_ips)})")

    # Important-looking assets
    important_assets = [
        a.asset for a in alerts if a.asset and _is_important_asset(a.asset)
    ]
    if important_assets:
        reasons_for_suspicion.append(
            f"high-value asset(s) targeted: {', '.join(set(important_assets))}"
        )

    # Suspicious raw_data content
    raw_data_hits = [a for a in alerts if _has_suspicious_raw_data(a.raw_data)]
    if raw_data_hits:
        reasons_for_suspicion.append(
            f"{len(raw_data_hits)} alert(s) with suspicious payload content"
        )

    # --- Decision logic ---
    # Treat as genuine threat if ANY suspicion signal is present
    if reasons_for_suspicion:
        incident.is_false_positive = False
        incident.false_positive_reason = (
            "Incident flagged as genuine threat: " + "; ".join(reasons_for_suspicion)
        )
    else:
        # Single low-severity, non-suspicious alert with no other indicators
        incident.is_false_positive = True
        incident.false_positive_reason = (
            "Single low-severity alert with no suspicious indicators "
            "(event type, asset, source diversity, or payload)"
        )

    return incident
