import re
from shared.schemas import NormalizedAlert
from typing import List, Optional

# ---------------------------------------------------------------------------
# Severity normalisation table
# ---------------------------------------------------------------------------
_SEVERITY_MAP = {
    "info":          "low",
    "informational": "low",
    "low":           "low",
    "warning":       "medium",
    "moderate":      "medium",
    "medium":        "medium",
    "high":          "high",
    "critical":      "critical",
}

# ---------------------------------------------------------------------------
# Event-type normalisation table (substring → canonical)
# Checked in order; first match wins.
# ---------------------------------------------------------------------------
_EVENT_TYPE_MAP = [
    (["login failure", "failed login", "authentication failure", "brute force"], "login_failure"),
    (["powershell"],                                                              "powershell_execution"),
    (["privilege escalation"],                                                   "privilege_escalation"),
    (["data exfil", "data transfer"],                                            "data_transfer"),
    (["lateral movement"],                                                       "lateral_movement"),
    (["malware drop", "malware"],                                                "malware_execution"),
    (["health check"],                                                           "routine_health_check"),
    (["anomaly"],                                                                "anomaly_detected"),
    (["movement detected"],                                                      "physical_movement"),
]

# Simple IPv4 pattern used to distinguish IP indicators from other types
_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Deterministic per-source counter used when no ID is present in the raw alert
_id_counters: dict = {}


def _next_id(prefix: str) -> str:
    _id_counters[prefix] = _id_counters.get(prefix, 0) + 1
    return f"{prefix}-{_id_counters[prefix]:03d}"


def _normalise_severity(raw: Optional[str]) -> str:
    if not raw:
        return "low"
    return _SEVERITY_MAP.get(str(raw).lower().strip(), "low")


def _normalise_event_type(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    lower = str(raw).lower().strip()
    for patterns, canonical in _EVENT_TYPE_MAP:
        for pat in patterns:
            if pat in lower:
                return canonical
    # Return a lightly cleaned version of the original when no match
    return lower.replace(" ", "_")


def _is_ip(value: str) -> bool:
    return bool(_IP_RE.match(str(value).strip()))


# ---------------------------------------------------------------------------
# Per-source field mappings
# ---------------------------------------------------------------------------

def _from_siem(raw: dict) -> NormalizedAlert:
    alert_id  = raw.get("id") or _next_id("SIEM")
    timestamp = raw.get("event_time") or raw.get("timestamp") or ""
    ip        = raw.get("src_ip")
    asset     = raw.get("hostname") or raw.get("asset")
    severity  = _normalise_severity(raw.get("level") or raw.get("severity"))
    event_type = _normalise_event_type(raw.get("event") or raw.get("event_type"))
    return NormalizedAlert(
        alert_id=alert_id,
        timestamp=timestamp,
        source="siem",
        ip=ip,
        asset=asset,
        severity=severity,
        event_type=event_type,
        raw_data=dict(raw),
    )


def _from_sensor(raw: dict) -> NormalizedAlert:
    alert_id  = raw.get("id") or _next_id("SENSOR")
    timestamp = raw.get("timestamp") or raw.get("event_time") or ""
    ip        = raw.get("ip")
    asset     = raw.get("asset") or raw.get("hostname")
    severity  = _normalise_severity(raw.get("severity") or raw.get("level"))
    event_type = _normalise_event_type(raw.get("event_type") or raw.get("event"))
    return NormalizedAlert(
        alert_id=alert_id,
        timestamp=timestamp,
        source="sensor",
        ip=ip,
        asset=asset,
        severity=severity,
        event_type=event_type,
        raw_data=dict(raw),
    )


def _from_intel(raw: dict) -> NormalizedAlert:
    alert_id  = raw.get("id") or _next_id("INTEL")
    timestamp = raw.get("time") or raw.get("timestamp") or ""
    indicator = raw.get("indicator") or ""
    # Only put the indicator in the ip field when it really is an IP address
    ip        = indicator if _is_ip(indicator) else None
    asset     = raw.get("target") or raw.get("asset")
    severity  = _normalise_severity(raw.get("risk") or raw.get("severity"))
    event_type = _normalise_event_type(raw.get("activity") or raw.get("event_type"))
    return NormalizedAlert(
        alert_id=alert_id,
        timestamp=timestamp,
        source="intel",
        ip=ip,
        asset=asset,
        severity=severity,
        event_type=event_type,
        raw_data=dict(raw),   # original indicator kept here regardless of type
    )


def _from_satellite(raw: dict) -> NormalizedAlert:
    alert_id  = raw.get("id") or _next_id("SAT")
    timestamp = raw.get("timestamp") or raw.get("time") or ""
    asset     = raw.get("asset")
    # Satellites typically carry no IP; flag physical movement as event type
    movement  = raw.get("movement_detected", False)
    event_type = "physical_movement" if movement else "satellite_observation"
    severity  = _normalise_severity(raw.get("severity"))
    return NormalizedAlert(
        alert_id=alert_id,
        timestamp=timestamp,
        source="satellite",
        ip=None,
        asset=asset,
        severity=severity,
        event_type=event_type,
        raw_data=dict(raw),   # location, satellite_flag, movement_detected all preserved
    )


# Dispatch table: canonical source name → handler
_HANDLERS = {
    "siem":      _from_siem,
    "sensor":    _from_sensor,
    "intel":     _from_intel,
    "satellite": _from_satellite,
}

# Source-name aliases used when normalizing raw alerts that come from
# multi_source_ingestion (which stamps each dict with "_source")
_SOURCE_ALIASES = {
    "siem":           "siem",
    "siem_feed":      "siem",
    "sensor":         "sensor",
    "cyber_sensor":   "sensor",
    "intel":          "intel",
    "intel_report":   "intel",
    "satellite":      "satellite",
    "satellite_feed": "satellite",
}


def normalize_alerts(raw_alerts: list) -> List[NormalizedAlert]:
    """
    Feature #2: Alert Normalization.
    Convert raw alerts from different sources into a common NormalizedAlert format.
    """
    # Reset per-run ID counters so results are deterministic across calls
    _id_counters.clear()

    normalized = []

    for raw in raw_alerts:
        # Guard: must be a non-empty dict
        if not isinstance(raw, dict) or not raw:
            continue

        # Determine source from the injected "_source" key or a "source" field
        raw_source = raw.get("_source") or raw.get("source") or ""
        canonical = _SOURCE_ALIASES.get(str(raw_source).lower().strip())

        handler = _HANDLERS.get(canonical) if canonical else None
        if handler is None:
            # Unknown source — attempt a best-effort generic normalization
            alert_id  = (raw.get("id") or raw.get("alert_id") or _next_id("UNKNOWN"))
            timestamp = (raw.get("timestamp") or raw.get("event_time")
                         or raw.get("time") or "")
            severity  = _normalise_severity(
                raw.get("severity") or raw.get("level") or raw.get("risk")
            )
            event_type = _normalise_event_type(
                raw.get("event_type") or raw.get("event") or raw.get("activity")
            )
            normalized.append(NormalizedAlert(
                alert_id=str(alert_id),
                timestamp=str(timestamp),
                source=str(raw_source) or "unknown",
                ip=raw.get("ip") or raw.get("src_ip"),
                asset=raw.get("asset") or raw.get("hostname") or raw.get("target"),
                severity=severity,
                event_type=event_type,
                raw_data=dict(raw),
            ))
            continue

        try:
            alert = handler(raw)
            normalized.append(alert)
        except Exception:
            # Malformed entry — skip rather than crash the whole pipeline
            continue

    return normalized
