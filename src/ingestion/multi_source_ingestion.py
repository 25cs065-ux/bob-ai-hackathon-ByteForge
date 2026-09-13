from typing import List

# ---------------------------------------------------------------------------
# Source-name aliases — map friendly names to canonical keys
# ---------------------------------------------------------------------------
_SOURCE_ALIASES = {
    "siem":            "siem",
    "siem_feed":       "siem",
    "sensor":          "sensor",
    "cyber_sensor":    "sensor",
    "intel":           "intel",
    "intel_report":    "intel",
    "satellite":       "satellite",
    "satellite_feed":  "satellite",
}

# ---------------------------------------------------------------------------
# Simulated alert payloads
# Each source uses its own field naming convention so Feature #2 can
# demonstrate real normalization.  All alerts share a coherent storyline:
#
#   Attack path (should correlate into ONE incident):
#     203.0.113.10 → server-01  (login_failure → powershell → priv-esc → exfil)
#
#   Benign path (should stay SEPARATE):
#     10.0.0.20 → workstation-10  (routine health-check)
# ---------------------------------------------------------------------------

_SIEM_ALERTS: List[dict] = [
    {
        "_source": "siem",
        "id": "SIEM-001",
        "event_time": "2024-01-15T10:00:00Z",
        "src_ip": "203.0.113.10",
        "hostname": "server-01",
        "level": "high",
        "event": "login failure",
    },
    {
        "_source": "siem",
        "id": "SIEM-002",
        "event_time": "2024-01-15T10:03:00Z",
        "src_ip": "203.0.113.10",
        "hostname": "server-01",
        "level": "critical",
        "event": "powershell execution",
    },
    {
        "_source": "siem",
        "id": "SIEM-003",
        "event_time": "2024-01-15T10:06:00Z",
        "src_ip": "203.0.113.10",
        "hostname": "server-01",
        "level": "critical",
        "event": "privilege escalation",
    },
    {
        "_source": "siem",
        "id": "SIEM-004",
        "event_time": "2024-01-15T12:30:00Z",
        "src_ip": "10.0.0.20",
        "hostname": "workstation-10",
        "level": "info",
        "event": "routine health check",
    },
]

_SENSOR_ALERTS: List[dict] = [
    {
        "_source": "sensor",
        "id": "SENSOR-001",
        "timestamp": "2024-01-15T10:08:00Z",
        "ip": "203.0.113.10",
        "asset": "server-01",
        "severity": "critical",
        "event_type": "data transfer",
    },
    {
        "_source": "sensor",
        "id": "SENSOR-002",
        "timestamp": "2024-01-15T10:09:00Z",
        "ip": "203.0.113.10",
        "asset": "server-01",
        "severity": "high",
        "event_type": "lateral movement",
    },
]

_INTEL_ALERTS: List[dict] = [
    {
        "_source": "intel",
        "id": "INTEL-001",
        "time": "2024-01-15T09:55:00Z",
        "indicator": "203.0.113.10",
        "target": "server-01",
        "risk": "high",
        "activity": "brute force",
    },
    {
        "_source": "intel",
        "id": "INTEL-002",
        "time": "2024-01-15T10:02:00Z",
        "indicator": "malware-hash-abc123",   # non-IP indicator — must NOT go into ip field
        "target": "server-01",
        "risk": "critical",
        "activity": "malware drop",
    },
]

_SATELLITE_ALERTS: List[dict] = [
    {
        "_source": "satellite",
        "id": "SAT-001",
        "timestamp": "2024-01-15T10:05:00Z",
        "asset": "server-01",
        "location": "datacenter-zone-A",
        "satellite_flag": True,
        "movement_detected": False,
    },
    {
        "_source": "satellite",
        "id": "SAT-002",
        "timestamp": "2024-01-15T10:07:00Z",
        "asset": "server-01",
        "location": "datacenter-zone-A",
        "satellite_flag": True,
        "movement_detected": True,
    },
]

_SOURCE_DATA = {
    "siem":      _SIEM_ALERTS,
    "sensor":    _SENSOR_ALERTS,
    "intel":     _INTEL_ALERTS,
    "satellite": _SATELLITE_ALERTS,
}


def collect_raw_alerts(sources: list) -> list:
    """
    Feature #1: Multi-Source Alert Ingestion.
    Pull raw alerts from SIEM, cyber sensors, intel reports, simulated satellite feeds.
    Return a list of raw dicts (before normalization).
    """
    raw_alerts = []

    for source in sources:
        canonical = _SOURCE_ALIASES.get(str(source).lower().strip())
        if canonical is None:
            # Unsupported source — skip silently, never crash
            continue
        raw_alerts.extend(_SOURCE_DATA[canonical])

    return raw_alerts
