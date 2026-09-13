import hashlib
from shared.schemas import Incident

# ---------------------------------------------------------------------------
# Behavioural tag extraction
# Each entry is (canonical_tag, list_of_matching_substrings).
# Tags are matched case-insensitively against alert.event_type.
# Order defines the canonical sort order used in the signature.
# ---------------------------------------------------------------------------
_BEHAVIOUR_TAGS = [
    ("AUTH_FAILURE",        ["login failure", "authentication failure"]),
    ("PRIV_ESCALATION",     ["privilege escalation"]),
    ("SCRIPT_EXECUTION",    ["powershell", "command execution"]),
    ("MALWARE",             ["malware"]),
    ("SUSPICIOUS_PROCESS",  ["suspicious process"]),
    ("FILE_ACCESS",         ["file access"]),
    ("DATA_TRANSFER",       ["data transfer"]),
    ("UNAUTHORIZED_ACCESS", ["unauthorized access"]),
    ("LATERAL_MOVEMENT",    ["lateral movement"]),
    ("NETWORK_ACTIVITY",    ["network", "firewall", "port scan", "connection"]),
]

# Severity codes used in the dominant-severity component of the DNA
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_RANK_TO_CODE  = {4: "SEV_CRITICAL", 3: "SEV_HIGH", 2: "SEV_MEDIUM", 1: "SEV_LOW"}


def _extract_behaviour_tags(alerts: list) -> list:
    """
    Return a sorted, deduplicated list of behavioural tags extracted from
    the event_types of all alerts.  Identity fields (IPs, IDs, hostnames)
    are deliberately ignored.
    """
    found = set()
    for alert in alerts:
        et = (alert.event_type or "").lower()
        for tag, substrings in _BEHAVIOUR_TAGS:
            if any(sub in et for sub in substrings):
                found.add(tag)
    return sorted(found)   # deterministic order


def _dominant_severity_code(alerts: list) -> str:
    """Return the severity tag for the highest severity seen across all alerts."""
    if not alerts:
        return "SEV_LOW"
    max_rank = max(
        _SEVERITY_RANK.get((a.severity or "low").lower(), 1) for a in alerts
    )
    return _RANK_TO_CODE.get(max_rank, "SEV_LOW")


def _source_diversity_tag(alerts: list) -> str:
    unique_sources = {a.source for a in alerts if a.source}
    n = len(unique_sources)
    if n >= 3:
        return "MULTI_SOURCE_3PLUS"
    if n == 2:
        return "MULTI_SOURCE_2"
    return "SINGLE_SOURCE"


def generate_threat_dna(incident: Incident) -> Incident:
    """
    Feature #19: Threat DNA - Behavioural Fingerprinting.
    Build a behavioural signature and compare against past incidents.
    Fill: incident.threat_dna_signature (str), incident.similar_past_incidents (list)

    The signature encodes BEHAVIOUR only:
      <dominant_severity>|<source_diversity>|<behaviour_tags…>

    A stable SHA-256 of that canonical string is appended as a compact hash
    so callers have a fixed-width key if they need one:
      <canonical_string>#<first-16-hex-chars-of-sha256>

    No identity fields (IP, ID, hostname, username, malware name) are used.

    Historical incident matching:
      The repository has no historical incident store, so
      similar_past_incidents is set to [] as required by the spec.
    """
    alerts = incident.alerts or []

    if not alerts:
        incident.threat_dna_signature = "SEV_LOW|SINGLE_SOURCE#" + hashlib.sha256(
            b"SEV_LOW|SINGLE_SOURCE"
        ).hexdigest()[:16]
        incident.similar_past_incidents = []
        return incident

    # Build the canonical behaviour string
    severity_part   = _dominant_severity_code(alerts)
    diversity_part  = _source_diversity_tag(alerts)
    behaviour_tags  = _extract_behaviour_tags(alerts)

    behaviour_part  = "|".join(behaviour_tags) if behaviour_tags else "NO_SPECIFIC_BEHAVIOUR"
    canonical       = f"{severity_part}|{diversity_part}|{behaviour_part}"

    # Stable hash — uses hashlib, not Python's built-in hash()
    stable_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    incident.threat_dna_signature = f"{canonical}#{stable_hash}"

    # No historical incident store exists in the repository
    incident.similar_past_incidents = []
    return incident
