from shared.schemas import Incident

# Severity base scores — each alert contributes this much before any multipliers
_SEVERITY_BASE = {"low": 5, "medium": 15, "high": 30, "critical": 45}

# Suspicious event-type terms (case-insensitive substring match)
_SUSPICIOUS_TERMS = [
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
]

# Asset name fragments that indicate a high-value target
_IMPORTANT_ASSET_TERMS = {"critical", "server", "database", "gateway", "control"}


def _severity_score(severity: str) -> float:
    return _SEVERITY_BASE.get((severity or "low").lower(), _SEVERITY_BASE["low"])


def _event_type_bonus(event_type: str) -> float:
    """Return +10 if the event type matches any suspicious term."""
    if not event_type:
        return 0.0
    et = event_type.lower()
    return 10.0 if any(term in et for term in _SUSPICIOUS_TERMS) else 0.0


def _asset_bonus(asset: str) -> float:
    """Return +5 if the asset looks like a high-value target."""
    if not asset:
        return 0.0
    a = asset.lower()
    return 5.0 if any(term in a for term in _IMPORTANT_ASSET_TERMS) else 0.0


def calculate_risk_score(incident: Incident) -> Incident:
    """
    Feature #5: Threat/Risk Scoring.
    Fill: incident.risk_score (float 0-100)

    Scoring approach (all deterministic, no RNG):
      1. Per-alert contribution = severity_base + event_type_bonus + asset_bonus.
      2. Sum ALL alert contributions (full additive).
      3. A pure-volume cap prevents a large pile of low-severity alerts from
         inflating the score artificially: raw alert count alone contributes
         at most +10 additional points over and above the per-alert content.
      4. Normalise the combined sum onto [0, 100] using a soft ceiling of 200
         (the practical maximum for heavily-loaded genuine incidents).
      5. Source-diversity bonus: up to +15 for alerts from 4+ distinct sources.
      6. False-positive incidents receive a 70 % penalty on the pre-clamp score.
      7. Final score is clamped to [0, 100].

    Design properties
    -----------------
    * A single low-severity routine login: score ~5  -> Low
    * Several high/critical + suspicious events + multi-source: score >= 75 -> Critical
    * Alert count alone cannot push a low-severity bundle above Medium.
    """
    alerts = incident.alerts or []

    if not alerts:
        incident.risk_score = 0.0
        return incident

    # --- Step 1: Sum per-alert contributions ---
    raw_sum = 0.0
    for alert in alerts:
        raw_sum += _severity_score(alert.severity)
        raw_sum += _event_type_bonus(alert.event_type or "")
    # --- Step 2 & 3: Volume cap ---
    # Allow full additive sum up to 3 alerts; beyond that each extra alert
    # contributes only its content score multiplied by a damping factor.
    # This ensures alert count alone cannot saturate the scale.
    n = len(alerts)
    if n <= 3:
        adjusted_sum = raw_sum
    else:
        # First 3 alerts contribute fully; extras contribute at 40 %
        per_alert_avg = raw_sum / n
        full_contribution  = per_alert_avg * 3
        extra_contribution = per_alert_avg * (n - 3) * 0.40
        adjusted_sum = full_contribution + extra_contribution

    # --- Step 3: Source-diversity bonus (up to +15) ---
    unique_sources = {a.source for a in alerts if a.source}
    source_bonus = min(len(unique_sources) - 1, 3) * 5.0  # max +15

    combined = adjusted_sum + source_bonus

    # --- Step 4: Normalise to [0, 100] with soft ceiling of 200 ---
    # 200 is the practical upper bound for a fully-loaded critical incident
    # (e.g. 3 critical alerts × (45+10+5) = 180, plus 15 source bonus = 195)
    score = (combined / 200.0) * 100.0

    # --- Step 5: False-positive penalty ---
    if getattr(incident, "is_false_positive", None):
        score *= 0.30   # 70 % reduction

    # --- Step 6: Clamp ---
    incident.risk_score = round(max(0.0, min(100.0, score)), 2)
    return incident
