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


def explain_risk_score(incident) -> list:
    """
    Return a list of (label, detail) tuples that explain how the current
    incident.risk_score was produced.

    Uses exactly the same constants and logic as calculate_risk_score() so
    the explanation is always consistent with the actual score.  Safe to call
    even when risk_score is None or when there are no alerts.
    """
    alerts = incident.alerts or []

    if not alerts:
        return [("No alerts", "Score is 0 — no alert data is available for this incident.")]

    factors = []

    # ── Per-alert severity contribution ──────────────────────────────────
    sev_counts: dict = {}
    sev_total = 0.0
    for a in alerts:
        sev = (a.severity or "low").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        sev_total += _SEVERITY_BASE.get(sev, _SEVERITY_BASE["low"])

    sev_order = ["critical", "high", "medium", "low"]
    sev_parts = [
        f"{sev_counts[s]} {s} (×{_SEVERITY_BASE[s]} pts each)"
        for s in sev_order
        if s in sev_counts
    ]
    factors.append((
        "Severity contribution",
        f"{', '.join(sev_parts)} → raw severity total: {sev_total:.1f} pts",
    ))

    # ── Suspicious event-type bonuses ─────────────────────────────────────
    matched_events = [
        f"{a.event_type!r}"
        for a in alerts
        if a.event_type and _event_type_bonus(a.event_type) > 0
    ]
    event_bonus_total = sum(_event_type_bonus(a.event_type or "") for a in alerts)
    if matched_events:
        factors.append((
            "Suspicious event-type bonus",
            f"+10 pts per match — matched: {', '.join(matched_events)} "
            f"→ +{event_bonus_total:.0f} pts total",
        ))
    else:
        factors.append((
            "Suspicious event-type bonus",
            "No alerts matched suspicious event-type terms — +0 pts",
        ))

    # ── High-value asset bonuses ───────────────────────────────────────────
    asset_bonus_total = sum(_asset_bonus(a.asset or "") for a in alerts)
    if asset_bonus_total > 0:
        matched_assets = sorted({
            a.asset for a in alerts
            if a.asset and _asset_bonus(a.asset) > 0
        })
        factors.append((
            "High-value asset bonus",
            f"+5 pts per high-value asset — matched: {', '.join(matched_assets)} "
            f"→ +{asset_bonus_total:.0f} pts total",
        ))
    else:
        factors.append((
            "High-value asset bonus",
            "No alerts targeted a high-value asset — +0 pts",
        ))

    # ── Volume cap / damping ──────────────────────────────────────────────
    n = len(alerts)
    raw_sum = sev_total + event_bonus_total + asset_bonus_total
    if n <= 3:
        adjusted_sum = raw_sum
        factors.append((
            "Alert volume",
            f"{n} alert(s) — full contribution applied (≤3 alerts, no damping)",
        ))
    else:
        per_alert_avg  = raw_sum / n
        full_contribution  = per_alert_avg * 3
        extra_contribution = per_alert_avg * (n - 3) * 0.40
        adjusted_sum = full_contribution + extra_contribution
        factors.append((
            "Alert volume (damping applied)",
            f"{n} alerts — first 3 contribute fully; {n - 3} additional alert(s) "
            f"contribute at 40% to prevent volume inflation "
            f"(adjusted total: {adjusted_sum:.1f} pts)",
        ))

    # ── Source-diversity bonus ─────────────────────────────────────────────
    unique_sources = sorted({a.source for a in alerts if a.source})
    source_bonus = min(len(unique_sources) - 1, 3) * 5.0
    factors.append((
        "Source diversity bonus",
        f"{len(unique_sources)} distinct source(s): {', '.join(unique_sources)} "
        f"→ +{source_bonus:.0f} pts (up to +15 for 4+ sources)",
    ))

    # ── Normalisation ─────────────────────────────────────────────────────
    combined = adjusted_sum + source_bonus
    raw_score = (combined / 200.0) * 100.0
    factors.append((
        "Normalisation",
        f"Combined score {combined:.1f} ÷ 200 × 100 = {raw_score:.1f} "
        f"(soft ceiling of 200 represents a maximum-severity fully-loaded incident)",
    ))

    # ── False-positive penalty ─────────────────────────────────────────────
    if getattr(incident, "is_false_positive", None):
        factors.append((
            "False-positive penalty",
            f"Incident flagged as false positive — score reduced by 70%: "
            f"{raw_score:.1f} × 0.30 = {raw_score * 0.30:.1f}",
        ))
    else:
        factors.append((
            "False-positive penalty",
            "Not applicable — incident is not flagged as a false positive",
        ))

    # ── Final score ───────────────────────────────────────────────────────
    final = incident.risk_score
    if final is not None:
        factors.append((
            "Final score (clamped to [0, 100])",
            f"{final}",
        ))

    return factors
