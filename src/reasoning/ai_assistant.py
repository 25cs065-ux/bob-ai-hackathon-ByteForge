from shared.schemas import Incident


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _collect_evidence(incident: Incident) -> dict:
    """
    Gather all available evidence fields into a single dict so every
    answer-builder can access them without repeating boilerplate.
    """
    alerts = incident.alerts or []

    severities = [a.severity for a in alerts if a.severity]
    event_types = [a.event_type for a in alerts if a.event_type]
    sources = list({a.source for a in alerts if a.source})
    assets = list({a.asset for a in alerts if a.asset})
    ips = list({a.ip for a in alerts if a.ip})

    high_sev_count = sum(1 for s in severities if s in ("high", "critical"))

    return {
        "alert_count": len(alerts),
        "severities": severities,
        "event_types": event_types,
        "sources": sources,
        "assets": assets,
        "ips": ips,
        "high_sev_count": high_sev_count,
        "risk_score": incident.risk_score,
        "priority": incident.priority or "Unknown",
        "is_false_positive": incident.is_false_positive,
        "false_positive_reason": incident.false_positive_reason,
        "mitre_techniques": incident.mitre_techniques or [],
        "attack_timeline": incident.attack_timeline or [],
        "threat_intel": incident.threat_intel or {},
        "physical_correlation": incident.physical_correlation,
        "threat_dna_signature": incident.threat_dna_signature,
        "similar_past_incidents": incident.similar_past_incidents or [],
    }


def _format_list(items: list, limit: int = 5) -> str:
    """Format a list as a comma-separated string, truncating if needed."""
    shown = items[:limit]
    result = ", ".join(str(i) for i in shown)
    if len(items) > limit:
        result += f" (and {len(items) - limit} more)"
    return result or "none"


# ---------------------------------------------------------------------------
# Per-topic answer builders
# ---------------------------------------------------------------------------

def _answer_criticality(ev: dict) -> str:
    parts = []
    priority = ev["priority"]
    risk = ev["risk_score"]
    if risk is not None:
        parts.append(
            f"This incident is classified as {priority} with a risk score of {risk:.1f}."
        )
    else:
        parts.append(f"This incident is classified as {priority}.")

    if ev["high_sev_count"]:
        parts.append(
            f"It contains {ev['high_sev_count']} high or critical severity alert(s) out of {ev['alert_count']} total."
        )
    elif ev["alert_count"]:
        parts.append(f"It contains {ev['alert_count']} alert(s).")

    if ev["event_types"]:
        parts.append(
            f"Observed behaviours include: {_format_list(list(set(ev['event_types'])))}."
        )

    if ev["mitre_techniques"]:
        parts.append(
            f"These map to MITRE ATT&CK techniques: {_format_list(ev['mitre_techniques'])}."
        )

    if ev["assets"]:
        parts.append(f"Affected asset(s): {_format_list(ev['assets'])}.")

    if ev["threat_intel"]:
        parts.append(
            "Threat intelligence indicators are present and support the assessment."
        )

    if ev["physical_correlation"]:
        pc = ev["physical_correlation"]
        signal = pc.get("physical_signal", "physical signal")
        parts.append(
            f"A physical correlation signal has been detected ({signal}), "
            "which coincides with the cyber activity."
        )

    if not parts:
        return "Insufficient evidence is available to explain the criticality of this incident."
    return " ".join(parts)


def _answer_false_positive(ev: dict) -> str:
    if ev["is_false_positive"] is True:
        reason = ev["false_positive_reason"] or "No specific reason was recorded."
        return (
            f"This incident has been assessed as a likely false positive. "
            f"Reason: {reason}"
        )
    if ev["is_false_positive"] is False:
        return (
            "This incident has been assessed as a genuine threat — "
            "it does not appear to be a false positive based on available evidence."
        )
    return "No false-positive determination has been recorded for this incident."


def _answer_mitre(ev: dict) -> str:
    techs = ev["mitre_techniques"]
    if not techs:
        return "No MITRE ATT&CK techniques have been mapped to this incident yet."
    return (
        f"The following MITRE ATT&CK techniques have been observed in this incident: "
        f"{', '.join(techs)}."
    )


def _answer_timeline(ev: dict) -> str:
    tl = ev["attack_timeline"]
    if not tl:
        return "No attack timeline has been constructed for this incident."
    first = tl[0]
    last = tl[-1]
    first_desc = first.get("event_desc") or first.get("description") or str(first)
    last_desc = last.get("event_desc") or last.get("description") or str(last)
    return (
        f"The attack timeline contains {len(tl)} event(s). "
        f"The first recorded event: '{first_desc}'. "
        f"The most recent event: '{last_desc}'."
    )


def _answer_impact(ev: dict) -> str:
    parts = []
    if ev["assets"]:
        parts.append(f"Potentially affected asset(s): {_format_list(ev['assets'])}.")
    if ev["ips"]:
        parts.append(f"Involved IP address(es): {_format_list(ev['ips'])}.")
    types = list(set(ev["event_types"]))
    if types:
        parts.append(f"Observed event types suggest: {_format_list(types)}.")
    if ev["physical_correlation"]:
        pc = ev["physical_correlation"]
        loc = pc.get("asset_location", "unknown location")
        parts.append(
            f"Physical correlation at {loc} may indicate a broader impact."
        )
    if not parts:
        return "Potential impact could not be fully determined from the available evidence."
    return " ".join(parts)


def _answer_asset(ev: dict) -> str:
    if ev["assets"]:
        return f"Affected asset(s) identified in this incident: {_format_list(ev['assets'])}."
    return "No specific assets have been identified in this incident."


def _answer_ip(ev: dict) -> str:
    if ev["ips"]:
        return f"IP address(es) observed in this incident: {_format_list(ev['ips'])}."
    if ev["threat_intel"]:
        return (
            "No IP addresses are directly recorded, but threat intelligence "
            "indicators are present in the incident."
        )
    return "No IP addresses have been recorded for this incident."


def _answer_physical(ev: dict) -> str:
    pc = ev["physical_correlation"]
    if not pc:
        return "No physical or geospatial correlation has been recorded for this incident."
    asset = pc.get("asset", "unknown asset")
    location = pc.get("asset_location", "unknown location")
    signal = pc.get("physical_signal", "physical signal")
    satellite = pc.get("satellite_flag", False)
    description = pc.get("correlation", "")
    sat_note = " A satellite feed flag is set." if satellite else ""
    return (
        f"Physical correlation is present for asset '{asset}' at {location}. "
        f"Signal type: {signal}.{sat_note} "
        f"{description}".strip()
    )


def _answer_recommendation(ev: dict) -> str:
    tips = []
    if ev["alert_count"]:
        tips.append("Review the complete alert set and correlate related events.")
    if ev["mitre_techniques"]:
        tips.append(
            f"Investigate activity mapped to MITRE techniques: "
            f"{_format_list(ev['mitre_techniques'])}."
        )
    if ev["assets"]:
        tips.append(f"Examine the affected asset(s): {_format_list(ev['assets'])}.")
    if ev["ips"]:
        tips.append(
            f"Research the reputation and history of IP(s): {_format_list(ev['ips'])}."
        )
    if ev["physical_correlation"]:
        tips.append("Validate the physical correlation signal against the asset's expected activity.")
    if ev["priority"] in ("Critical", "High"):
        tips.append("Escalate for analyst investigation according to operational procedures.")
    if not tips:
        return "Review the incident details and any available logs for further context."
    return " ".join(tips)


def _general_summary(ev: dict) -> str:
    """Fall-through: produce a broad evidence summary."""
    return _answer_criticality(ev)


# ---------------------------------------------------------------------------
# Keyword → handler routing
# ---------------------------------------------------------------------------

_ROUTES = [
    (["false positive", "benign", "noise"],                _answer_false_positive),
    (["why", "critical", "high", "risk", "threat"],       _answer_criticality),
    (["mitre", "ttp", "technique", "tactic"],              _answer_mitre),
    (["timeline", "first", "what happened", "sequence",
      "order", "chronolog"],                               _answer_timeline),
    (["impact", "damage", "affected"],                     _answer_impact),
    (["asset", "host", "server", "machine", "endpoint"],   _answer_asset),
    (["ip", "address", "network"],                         _answer_ip),
    (["physical", "satellite", "geo", "location"],         _answer_physical),
    (["recommend", "next step", "investigate",
      "what should", "action"],                            _answer_recommendation),
    (["evidence", "indicator", "support"],                 _answer_criticality),
]


def answer_analyst_question(incident: Incident, question: str = "Why is this critical?") -> str:
    """
    Feature #11: AI Investigation Assistant.
    Answer analyst questions grounded in the incident's evidence.
    """
    ev = _collect_evidence(incident)
    q_lower = question.lower()

    for keywords, handler in _ROUTES:
        if any(kw in q_lower for kw in keywords):
            return handler(ev)

    # Unrecognised question — return a general summary instead of an error
    return _general_summary(ev)


def generate_ai_explanation(incident: Incident) -> Incident:
    """Fill: incident.ai_explanation (str) — default explanation for the incident."""
    ev = _collect_evidence(incident)

    parts = []
    priority = ev["priority"]
    risk = ev["risk_score"]

    # Lead with priority / risk
    if risk is not None:
        parts.append(
            f"The incident is classified as {priority} with a risk score of {risk:.1f}."
        )
    elif priority != "Unknown":
        parts.append(f"The incident is classified as {priority}.")
    else:
        parts.append("The incident has been recorded with limited scoring information.")

    # False-positive status
    if ev["is_false_positive"] is True:
        reason = ev["false_positive_reason"] or "No reason recorded."
        parts.append(
            f"It has been assessed as a likely false positive ({reason})"
        )
    elif ev["is_false_positive"] is False:
        parts.append("It has been assessed as a genuine threat.")

    # Alert volume and severity
    if ev["alert_count"]:
        if ev["high_sev_count"]:
            parts.append(
                f"It contains {ev['alert_count']} alert(s), of which "
                f"{ev['high_sev_count']} are high or critical severity."
            )
        else:
            parts.append(f"It contains {ev['alert_count']} alert(s).")

    # Event types
    unique_types = list(set(ev["event_types"]))
    if unique_types:
        parts.append(
            f"Observed activity includes: {_format_list(unique_types)}."
        )

    # MITRE techniques
    if ev["mitre_techniques"]:
        parts.append(
            f"The observed behaviour maps to MITRE ATT&CK techniques: "
            f"{', '.join(ev['mitre_techniques'])}."
        )

    # Affected assets
    if ev["assets"]:
        parts.append(f"Affected asset(s): {_format_list(ev['assets'])}.")

    # Threat intelligence
    if ev["threat_intel"]:
        parts.append(
            "Threat intelligence indicators corroborate suspicious activity."
        )

    # Physical correlation
    if ev["physical_correlation"]:
        pc = ev["physical_correlation"]
        signal = pc.get("physical_signal", "physical signal")
        parts.append(
            f"A physical correlation signal ({signal}) coincides with the cyber events."
        )

    if not parts:
        parts.append(
            "Insufficient evidence is currently available to provide a detailed explanation."
        )
    else:
        parts.append(
            "These combined indicators warrant analyst review."
        )

    incident.ai_explanation = " ".join(parts)
    return incident
