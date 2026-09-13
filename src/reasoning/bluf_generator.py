from shared.schemas import Incident


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _format_list(items: list, limit: int = 5) -> str:
    shown = items[:limit]
    result = ", ".join(str(i) for i in shown)
    if len(items) > limit:
        result += f" (and {len(items) - limit} more)"
    return result or "none"


def _extract_alerts(incident: Incident) -> dict:
    alerts = incident.alerts or []
    severities = [a.severity for a in alerts if a.severity]
    event_types = [a.event_type for a in alerts if a.event_type]
    assets = list({a.asset for a in alerts if a.asset})
    ips = list({a.ip for a in alerts if a.ip})
    high_sev_count = sum(1 for s in severities if s in ("high", "critical"))
    return {
        "count": len(alerts),
        "severities": severities,
        "unique_event_types": list(set(event_types)),
        "assets": assets,
        "ips": ips,
        "high_sev_count": high_sev_count,
    }


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_threat(incident: Incident, al: dict) -> str:
    """Bottom-line threat statement."""
    priority = incident.priority or "Unknown"
    risk = incident.risk_score

    if incident.is_false_positive is True:
        reason = incident.false_positive_reason or "no specific reason recorded"
        return (
            f"Incident assessed as a likely false positive ({reason}). "
            "No confirmed threat at this time."
        )

    parts = []
    if risk is not None:
        parts.append(f"{priority}-priority activity with a risk score of {risk:.1f}.")
    else:
        parts.append(f"{priority}-priority activity.")

    if al["unique_event_types"]:
        parts.append(
            f"Observed behaviours: {_format_list(al['unique_event_types'])}."
        )

    if incident.mitre_techniques:
        parts.append(
            f"MITRE techniques: {', '.join(incident.mitre_techniques)}."
        )

    if incident.threat_intel:
        parts.append("Threat intelligence indicators are present.")

    if incident.physical_correlation:
        signal = incident.physical_correlation.get("physical_signal", "physical signal")
        parts.append(f"Physical signal detected: {signal}.")

    return " ".join(parts) if parts else "Insufficient evidence to characterise the threat."


def _build_impact(incident: Incident, al: dict) -> str:
    """Potential impact based on available evidence."""
    parts = []

    if al["assets"]:
        parts.append(f"Potentially affected asset(s): {_format_list(al['assets'])}.")

    if al["ips"]:
        parts.append(f"Involved IP(s): {_format_list(al['ips'])}.")

    # Event-type driven impact statements
    et_lower = [e.lower() for e in al["unique_event_types"]]
    if any("privilege" in e or "escalat" in e for e in et_lower):
        parts.append("Potential for unauthorised privilege escalation on affected system(s).")
    if any("lateral" in e for e in et_lower):
        parts.append("Possible lateral movement to additional systems.")
    if any("data" in e and ("transfer" in e or "exfil" in e) for e in et_lower):
        parts.append("Possible unauthorised data transfer or exfiltration.")
    if any("login" in e or "auth" in e or "brute" in e for e in et_lower):
        parts.append("Targeted accounts may be at risk of compromise.")

    # MITRE-technique driven impact
    techs = incident.mitre_techniques or []
    if "T1068" in techs:
        parts.append("Privilege escalation has been observed.")
    if "T1021" in techs or any(t.startswith("T1021") for t in techs):
        parts.append("Remote service access may allow spread to additional systems.")
    if "T1041" in techs:
        parts.append("Data may have been exfiltrated over a command-and-control channel.")

    if incident.physical_correlation:
        loc = incident.physical_correlation.get("asset_location", "the affected site")
        parts.append(
            f"Physical correlation at {loc} suggests a potential broader impact."
        )

    if not parts:
        return "Potential impact could not be fully determined from the available evidence."
    return " ".join(parts)


def _build_confidence(incident: Incident, al: dict) -> str:
    """Evidence-based confidence level: High / Medium / Low."""
    score = 0

    # Multiple independent alerts
    if al["count"] >= 5:
        score += 3
    elif al["count"] >= 2:
        score += 2
    elif al["count"] == 1:
        score += 1

    # Alert severity
    if al["high_sev_count"] >= 2:
        score += 2
    elif al["high_sev_count"] == 1:
        score += 1

    # MITRE techniques
    if len(incident.mitre_techniques or []) >= 3:
        score += 2
    elif len(incident.mitre_techniques or []) >= 1:
        score += 1

    # Threat intel present
    if incident.threat_intel:
        score += 2

    # Physical correlation
    if incident.physical_correlation:
        score += 2

    # Multiple sources
    sources = list({a.source for a in (incident.alerts or []) if a.source})
    if len(sources) >= 3:
        score += 2
    elif len(sources) >= 2:
        score += 1

    if score >= 7:
        return "High"
    if score >= 3:
        return "Medium"
    return "Low"


def _build_evidence(incident: Incident, al: dict) -> str:
    """Concrete evidence summary."""
    parts = []

    if al["count"]:
        sev_summary = ", ".join(sorted(set(al["severities"]), reverse=True))
        parts.append(
            f"{al['count']} alert(s) with severity level(s): {sev_summary}."
        )

    if al["unique_event_types"]:
        parts.append(
            f"Event type(s): {_format_list(al['unique_event_types'])}."
        )

    if incident.mitre_techniques:
        parts.append(
            f"MITRE ATT&CK technique(s): {', '.join(incident.mitre_techniques)}."
        )

    if al["assets"]:
        parts.append(f"Affected asset(s): {_format_list(al['assets'])}.")

    if al["ips"]:
        parts.append(f"Observed IP(s): {_format_list(al['ips'])}.")

    if incident.threat_intel:
        keys = list(incident.threat_intel.keys())[:3]
        parts.append(
            f"Threat intelligence indicators present for: {', '.join(str(k) for k in keys)}."
        )

    if incident.physical_correlation:
        pc = incident.physical_correlation
        signal = pc.get("physical_signal", "unknown signal")
        satellite = pc.get("satellite_flag", False)
        sat_note = " (satellite flag set)" if satellite else ""
        parts.append(f"Physical signal: {signal}{sat_note}.")

    if incident.attack_timeline:
        parts.append(
            f"Attack timeline contains {len(incident.attack_timeline)} recorded event(s)."
        )

    if not parts:
        return "No concrete evidence is currently available."
    return " ".join(parts)


def _build_next_steps(incident: Incident, al: dict) -> list:
    """Practical investigation next steps (recommendations only)."""
    steps = []

    if al["assets"]:
        steps.append(
            f"Review the affected asset(s) ({_format_list(al['assets'])}) "
            "and inspect related logs."
        )

    et_lower = [e.lower() for e in al["unique_event_types"]]
    if any("login" in e or "auth" in e or "brute" in e for e in et_lower):
        steps.append(
            "Review authentication logs for repeated failed attempts and check "
            "for any successful login following the failures."
        )
    if any("privilege" in e or "escalat" in e for e in et_lower):
        steps.append(
            "Review recent privilege changes on the affected asset and verify "
            "whether the change was authorised."
        )
    if any("command" in e or "script" in e or "powershell" in e for e in et_lower):
        steps.append(
            "Review command/script execution details in endpoint logs and determine "
            "whether the execution originated from an expected administrative process."
        )
    if any("data" in e and ("transfer" in e or "exfil" in e) for e in et_lower):
        steps.append(
            "Review the destination and volume of the data transfer and determine "
            "whether it was authorised."
        )

    if al["ips"]:
        steps.append(
            f"Investigate the reputation and historical activity of the observed "
            f"IP(s): {_format_list(al['ips'])}."
        )

    if incident.mitre_techniques:
        steps.append(
            f"Review activity mapped to the observed MITRE techniques "
            f"({', '.join(incident.mitre_techniques)}) in your EDR/SIEM."
        )

    if incident.threat_intel:
        steps.append(
            "Investigate the reputation and historical activity of the "
            "threat intelligence indicators."
        )

    if incident.physical_correlation:
        steps.append(
            "Validate the physical/geospatial signal against the affected "
            "asset's expected activity."
        )

    if incident.attack_timeline:
        steps.append(
            "Review the full attack timeline to identify whether activity "
            "continued after the latest recorded event."
        )

    if (incident.priority in ("Critical", "High")) or (
        incident.risk_score is not None and incident.risk_score >= 70
    ):
        steps.append(
            "Escalate for analyst investigation according to operational procedures."
        )

    if not steps:
        steps.append(
            "Review the incident details and any available logs for further context."
        )

    return steps


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def generate_bluf_report(incident: Incident) -> Incident:
    """
    Feature #12: BLUF Report Generator.
    Fill: incident.bluf_report (dict with keys: threat, impact, confidence, evidence, next_steps)
    """
    al = _extract_alerts(incident)

    incident.bluf_report = {
        "threat":     _build_threat(incident, al),
        "impact":     _build_impact(incident, al),
        "confidence": _build_confidence(incident, al),
        "evidence":   _build_evidence(incident, al),
        "next_steps": _build_next_steps(incident, al),
    }

    return incident
