from shared.schemas import Incident


def recommend_actions(incident: Incident) -> Incident:
    """
    Feature #15: Recommended Actions.
    Fill: incident.recommended_actions (list of str)
    """
    actions = []
    alerts = incident.alerts or []

    # Collect event types, lowercased, for pattern matching
    event_types = [
        (a.event_type or "").lower() for a in alerts if a.event_type
    ]
    assets = list({a.asset for a in alerts if a.asset})
    ips = list({a.ip for a in alerts if a.ip})

    # Helper to format a small list inline
    def _fmt(items, limit=3):
        shown = items[:limit]
        result = ", ".join(str(i) for i in shown)
        if len(items) > limit:
            result += f" (and {len(items) - limit} more)"
        return result

    # ------------------------------------------------------------------ #
    # 1. Authentication / brute-force attacks
    # ------------------------------------------------------------------ #
    if any(
        "login" in e or "auth" in e or "brute" in e or "password" in e
        for e in event_types
    ):
        actions.append(
            "Review authentication logs for repeated failed login attempts."
        )
        actions.append(
            "Check whether the targeted account showed any successful login "
            "after the failures."
        )

    # ------------------------------------------------------------------ #
    # 2. Privilege escalation
    # ------------------------------------------------------------------ #
    if any("privilege" in e or "escalat" in e for e in event_types):
        actions.append(
            "Review recent privilege changes on the affected asset."
        )
        actions.append(
            "Verify whether the privilege change was authorised."
        )

    # ------------------------------------------------------------------ #
    # 3. Command / script / PowerShell execution
    # ------------------------------------------------------------------ #
    if any(
        "command" in e or "script" in e or "powershell" in e or "exec" in e
        for e in event_types
    ):
        actions.append(
            "Review the executed command or script details in the endpoint logs."
        )
        actions.append(
            "Check whether the execution originated from an expected "
            "administrative process."
        )

    # ------------------------------------------------------------------ #
    # 4. Data transfer / exfiltration
    # ------------------------------------------------------------------ #
    if any(
        ("data" in e and ("transfer" in e or "exfil" in e)) or "upload" in e
        for e in event_types
    ):
        actions.append(
            "Review the destination and volume of the data transfer."
        )
        actions.append(
            "Determine whether the data transfer was authorised."
        )

    # ------------------------------------------------------------------ #
    # 5. Lateral movement
    # ------------------------------------------------------------------ #
    if any("lateral" in e or "remote" in e for e in event_types):
        actions.append(
            "Investigate potential lateral movement: review connections "
            "from the affected asset to other internal systems."
        )

    # ------------------------------------------------------------------ #
    # 6. MITRE-technique driven recommendations
    # ------------------------------------------------------------------ #
    techs = incident.mitre_techniques or []

    if "T1110" in techs or any(t.startswith("T1110") for t in techs):
        if not any("authentication logs" in a for a in actions):
            actions.append(
                "Review authentication logs for repeated failed login attempts."
            )

    if "T1059" in techs or any(t.startswith("T1059") for t in techs):
        if not any("command or script" in a for a in actions):
            actions.append(
                "Review command and script execution details in endpoint logs."
            )

    if "T1068" in techs:
        if not any("privilege changes" in a for a in actions):
            actions.append(
                "Review recent privilege changes on the affected system."
            )

    if "T1078" in techs:
        actions.append(
            "Verify whether any account credentials may have been compromised "
            "and review recent account activity."
        )

    if "T1021" in techs or any(t.startswith("T1021") for t in techs):
        actions.append(
            "Review remote service connections from the affected asset "
            "to identify potential lateral movement."
        )

    if "T1041" in techs:
        if not any("data transfer" in a for a in actions):
            actions.append(
                "Review outbound network traffic for signs of data exfiltration "
                "over a command-and-control channel."
            )

    if "T1005" in techs:
        actions.append(
            "Review file access activity on the affected system for signs "
            "of local data collection."
        )

    if "T1566" in techs or any(t.startswith("T1566") for t in techs):
        actions.append(
            "Review email logs for suspicious messages and check whether "
            "any user interacted with phishing content."
        )

    if "T1204" in techs or any(t.startswith("T1204") for t in techs):
        actions.append(
            "Investigate files or links that a user may have executed "
            "as part of a social engineering attempt."
        )

    # ------------------------------------------------------------------ #
    # 7. Observed IPs
    # ------------------------------------------------------------------ #
    if ips:
        actions.append(
            f"Investigate the reputation and historical activity associated "
            f"with the observed IP(s): {_fmt(ips)}."
        )

    # ------------------------------------------------------------------ #
    # 8. Threat intelligence indicators
    # ------------------------------------------------------------------ #
    if incident.threat_intel:
        actions.append(
            "Investigate the reputation and historical activity associated "
            "with the threat intelligence indicators."
        )

    # ------------------------------------------------------------------ #
    # 9. Physical correlation — only when a signal was actually found
    # ------------------------------------------------------------------ #
    pc = incident.physical_correlation
    if pc and pc.get("correlated"):
        actions.append(
            "Validate the physical/geospatial signal against the affected "
            "asset and its expected activity."
        )

    # ------------------------------------------------------------------ #
    # 10. Affected assets — general review
    # ------------------------------------------------------------------ #
    if assets:
        actions.append(
            f"Review the complete activity log for the affected asset(s): "
            f"{_fmt(assets)}."
        )

    # ------------------------------------------------------------------ #
    # 11. High / Critical priority — escalation
    # ------------------------------------------------------------------ #
    if incident.priority in ("Critical", "High") or (
        incident.risk_score is not None and incident.risk_score >= 70
    ):
        actions.append(
            "Review the complete incident timeline and correlate all related alerts."
        )
        actions.append(
            "Escalate for analyst investigation according to operational procedures."
        )

    # ------------------------------------------------------------------ #
    # 12. False positive — close loop
    # ------------------------------------------------------------------ #
    if incident.is_false_positive is True:
        actions.append(
            "Verify the false-positive determination and update the incident "
            "status accordingly."
        )

    # ------------------------------------------------------------------ #
    # 13. Fallback — no evidence at all
    # ------------------------------------------------------------------ #
    if not actions:
        actions.append(
            "Review the incident details and any available logs for further context."
        )

    # Deduplicate while preserving order
    seen = set()
    unique_actions = []
    for a in actions:
        if a not in seen:
            seen.add(a)
            unique_actions.append(a)

    incident.recommended_actions = unique_actions
    return incident