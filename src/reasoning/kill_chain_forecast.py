from shared.schemas import Incident

# ---------------------------------------------------------------------------
# Deterministic kill-chain progression rules
#
# Each entry maps an observed technique (or technique prefix) to a list of
# candidate "likely next" techniques, ordered by progression likelihood.
#
# Rules are based on typical attacker patterns derived from MITRE ATT&CK.
# ---------------------------------------------------------------------------
_PROGRESSION: dict = {
    # Initial Access
    "T1566":   ["T1204"],          # Phishing → User Execution
    "T1566.001": ["T1204"],
    "T1566.002": ["T1204"],

    # Execution
    "T1204":   ["T1059", "T1547"], # User Execution → Script Exec / Persistence
    "T1204.001": ["T1059"],
    "T1204.002": ["T1059"],
    "T1059":   ["T1068", "T1547"], # Command/Script → Privilege Esc / Persistence
    "T1059.001": ["T1068", "T1547"],

    # Credential Access / Brute Force
    "T1110":   ["T1078"],          # Brute Force → Valid Accounts
    "T1110.001": ["T1078"],
    "T1110.003": ["T1078"],

    # Privilege Escalation
    "T1068":   ["T1021", "T1547"], # Privilege Esc → Remote Services / Persistence

    # Defense Evasion / Persistence
    "T1547":   ["T1021"],          # Boot/Logon Autostart → Remote Services

    # Lateral Movement
    "T1078":   ["T1021"],          # Valid Accounts → Remote Services
    "T1021":   ["T1005", "T1041"], # Remote Services → Data Collection / Exfil
    "T1021.001": ["T1005", "T1041"],
    "T1021.002": ["T1005", "T1041"],

    # Collection
    "T1005":   ["T1041"],          # Data from Local System → Exfil over C2

    # Exfiltration
    "T1041":   [],                 # End of the typical chain — no prediction
}


def predict_next_techniques(incident: Incident) -> Incident:
    """
    Feature #21: Predictive Kill-Chain Forecasting (Innovation - Option B).
    Based on incident.mitre_techniques already observed, predict likely next
    technique(s).  Fill: incident.predicted_next_techniques (list of technique IDs)
    """
    observed = set(incident.mitre_techniques or [])

    if not observed:
        incident.predicted_next_techniques = []
        return incident

    # Collect candidate next techniques from all observed techniques
    candidates: list[str] = []
    for tech in observed:
        # Try exact match first, then prefix match (e.g. "T1059.001" → "T1059")
        next_techs = _PROGRESSION.get(tech)
        if next_techs is None:
            # Try the base technique ID (strip sub-technique suffix)
            base = tech.split(".")[0]
            next_techs = _PROGRESSION.get(base, [])

        for candidate in next_techs:
            # Only suggest techniques not already observed
            if candidate not in observed and candidate not in candidates:
                candidates.append(candidate)

    # Keep predictions small and deterministic (up to 3)
    incident.predicted_next_techniques = candidates[:3]
    return incident
