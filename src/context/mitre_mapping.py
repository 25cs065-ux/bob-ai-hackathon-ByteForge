from shared.schemas import Incident

_EVENT_TYPE_MAP = [
    ("powershell",               "T1059.001"),
    ("cmd_execution",            "T1059"),
    ("command_execution",        "T1059"),
    ("shell_execution",          "T1059"),
    ("script_execution",         "T1059"),
    ("suspicious_process",       "T1059"),
    ("valid_account",            "T1078"),
    ("valid_accounts",           "T1078"),
    ("suspicious_auth",          "T1078"),
    ("credential_abuse",         "T1078"),
    ("brute_force",              "T1110"),
    ("login_failure",            "T1110"),
    ("repeated_login",           "T1110"),
    ("failed_login",             "T1110"),
    ("password_spray",           "T1110"),
    ("privilege_escalation",     "T1068"),
    ("privilege_escalation_attempt", "T1068"),
    ("privesc",                  "T1068"),
    ("lateral_movement",         "T1021"),
    ("remote_service",           "T1021"),
    ("rdp",                      "T1021"),
    ("smb",                      "T1021"),
    ("data_transfer",            "T1041"),
    ("exfiltration",             "T1041"),
    ("data_exfil",               "T1041"),
    ("file_access",              "T1005"),
    ("file_collection",          "T1005"),
    ("data_collection",          "T1005"),
    ("phishing",                 "T1566"),
    ("malware_execution",        "T1204"),
    ("malware",                  "T1204"),
    ("user_execution",           "T1204"),
]

_RAW_DATA_MAP = [
    ("powershell",               "T1059.001"),
    ("brute_force",              "T1110"),
    ("login_failure",            "T1110"),
    ("failed_login",             "T1110"),
    ("privilege_escalation",     "T1068"),
    ("privesc",                  "T1068"),
    ("exfiltration",             "T1041"),
    ("data_exfil",               "T1041"),
    ("lateral_movement",         "T1021"),
    ("phishing",                 "T1566"),
]


def _match_event_type(event_type: str, seen: set, ordered: list) -> None:
    et = event_type.lower().strip()
    for keyword, technique_id in _EVENT_TYPE_MAP:
        if technique_id not in seen and keyword in et:
            seen.add(technique_id)
            ordered.append(technique_id)


def _match_raw_data(raw_data: dict, seen: set, ordered: list) -> None:
    try:
        text = str(raw_data).lower()
    except Exception:
        return
    for keyword, technique_id in _RAW_DATA_MAP:
        if technique_id not in seen and keyword in text:
            seen.add(technique_id)
            ordered.append(technique_id)


def map_mitre_techniques(incident: Incident) -> Incident:
    """
    Feature #8: MITRE ATT&CK Mapping.
    """
    seen: set = set()
    ordered: list = []

    for alert in (incident.alerts or []):
        try:
            if alert.event_type:
                _match_event_type(str(alert.event_type), seen, ordered)
            if alert.raw_data and isinstance(alert.raw_data, dict):
                _match_raw_data(alert.raw_data, seen, ordered)
        except Exception:
            continue

    incident.mitre_techniques = ordered
    return incident


if __name__ == "__main__":
    from shared.schemas import Incident, NormalizedAlert

    sample_alert = NormalizedAlert(
        alert_id="TEST-001",
        timestamp="2024-01-15T10:00:00Z",
        source="siem",
        ip="203.0.113.10",
        asset="server-01",
        severity="critical",
        event_type="privilege_escalation",
        raw_data={},
    )
    incident = Incident(incident_id="INC-TEST-001", alerts=[sample_alert])

    result = map_mitre_techniques(incident)
    print("mitre_techniques:", result.mitre_techniques)
    