from shared.schemas import Incident

# ---------------------------------------------------------------------------
# MITRE ATT&CK keyword-to-technique mapping table.
# Each entry is (keyword, technique_id).
# Keywords are matched against a lowercase version of alert.event_type only
# (exact whole-string or substring match within the event_type token).
# raw_data is searched as a secondary signal but only for clearly specific
# security terms — never generic English words.
#
# Order matters: more-specific sub-technique entries appear before their
# parent technique so T1059.001 is recorded instead of plain T1059 when
# "powershell" is present.
# ---------------------------------------------------------------------------
_EVENT_TYPE_MAP = [
    # --- Execution: PowerShell (sub-technique — must precede generic T1059) ---
    ("powershell",               "T1059.001"),

    # --- Execution: Command / scripting interpreter ---
    ("cmd_execution",            "T1059"),
    ("command_execution",        "T1059"),
    ("shell_execution",          "T1059"),
    ("script_execution",         "T1059"),
    ("suspicious_process",       "T1059"),

    # --- Credential access: Valid accounts ---
    ("valid_account",            "T1078"),
    ("valid_accounts",           "T1078"),
    ("suspicious_auth",          "T1078"),
    ("credential_abuse",         "T1078"),

    # --- Credential access: Brute force ---
    ("brute_force",              "T1110"),
    ("login_failure",            "T1110"),
    ("repeated_login",           "T1110"),
    ("failed_login",             "T1110"),
    ("password_spray",           "T1110"),

    # --- Privilege escalation (specific terms only) ---
    ("privilege_escalation",     "T1068"),
    ("privilege_escalation_attempt", "T1068"),
    ("privesc",                  "T1068"),

    # --- Lateral movement / remote services ---
    ("lateral_movement",         "T1021"),
    ("remote_service",           "T1021"),
    ("rdp",                      "T1021"),
    ("smb",                      "T1021"),

    # --- Exfiltration / data transfer ---
    ("data_transfer",            "T1041"),
    ("exfiltration",             "T1041"),
    ("data_exfil",               "T1041"),

    # --- Collection: file access ---
    ("file_access",              "T1005"),
    ("file_collection",          "T1005"),
    ("data_collection",          "T1005"),

    # --- Initial access: phishing ---
    ("phishing",                 "T1566"),

    # --- Execution: malware / user execution ---
    ("malware_execution",        "T1204"),
    ("malware",                  "T1204"),
    ("user_execution",           "T1204"),
]

# Secondary raw_data keywords: only very specific security terms that cannot
# appear in benign text by accident.  Intentionally short list.
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
    """Apply _EVENT_TYPE_MAP against the normalised event_type string."""
    et = event_type.lower().strip()
    for keyword, technique_id in _EVENT_TYPE_MAP:
        if technique_id not in seen and keyword in et:
            seen.add(technique_id)
            ordered.append(technique_id)


def _match_raw_data(raw_data: dict, seen: set, ordered: list) -> None:
    """Apply _RAW_DATA_MAP against the string representation of raw_data."""
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
    Fill: incident.mitre_techniques (list of technique IDs, e.g. ["T1078"])
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
            continue  # never crash on a single malformed alert

    incident.mitre_techniques = ordered
    return incident
