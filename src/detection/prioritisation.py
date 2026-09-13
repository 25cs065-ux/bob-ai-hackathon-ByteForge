from shared.schemas import Incident


def assign_priority(incident: Incident) -> Incident:
    """
    Feature #6: Alert Prioritisation.
    Convert incident.risk_score into a priority bucket.
    Fill: incident.priority ("Critical" | "High" | "Medium" | "Low")

    Ranges (exclusive upper bound except the top):
        75 <= score <= 100  →  Critical
        50 <= score <  75   →  High
        25 <= score <  50   →  Medium
         0 <= score <  25   →  Low
        None / missing      →  Low
    """
    score = incident.risk_score

    if score is None:
        incident.priority = "Low"
    elif score >= 75:
        incident.priority = "Critical"
    elif score >= 50:
        incident.priority = "High"
    elif score >= 25:
        incident.priority = "Medium"
    else:
        incident.priority = "Low"

    return incident
