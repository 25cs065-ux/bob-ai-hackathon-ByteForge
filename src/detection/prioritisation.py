from shared.schemas import Incident


def assign_priority(incident: Incident) -> Incident:
    """
    Feature #6: Alert Prioritisation.
    Convert incident.risk_score into a priority bucket.
    Fill: incident.priority ("Critical" | "High" | "Medium" | "Low")
    """
    # TODO: your logic here (e.g. thresholds on risk_score)
    incident.priority = "Low"
    return incident