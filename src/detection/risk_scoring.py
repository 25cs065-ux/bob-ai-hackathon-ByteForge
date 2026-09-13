from shared.schemas import Incident


def calculate_risk_score(incident: Incident) -> Incident:
    """
    Feature #5: Threat/Risk Scoring.
    Fill: incident.risk_score (float 0-100)
    """
    # TODO: your logic here
    incident.risk_score = 0.0
    return incident