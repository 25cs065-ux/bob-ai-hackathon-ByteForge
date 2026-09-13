from shared.schemas import Incident


def recommend_actions(incident: Incident) -> Incident:
    """
    Feature #15: Recommended Actions.
    Fill: incident.recommended_actions (list of str)
    """
    # TODO: your logic here
    incident.recommended_actions = []
    return incident