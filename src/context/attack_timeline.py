from shared.schemas import Incident


def build_timeline(incident: Incident) -> Incident:
    """
    Feature #9: Attack Timeline.
    Fill: incident.attack_timeline (list of dicts: {"time": ..., "event_desc": ...})
    """
    # TODO: your logic here (sort incident.alerts chronologically)
    incident.attack_timeline = []
    return incident