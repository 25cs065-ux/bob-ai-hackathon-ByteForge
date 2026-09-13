from shared.schemas import Incident


def check_false_positive(incident: Incident) -> Incident:
    """
    Feature #4: Threat Detection & False-Positive Reduction.
    Decide if this incident is a genuine threat or likely noise.
    Fill: incident.is_false_positive (bool), incident.false_positive_reason (str)
    """
    # TODO: your logic here
    incident.is_false_positive = False
    incident.false_positive_reason = "placeholder"
    return incident