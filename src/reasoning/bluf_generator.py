from shared.schemas import Incident


def generate_bluf_report(incident: Incident) -> Incident:
    """
    Feature #12: BLUF Report Generator.
    Fill: incident.bluf_report (dict with keys: threat, impact, confidence, evidence, next_steps)
    """
    # TODO: your logic here
    incident.bluf_report = {
        "threat": "placeholder",
        "impact": "placeholder",
        "confidence": "placeholder",
        "evidence": "placeholder",
        "next_steps": "placeholder",
    }
    return incident