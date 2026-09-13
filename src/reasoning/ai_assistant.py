from shared.schemas import Incident


def answer_analyst_question(incident: Incident, question: str = "Why is this critical?") -> str:
    """
    Feature #11: AI Investigation Assistant.
    Answer analyst questions grounded in the incident's evidence.
    """
    # TODO: your logic here (likely calls an LLM with incident data as context)
    return "placeholder answer"


def generate_ai_explanation(incident: Incident) -> Incident:
    """Fill: incident.ai_explanation (str) — default explanation for the incident."""
    incident.ai_explanation = "placeholder explanation"
    return incident