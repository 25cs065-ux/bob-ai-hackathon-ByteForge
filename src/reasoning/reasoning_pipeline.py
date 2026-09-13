from shared.schemas import Incident
from reasoning.ai_assistant import generate_ai_explanation
from reasoning.bluf_generator import generate_bluf_report
from reasoning.recommended_actions import recommend_actions
from reasoning.kill_chain_forecast import predict_next_techniques


def generate_ai_insights(incident: Incident) -> Incident:
    incident = generate_ai_explanation(incident)
    incident = generate_bluf_report(incident)
    incident = recommend_actions(incident)
    incident = predict_next_techniques(incident)
    return incident