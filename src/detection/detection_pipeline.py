from shared.schemas import Incident
from detection.false_positive import check_false_positive
from detection.risk_scoring import calculate_risk_score
from detection.prioritisation import assign_priority
from detection.threat_dna import generate_threat_dna


def detect_and_score(incident: Incident) -> Incident:
    incident = check_false_positive(incident)
    incident = calculate_risk_score(incident)
    incident = assign_priority(incident)
    incident = generate_threat_dna(incident)
    return incident