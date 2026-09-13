from shared.schemas import Incident, NormalizedAlert
from detection.detection_pipeline import detect_and_score
from context.context_pipeline import enrich_context
from reasoning.reasoning_pipeline import generate_ai_insights

# Build one fake Incident manually — mimics what your ingestion module would output
sample_alert = NormalizedAlert(
    alert_id="TEST-001",
    timestamp="2024-01-15T10:00:00Z",
    source="siem",
    ip="203.0.113.10",
    asset="server-01",
    severity="critical",
    event_type="privilege_escalation",
    raw_data={},
)

incident = Incident(incident_id="INC-TEST-001", alerts=[sample_alert])

print("=== BEFORE ===")
print(incident)

print("\n=== Running Detection (Teammate 1) ===")
incident = detect_and_score(incident)
print("is_false_positive:", incident.is_false_positive)
print("risk_score:", incident.risk_score)
print("priority:", incident.priority)
print("threat_dna_signature:", incident.threat_dna_signature)

print("\n=== Running Context (Teammate 2) ===")
incident = enrich_context(incident)
print("mitre_techniques:", incident.mitre_techniques)
print("attack_timeline:", incident.attack_timeline)
print("threat_intel:", incident.threat_intel)
print("physical_correlation:", incident.physical_correlation)

print("\n=== Running Reasoning (Teammate 3) ===")
incident = generate_ai_insights(incident)
print("ai_explanation:", incident.ai_explanation)
print("bluf_report:", incident.bluf_report)
print("recommended_actions:", incident.recommended_actions)
print("predicted_next_techniques:", incident.predicted_next_techniques)