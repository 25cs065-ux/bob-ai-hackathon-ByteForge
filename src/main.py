from ingestion.ingestion_pipeline import run_ingestion
from detection.detection_pipeline import detect_and_score
from context.context_pipeline import enrich_context
from reasoning.reasoning_pipeline import generate_ai_insights


def run_pipeline(raw_sources: list):
    incidents = run_ingestion(raw_sources)

    results = []
    for incident in incidents:
        incident = detect_and_score(incident)
        incident = enrich_context(incident)
        incident = generate_ai_insights(incident)
        results.append(incident)

    return results


if __name__ == "__main__":
    sample_sources = ["siem", "sensor", "intel", "satellite"]
    final_incidents = run_pipeline(sample_sources)

    print(f"Total incidents processed: {len(final_incidents)}\n")

    for inc in final_incidents:
        print(f"--- Incident {inc.incident_id} ---")
        print(f"Priority: {inc.priority} | Risk Score: {inc.risk_score}")
        print(f"False Positive: {inc.is_false_positive}")
        print(f"Threat DNA: {inc.threat_dna_signature}")
        print(f"MITRE Techniques: {inc.mitre_techniques}")
        print(f"Predicted Next Techniques: {inc.predicted_next_techniques}")
        print(f"Physical Correlation: {inc.physical_correlation}")
        print(f"\nBLUF Report:")
        if inc.bluf_report:
            for key, value in inc.bluf_report.items():
                print(f"  {key}: {value}")
        print(f"\nRecommended Actions:")
        for action in inc.recommended_actions:
            print(f"  - {action}")
        print("\n" + "="*80 + "\n")