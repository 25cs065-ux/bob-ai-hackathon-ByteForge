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
    sample_sources = []
    final_incidents = run_pipeline(sample_sources)
    for inc in final_incidents:
        print(inc)