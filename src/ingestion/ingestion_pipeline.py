from shared.schemas import Incident
from typing import List
from ingestion.multi_source_ingestion import collect_raw_alerts
from ingestion.normalization import normalize_alerts
from ingestion.alert_correlation import correlate_alerts
from ingestion.incident_clustering import build_incidents


def run_ingestion(sources: list) -> List[Incident]:
    raw = collect_raw_alerts(sources)
    normalized = normalize_alerts(raw)
    groups = correlate_alerts(normalized)
    incidents = build_incidents(groups)
    return incidents