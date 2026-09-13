from shared.schemas import NormalizedAlert
from typing import List


def collect_raw_alerts(sources: list) -> list:
    """
    Feature #1: Multi-Source Alert Ingestion.
    Pull raw alerts from SIEM, cyber sensors, intel reports, simulated satellite feeds.
    Return a list of raw dicts (before normalization).
    """
    raw_alerts = []
    # TODO: your logic — read from files/APIs/mock feeds for each source type
    return raw_alerts