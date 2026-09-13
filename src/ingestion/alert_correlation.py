from shared.schemas import NormalizedAlert
from typing import List, Dict


def correlate_alerts(alerts: List[NormalizedAlert]) -> List[List[NormalizedAlert]]:
    """
    Feature #3: AI Alert Correlation.
    Group alerts that are likely part of the same attack.
    Return a list of groups (each group = list of related alerts).
    """
    groups = []
    # TODO: your correlation logic (e.g. same asset/IP within a time window)
    return groups