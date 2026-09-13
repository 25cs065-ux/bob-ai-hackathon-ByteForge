from shared.schemas import NormalizedAlert
from typing import List


def normalize_alerts(raw_alerts: list) -> List[NormalizedAlert]:
    """
    Feature #2: Alert Normalization.
    Convert raw alerts from different sources into a common NormalizedAlert format.
    """
    normalized = []
    # TODO: for each raw alert, map its fields into NormalizedAlert(...)
    return normalized