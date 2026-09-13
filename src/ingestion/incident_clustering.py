from shared.schemas import NormalizedAlert, Incident
from typing import List
import uuid


def build_incidents(alert_groups: List[List[NormalizedAlert]]) -> List[Incident]:
    """
    Feature #7: Incident Clustering.
    Convert each correlated group of alerts into a single Incident object.
    """
    incidents = []
    for group in alert_groups:
        incident = Incident(incident_id=str(uuid.uuid4()), alerts=group)
        incidents.append(incident)
    return incidents