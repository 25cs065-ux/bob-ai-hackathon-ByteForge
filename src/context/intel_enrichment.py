from shared.schemas import Incident


def enrich_with_threat_intel(incident: Incident) -> Incident:
    """
    Feature #10: Threat Intelligence Enrichment.
    Fill: incident.threat_intel (dict, e.g. {"ip_reputation": ..., "known_bad": ...})
    """
    # TODO: your logic here
    incident.threat_intel = {}
    return incident