from shared.schemas import Incident


def generate_threat_dna(incident: Incident) -> Incident:
    """
    Feature #19: Threat DNA - Behavioural Fingerprinting.
    Build a behavioural signature and compare against past incidents.
    Fill: incident.threat_dna_signature (str), incident.similar_past_incidents (list of ids)
    """
    # TODO: your logic here
    incident.threat_dna_signature = "placeholder-signature"
    incident.similar_past_incidents = []
    return incident