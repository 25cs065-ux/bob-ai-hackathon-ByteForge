from shared.schemas import Incident
from context.mitre_mapping import map_mitre_techniques
from context.attack_timeline import build_timeline
from context.intel_enrichment import enrich_with_threat_intel
from context.cyber_physical_fusion import fuse_cyber_physical


def enrich_context(incident: Incident) -> Incident:
    incident = map_mitre_techniques(incident)
    incident = build_timeline(incident)
    incident = enrich_with_threat_intel(incident)
    incident = fuse_cyber_physical(incident)
    return incident