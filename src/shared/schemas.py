"""
SHARED CONTRACT — only the team lead edits this file.
Everyone else imports from here and adds fields to these objects
inside their own module. Never rename or remove existing fields.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


@dataclass
class NormalizedAlert:
    """Output of Ingestion stage (#1, #2). One standardized alert."""
    alert_id: str
    timestamp: str
    source: str          # e.g. "SIEM", "firewall", "satellite_feed", "endpoint"
    ip: Optional[str] = None
    asset: Optional[str] = None
    severity: str = "low"       # low | medium | high | critical
    event_type: Optional[str] = None
    raw_data: dict = field(default_factory=dict)  # original payload, just in case


@dataclass
class Incident:
    """
    Central object passed through the whole pipeline.
    Each stage reads it, adds ITS OWN fields, returns it.
    """
    incident_id: str
    alerts: List[NormalizedAlert] = field(default_factory=list)  # from Ingestion (#3, #7)

    # ---- Filled in by Teammate 1 (Detection & Scoring: #4, #5, #6, #19) ----
    is_false_positive: Optional[bool] = None
    false_positive_reason: Optional[str] = None
    risk_score: Optional[float] = None          # 0-100
    priority: Optional[str] = None              # Critical | High | Medium | Low
    threat_dna_signature: Optional[str] = None  # unique behavioural fingerprint
    similar_past_incidents: List[str] = field(default_factory=list)  # incident_ids

    # ---- Filled in by Teammate 2 (Context Engine: #8, #9, #10, #20) ----
    mitre_techniques: List[str] = field(default_factory=list)  # e.g. ["T1078", "T1110"]
    attack_timeline: List[dict] = field(default_factory=list)  # [{time, event_desc}]
    threat_intel: dict = field(default_factory=dict)           # enrichment on IPs/hashes/domains
    physical_correlation: Optional[dict] = None                 # Option A: satellite/geo fusion data

    # ---- Filled in by Teammate 3 (AI Reasoning: #11, #12, #15, #21) ----
    ai_explanation: Optional[str] = None         # answers "why is this critical?"
    bluf_report: Optional[dict] = None           # {threat, impact, confidence, evidence, next_steps}
    recommended_actions: List[str] = field(default_factory=list)
    predicted_next_techniques: List[str] = field(default_factory=list)  # Option B: kill-chain forecast

    # ---- Shared / dashboard use (#13-#18) ----
    analyst_feedback: Optional[str] = None       # useful | incorrect | genuine_threat | false_positive
    status: str = "new"                          # new | investigating | closed