"""
Verification tests for the Detection & Scoring module.
Covers all 5 scenarios specified in the task brief.
Run from the src/ directory:  python -m detection.test_detection
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))  # ensure src/ is on path

from shared.schemas import NormalizedAlert, Incident
from detection.false_positive import check_false_positive
from detection.risk_scoring import calculate_risk_score
from detection.prioritisation import assign_priority
from detection.threat_dna import generate_threat_dna
from detection.detection_pipeline import detect_and_score


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_alert(
    alert_id="a1",
    source="SIEM",
    severity="low",
    event_type="routine_login",
    ip="192.168.1.1",
    asset=None,
    raw_data=None,
    timestamp="2024-01-01T00:00:00Z",
):
    return NormalizedAlert(
        alert_id=alert_id,
        timestamp=timestamp,
        source=source,
        ip=ip,
        asset=asset,
        severity=severity,
        event_type=event_type,
        raw_data=raw_data or {},
    )


def run_full_pipeline(incident: Incident) -> Incident:
    incident = check_false_positive(incident)
    incident = calculate_risk_score(incident)
    incident = assign_priority(incident)
    incident = generate_threat_dna(incident)
    return incident


def assert_true(cond, msg):
    if not cond:
        raise AssertionError(f"FAIL: {msg}")
    print(f"  PASS: {msg}")


# ---------------------------------------------------------------------------
# Scenario 1 – One low-severity routine_login alert
# ---------------------------------------------------------------------------
def test_scenario_1_low_severity_routine_login():
    print("\n[Scenario 1] Single low-severity routine_login alert")
    inc = Incident(incident_id="INC-001", alerts=[
        make_alert(alert_id="a1", severity="low", event_type="routine_login")
    ])
    inc = run_full_pipeline(inc)

    assert_true(inc.is_false_positive is True,
                "is_false_positive should be True")
    assert_true(inc.risk_score is not None and inc.risk_score < 25,
                f"risk_score should be < 25, got {inc.risk_score}")
    assert_true(inc.priority == "Low",
                f"priority should be Low, got {inc.priority}")
    assert_true(inc.threat_dna_signature is not None and len(inc.threat_dna_signature) > 0,
                "threat_dna_signature should be a non-empty string")
    assert_true(isinstance(inc.similar_past_incidents, list),
                "similar_past_incidents should be a list")
    print(f"  risk_score={inc.risk_score}, priority={inc.priority}")
    print(f"  false_positive_reason={inc.false_positive_reason}")
    print(f"  threat_dna_signature={inc.threat_dna_signature}")


# ---------------------------------------------------------------------------
# Scenario 2 – Several high/critical alerts from multiple sources
# ---------------------------------------------------------------------------
def test_scenario_2_high_critical_multi_source():
    print("\n[Scenario 2] Multiple high/critical alerts from multiple sources")
    inc = Incident(incident_id="INC-002", alerts=[
        make_alert("a1", source="SIEM",     severity="critical", event_type="malware detected",
                   ip="10.0.0.1", asset="database-server-01"),
        make_alert("a2", source="endpoint", severity="high",     event_type="privilege escalation",
                   ip="10.0.0.2", asset="gateway-node"),
        make_alert("a3", source="firewall", severity="high",     event_type="lateral movement",
                   ip="10.0.0.3"),
        make_alert("a4", source="SIEM",     severity="critical", event_type="unauthorized access",
                   ip="10.0.0.4"),
    ])
    inc = run_full_pipeline(inc)

    assert_true(inc.is_false_positive is False,
                "is_false_positive should be False")
    assert_true(inc.risk_score is not None and inc.risk_score >= 50,
                f"risk_score should be >= 50, got {inc.risk_score}")
    assert_true(inc.priority in ("High", "Critical"),
                f"priority should be High or Critical, got {inc.priority}")
    assert_true(inc.threat_dna_signature is not None and "SEV_CRITICAL" in inc.threat_dna_signature,
                "DNA should contain SEV_CRITICAL")
    assert_true(isinstance(inc.similar_past_incidents, list),
                "similar_past_incidents should be a list")
    print(f"  risk_score={inc.risk_score}, priority={inc.priority}")
    print(f"  false_positive_reason={inc.false_positive_reason}")
    print(f"  threat_dna_signature={inc.threat_dna_signature}")


# ---------------------------------------------------------------------------
# Scenario 3 - Correlated critical/high suspicious alerts -> score >= 75 -> Critical
# ---------------------------------------------------------------------------
def test_scenario_3_correlated_critical():
    print("\n[Scenario 3] Correlated critical/high suspicious alerts -> should be Critical")
    inc = Incident(incident_id="INC-003", alerts=[
        make_alert("a1", source="SIEM",     severity="critical", event_type="authentication failure",
                   ip="10.1.1.1", asset="critical-control-server"),
        make_alert("a2", source="endpoint", severity="critical", event_type="powershell execution",
                   ip="10.1.1.2", asset="critical-control-server"),
        make_alert("a3", source="firewall", severity="high",     event_type="lateral movement",
                   ip="10.1.1.3", asset="database-server"),
        make_alert("a4", source="SIEM",     severity="high",     event_type="data transfer",
                   ip="10.1.1.4", asset="gateway"),
    ])
    inc = run_full_pipeline(inc)

    assert_true(inc.risk_score is not None and inc.risk_score >= 75,
                f"risk_score should be >= 75, got {inc.risk_score}")
    assert_true(inc.priority == "Critical",
                f"priority should be Critical, got {inc.priority}")
    print(f"  risk_score={inc.risk_score}, priority={inc.priority}")
    print(f"  threat_dna_signature={inc.threat_dna_signature}")


# ---------------------------------------------------------------------------
# Scenario 4 – Empty alerts: no crash, low/default risk, priority Low, DNA valid
# ---------------------------------------------------------------------------
def test_scenario_4_empty_alerts():
    print("\n[Scenario 4] Empty alerts list")
    inc = Incident(incident_id="INC-004", alerts=[])
    inc = run_full_pipeline(inc)

    assert_true(inc.risk_score is not None and inc.risk_score == 0.0,
                f"risk_score should be 0.0 for empty alerts, got {inc.risk_score}")
    assert_true(inc.priority == "Low",
                f"priority should be Low, got {inc.priority}")
    assert_true(inc.threat_dna_signature is not None and len(inc.threat_dna_signature) > 0,
                "threat_dna_signature should still be a non-empty string")
    assert_true(inc.similar_past_incidents == [],
                "similar_past_incidents should be []")
    print(f"  risk_score={inc.risk_score}, priority={inc.priority}")
    print(f"  threat_dna_signature={inc.threat_dna_signature}")


# ---------------------------------------------------------------------------
# Scenario 5 - Two incidents with different IPs/IDs but same behaviour -> same DNA
# ---------------------------------------------------------------------------
def test_scenario_5_behaviour_based_dna():
    print("\n[Scenario 5] Different IPs/IDs, same behaviour -> identical DNA")
    inc_a = Incident(incident_id="INC-005A", alerts=[
        make_alert("alert-111", source="SIEM", severity="high",
                   event_type="login failure", ip="192.168.10.1"),
        make_alert("alert-222", source="SIEM", severity="high",
                   event_type="file access",   ip="192.168.10.1"),
    ])
    inc_b = Incident(incident_id="INC-005B", alerts=[
        make_alert("alert-999", source="SIEM", severity="high",
                   event_type="login failure", ip="10.99.99.99"),
        make_alert("alert-888", source="SIEM", severity="high",
                   event_type="file access",   ip="10.99.99.99"),
    ])
    inc_a = run_full_pipeline(inc_a)
    inc_b = run_full_pipeline(inc_b)

    assert_true(inc_a.threat_dna_signature == inc_b.threat_dna_signature,
                f"DNA should match regardless of IP/ID:\n"
                f"  A: {inc_a.threat_dna_signature}\n"
                f"  B: {inc_b.threat_dna_signature}")
    print(f"  inc_a DNA: {inc_a.threat_dna_signature}")
    print(f"  inc_b DNA: {inc_b.threat_dna_signature}")
    print("  DNAs match — behaviour-based fingerprinting confirmed")


# ---------------------------------------------------------------------------
# Additional: verify detect_and_score pipeline wrapper works end-to-end
# ---------------------------------------------------------------------------
def test_pipeline_wrapper():
    print("\n[Pipeline] detect_and_score() wrapper smoke test")
    inc = Incident(incident_id="INC-PIPE", alerts=[
        make_alert("px1", source="endpoint", severity="medium", event_type="suspicious process"),
    ])
    inc = detect_and_score(inc)
    assert_true(inc.is_false_positive is not None, "is_false_positive populated")
    assert_true(inc.risk_score is not None, "risk_score populated")
    assert_true(inc.priority is not None, "priority populated")
    assert_true(inc.threat_dna_signature is not None, "threat_dna_signature populated")
    print(f"  risk_score={inc.risk_score}, priority={inc.priority}, fp={inc.is_false_positive}")
    print(f"  DNA={inc.threat_dna_signature}")


# ---------------------------------------------------------------------------
# Verify priority threshold boundaries
# ---------------------------------------------------------------------------
def test_priority_boundaries():
    print("\n[Boundaries] Priority threshold edge cases")
    cases = [
        (0.0,   "Low"),
        (24.99, "Low"),
        (25.0,  "Medium"),
        (49.99, "Medium"),
        (50.0,  "High"),
        (74.99, "High"),
        (75.0,  "Critical"),
        (100.0, "Critical"),
        (None,  "Low"),
    ]
    for score, expected in cases:
        inc = Incident(incident_id="INC-B", risk_score=score)
        inc = assign_priority(inc)
        assert_true(
            inc.priority == expected,
            f"score={score} => expected {expected}, got {inc.priority}"
        )


# ---------------------------------------------------------------------------
# Verify FP penalty lowers risk score significantly
# ---------------------------------------------------------------------------
def test_fp_penalty_applied():
    print("\n[FP Penalty] False-positive incidents get reduced risk score")
    inc_fp = Incident(incident_id="INC-FP", is_false_positive=True, alerts=[
        make_alert("a1", severity="high", event_type="unauthorized access"),
    ])
    inc_real = Incident(incident_id="INC-REAL", is_false_positive=False, alerts=[
        make_alert("a1", severity="high", event_type="unauthorized access"),
    ])
    inc_fp   = calculate_risk_score(inc_fp)
    inc_real = calculate_risk_score(inc_real)
    assert_true(inc_fp.risk_score < inc_real.risk_score,
                f"FP score ({inc_fp.risk_score}) must be < real score ({inc_real.risk_score})")
    print(f"  FP score={inc_fp.risk_score}, real score={inc_real.risk_score}")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    tests = [
        test_scenario_1_low_severity_routine_login,
        test_scenario_2_high_critical_multi_source,
        test_scenario_3_correlated_critical,
        test_scenario_4_empty_alerts,
        test_scenario_5_behaviour_based_dna,
        test_pipeline_wrapper,
        test_priority_boundaries,
        test_fp_penalty_applied,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"  *** {e}")
            failed += 1
        except Exception as e:
            print(f"  *** UNEXPECTED ERROR in {t.__name__}: {type(e).__name__}: {e}")
            failed += 1

    print(f"\n{'='*60}")
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    if failed:
        sys.exit(1)
    else:
        print("All tests passed.")
        sys.exit(0)
